"""
Phase 1 — Subdomain Enumeration (v2)

Sources:
  - subfinder (fast + deep)
  - assetfinder (fast)
  - amass (deep only — slow but thorough)
  - crt.sh (certificate transparency, no install needed)
  - DNS bruteforce fallback (if no tools)

Go binary resolution: searches ~/go/bin/ directly to avoid PATH issues.
"""

import os
import json
import subprocess
import shutil
from pathlib import Path

import requests as req
from rich.console import Console

console = Console()


def _find_go_binary(name):
    """
    Tìm Go binary: ~/go/bin/ → GOPATH/bin/ → PATH.
    Returns full path hoặc None.
    """
    # Check ~/go/bin/
    home_bin = os.path.join(str(Path.home()), "go", "bin", name)
    if os.path.isfile(home_bin) and os.access(home_bin, os.X_OK):
        return home_bin

    # Check GOPATH/bin/
    try:
        result = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True, text=True, timeout=5,
        )
        gopath = result.stdout.strip()
        if gopath:
            gopath_bin = os.path.join(gopath, "bin", name)
            if os.path.isfile(gopath_bin) and os.access(gopath_bin, os.X_OK):
                return gopath_bin
    except Exception:
        pass

    # Check PATH
    path = shutil.which(name)
    return path


def _run_tool(cmd, timeout):
    """Run a subprocess and return stdout lines."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _run_subfinder(binary, domain, depth, timeout):
    """Chạy subfinder subprocess."""
    cmd = [binary, "-d", domain, "-silent"]
    if depth == "deep":
        cmd.extend(["-all", "-recursive"])
    return _run_tool(cmd, timeout)


def _run_assetfinder(binary, domain, timeout):
    """Chạy assetfinder subprocess."""
    subs = _run_tool([binary, "--subs-only", domain], timeout)
    return [s for s in subs if domain in s]


def _run_amass(binary, domain, timeout):
    """Chạy amass passive enum (deep mode only)."""
    subs = _run_tool(
        [binary, "enum", "-passive", "-d", domain],
        timeout * 3,  # amass chạy lâu
    )
    return [s for s in subs if domain in s]


def _query_crtsh(domain, timeout):
    """Query crt.sh (Certificate Transparency logs)."""
    try:
        resp = req.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=min(timeout, 30),
            headers={"User-Agent": "ReconRisk/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line and not line.startswith("*") and domain in line:
                        subs.add(line)
            return list(subs)
        return []
    except Exception:
        console.print("  [yellow]⚠ crt.sh query failed[/yellow]")
        return []


def _dns_bruteforce(domain, timeout):
    """Fallback: dùng dnspython để resolve một wordlist nhỏ."""
    try:
        import dns.resolver
    except ImportError:
        console.print("  [yellow]⚠ dnspython not installed[/yellow]")
        return []

    prefixes = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "blog", "shop", "app", "portal", "vpn", "remote", "cdn", "ns1",
        "ns2", "mx", "smtp", "pop", "imap", "webmail", "cpanel", "login",
        "dashboard", "git", "gitlab", "jenkins", "ci", "status", "monitor",
        "docs", "wiki", "support", "help", "m", "mobile", "beta", "alpha",
        "demo", "sandbox", "internal", "intranet", "uat", "qa", "prod",
        "backend", "frontend", "static", "assets", "media", "img", "images",
    ]

    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    console.print(f"  [dim]DNS bruteforce: {len(prefixes)} prefixes...[/dim]")

    for prefix in prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            answers = resolver.resolve(subdomain, "A")
            if answers:
                found.append(subdomain)
        except Exception:
            pass

    return found


def run_subdomain(config, results):
    """
    Main entry point cho Phase 1.
    Returns: list of subdomain strings
    """
    domain = config["domain"]
    depth = config["depth"]
    timeout = config["timeout"]
    output_dir = config["output_dir"]

    all_subs = set()
    tool_count = 0

    # ─── Source 1: subfinder ─────────────────────────
    subfinder = _find_go_binary("subfinder")
    if subfinder:
        console.print(f"  [dim]Running subfinder ({depth} mode)...[/dim]")
        subs = _run_subfinder(subfinder, domain, depth, timeout)
        console.print(f"  [dim]subfinder: {len(subs)} subdomains[/dim]")
        all_subs.update(subs)
        tool_count += 1
    else:
        console.print("  [dim]subfinder not installed (optional)[/dim]")

    # ─── Source 2: assetfinder ───────────────────────
    assetfinder = _find_go_binary("assetfinder")
    if assetfinder:
        console.print("  [dim]Running assetfinder...[/dim]")
        subs = _run_assetfinder(assetfinder, domain, timeout)
        console.print(f"  [dim]assetfinder: {len(subs)} subdomains[/dim]")
        all_subs.update(subs)
        tool_count += 1
    else:
        console.print("  [dim]assetfinder not installed (optional)[/dim]")

    # ─── Source 3: crt.sh (always available) ─────────
    console.print("  [dim]Querying crt.sh (Certificate Transparency)...[/dim]")
    subs = _query_crtsh(domain, timeout)
    console.print(f"  [dim]crt.sh: {len(subs)} subdomains[/dim]")
    all_subs.update(subs)

    # ─── Source 4: amass (deep only) ─────────────────
    if depth == "deep":
        amass = _find_go_binary("amass")
        if amass:
            console.print("  [dim]Running amass (passive mode — may take a while)...[/dim]")
            subs = _run_amass(amass, domain, timeout)
            console.print(f"  [dim]amass: {len(subs)} subdomains[/dim]")
            all_subs.update(subs)
            tool_count += 1

    # ─── Fallback: DNS bruteforce ────────────────────
    if tool_count == 0 and len(all_subs) <= 1:
        console.print("  [yellow]⚠ Few results, running DNS bruteforce...[/yellow]")
        subs = _dns_bruteforce(domain, timeout)
        all_subs.update(subs)

    # Always include root domain
    all_subs.add(domain)

    # Deduplicate & sort
    all_subs = sorted(all_subs)

    # Save
    output_file = os.path.join(output_dir, "subdomains.txt")
    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(all_subs))

    console.print(
        f"  [green]✓ Total unique subdomains: {len(all_subs)}[/green]  "
        f"[dim]→ {output_file}[/dim]"
    )

    return all_subs
