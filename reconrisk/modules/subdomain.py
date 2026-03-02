"""
Phase 1 — Subdomain Enumeration (v2)

Sources:
  - subfinder (fast + deep)
  - assetfinder (fast)
  - amass (deep only — slow but thorough)
  - crt.sh (certificate transparency, no install needed)
  - DNS bruteforce fallback (if no tools)
"""

import os
import json
import subprocess
import shutil
from pathlib import Path

import requests as req
from rich.console import Console

console = Console()


def _check_tool(name):
    return shutil.which(name) is not None


def _run_subfinder(domain, depth, timeout):
    """Chạy subfinder subprocess."""
    cmd = ["subfinder", "-d", domain, "-silent"]
    if depth == "deep":
        cmd.extend(["-all", "-recursive"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _run_assetfinder(domain, timeout):
    """Chạy assetfinder subprocess."""
    try:
        result = subprocess.run(
            ["assetfinder", "--subs-only", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return [l.strip() for l in result.stdout.strip().split("\n")
                    if l.strip() and domain in l]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _run_amass(domain, timeout):
    """Chạy amass passive enum (deep mode only)."""
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain],
            capture_output=True, text=True,
            timeout=timeout * 3,  # amass chạy lâu
        )
        if result.returncode == 0:
            return [l.strip() for l in result.stdout.strip().split("\n")
                    if l.strip() and domain in l]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        console.print("  [yellow]⚠ amass timed out or not found[/yellow]")
        return []


def _query_crtsh(domain, timeout):
    """Query crt.sh (Certificate Transparency logs) — no install needed."""
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
                # crt.sh may return wildcard or multi-line entries
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

    # ─── Source 1: subfinder ─────────────────────────
    has_subfinder = _check_tool("subfinder")
    if has_subfinder:
        console.print(f"  [dim]Running subfinder ({depth} mode)...[/dim]")
        subs = _run_subfinder(domain, depth, timeout)
        console.print(f"  [dim]subfinder: {len(subs)} subdomains[/dim]")
        all_subs.update(subs)
    else:
        console.print("  [yellow]⚠ subfinder not found[/yellow]")

    # ─── Source 2: assetfinder ───────────────────────
    has_assetfinder = _check_tool("assetfinder")
    if has_assetfinder:
        console.print("  [dim]Running assetfinder...[/dim]")
        subs = _run_assetfinder(domain, timeout)
        console.print(f"  [dim]assetfinder: {len(subs)} subdomains[/dim]")
        all_subs.update(subs)

    # ─── Source 3: crt.sh (always available) ─────────
    console.print("  [dim]Querying crt.sh (Certificate Transparency)...[/dim]")
    subs = _query_crtsh(domain, timeout)
    console.print(f"  [dim]crt.sh: {len(subs)} subdomains[/dim]")
    all_subs.update(subs)

    # ─── Source 4: amass (deep only) ─────────────────
    if depth == "deep" and _check_tool("amass"):
        console.print("  [dim]Running amass (passive mode — may take a while)...[/dim]")
        subs = _run_amass(domain, timeout)
        console.print(f"  [dim]amass: {len(subs)} subdomains[/dim]")
        all_subs.update(subs)

    # ─── Fallback: DNS bruteforce ────────────────────
    if not has_subfinder and not has_assetfinder and len(all_subs) <= 1:
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
