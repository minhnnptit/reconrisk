"""
Phase 1 — Subdomain Enumeration

State Machine:
  CheckTools → RunEnum (fast/deep) → Deduplicate → SaveFile → ReturnList
  Fallback: dnspython brute resolve nếu thiếu subfinder
"""

import os
import subprocess
import shutil
from pathlib import Path

from rich.console import Console

console = Console()


def _check_tool(name):
    """Kiểm tra tool có trong PATH không."""
    return shutil.which(name) is not None


def _run_subfinder(domain, depth, timeout):
    """Chạy subfinder subprocess."""
    cmd = ["subfinder", "-d", domain, "-silent"]
    if depth == "deep":
        # Deep mode: nhiều source hơn, recursive
        cmd.extend(["-all", "-recursive"])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            subs = [
                line.strip()
                for line in result.stdout.strip().split("\n")
                if line.strip()
            ]
            return subs
        else:
            console.print(f"  [yellow]⚠ subfinder stderr: {result.stderr.strip()[:200]}[/yellow]")
            return []
    except subprocess.TimeoutExpired:
        console.print(f"  [yellow]⚠ subfinder timed out after {timeout}s[/yellow]")
        return []
    except FileNotFoundError:
        console.print("  [yellow]⚠ subfinder not found[/yellow]")
        return []


def _run_assetfinder(domain, timeout):
    """Chạy assetfinder subprocess."""
    cmd = ["assetfinder", "--subs-only", domain]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            subs = [
                line.strip()
                for line in result.stdout.strip().split("\n")
                if line.strip() and domain in line
            ]
            return subs
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _dns_bruteforce(domain, timeout):
    """
    Fallback: dùng dnspython để resolve một wordlist nhỏ.
    Chạy khi không có subfinder/assetfinder.
    """
    try:
        import dns.resolver
    except ImportError:
        console.print("  [yellow]⚠ dnspython not installed, cannot bruteforce[/yellow]")
        return []

    # Wordlist nhỏ cho fallback
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
                console.print(f"    [green]+ {subdomain}[/green]")
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

    # Check available tools
    has_subfinder = _check_tool("subfinder")
    has_assetfinder = _check_tool("assetfinder")

    if has_subfinder:
        console.print(f"  [dim]Running subfinder ({depth} mode)...[/dim]")
        subs = _run_subfinder(domain, depth, timeout)
        console.print(f"  [dim]subfinder found {len(subs)} subdomains[/dim]")
        all_subs.update(subs)
    else:
        console.print("  [yellow]⚠ subfinder not found[/yellow]")

    if has_assetfinder and depth == "fast":
        console.print("  [dim]Running assetfinder...[/dim]")
        subs = _run_assetfinder(domain, timeout)
        console.print(f"  [dim]assetfinder found {len(subs)} subdomains[/dim]")
        all_subs.update(subs)

    # Fallback nếu không có tool nào
    if not has_subfinder and not has_assetfinder:
        console.print("  [yellow]⚠ No recon tools found, falling back to DNS bruteforce[/yellow]")
        subs = _dns_bruteforce(domain, timeout)
        all_subs.update(subs)

    # Luôn thêm domain gốc
    all_subs.add(domain)

    # Deduplicate & sort
    all_subs = sorted(all_subs)

    # Save to file
    output_file = os.path.join(output_dir, "subdomains.txt")
    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(all_subs))

    console.print(
        f"  [green]✓ Total unique subdomains: {len(all_subs)}[/green]  "
        f"[dim]→ {output_file}[/dim]"
    )

    return all_subs
