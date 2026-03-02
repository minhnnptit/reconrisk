"""
Phase 2 — DNS Resolution

Resolve subdomains → IPs, detect CNAME (subdomain takeover potential),
deduplicate IPs, build reverse mapping.
"""

import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console

console = Console()


def _resolve_host(subdomain):
    """Resolve a subdomain to A records and check CNAME."""
    import dns.resolver
    import dns.name

    result = {
        "subdomain": subdomain,
        "ips": [],
        "cname": None,
        "resolved": False,
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # Check CNAME first
    try:
        answers = resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            cname_target = str(rdata.target).rstrip(".")
            result["cname"] = cname_target
    except Exception:
        pass

    # Resolve A records
    try:
        answers = resolver.resolve(subdomain, "A")
        for rdata in answers:
            result["ips"].append(str(rdata.address))
        result["resolved"] = True
    except Exception:
        pass

    # Resolve AAAA records
    try:
        answers = resolver.resolve(subdomain, "AAAA")
        for rdata in answers:
            result["ips"].append(str(rdata.address))
        if result["ips"]:
            result["resolved"] = True
    except Exception:
        pass

    return result


# Known services susceptible to subdomain takeover
TAKEOVER_CNAMES = [
    "s3.amazonaws.com", "s3-website", "cloudfront.net",
    "herokuapp.com", "herokussl.com",
    "github.io", "github.com",
    "azurewebsites.net", "cloudapp.net",
    "trafficmanager.net",
    "shopify.com", "myshopify.com",
    "pantheon.io", "fastly.net",
    "ghost.io", "helpscoutdocs.com",
    "helpjuice.com", "unbouncepages.com",
    "feedpress.me", "surge.sh",
    "bitbucket.io", "gitlab.io",
]


def _check_takeover(cname):
    """Check if CNAME points to a service vulnerable to takeover."""
    if not cname:
        return False, ""
    cname_lower = cname.lower()
    for pattern in TAKEOVER_CNAMES:
        if pattern in cname_lower:
            return True, pattern
    return False, ""


def run_dns_resolve(config, results):
    """
    Main entry point cho Phase 2.
    Input: subdomains list
    Returns: dns_map dict
    """
    subdomains = results.get("subdomain", [])
    if not subdomains:
        console.print("  [yellow]⚠ No subdomains to resolve[/yellow]")
        return {}

    threads = config.get("threads", 10)
    output_dir = config["output_dir"]

    console.print(f"  [dim]Resolving {len(subdomains)} subdomains (threads={threads})...[/dim]")

    dns_map = {
        "hosts": {},       # subdomain → {ips, cname, resolved}
        "ip_map": {},      # IP → [subdomains]
        "unique_ips": [],
        "takeovers": [],   # potential subdomain takeovers
    }

    resolved_count = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_resolve_host, sub): sub
            for sub in subdomains
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                sub = result["subdomain"]
                dns_map["hosts"][sub] = result

                if result["resolved"]:
                    resolved_count += 1
                    for ip in result["ips"]:
                        if ip not in dns_map["ip_map"]:
                            dns_map["ip_map"][ip] = []
                        dns_map["ip_map"][ip].append(sub)

                # Check takeover
                if result["cname"]:
                    is_vuln, service = _check_takeover(result["cname"])
                    if is_vuln:
                        dns_map["takeovers"].append({
                            "subdomain": sub,
                            "cname": result["cname"],
                            "service": service,
                        })
                        console.print(
                            f"    [bold red]⚠ TAKEOVER: {sub} → "
                            f"{result['cname']} ({service})[/bold red]"
                        )
            except Exception:
                pass

    # Unique IPs
    dns_map["unique_ips"] = sorted(dns_map["ip_map"].keys())

    # Summary
    console.print(
        f"  [green]✓ Resolved: {resolved_count}/{len(subdomains)} subdomains → "
        f"{len(dns_map['unique_ips'])} unique IPs[/green]"
    )
    if dns_map["takeovers"]:
        console.print(
            f"  [bold red]⚠ {len(dns_map['takeovers'])} potential subdomain takeovers![/bold red]"
        )

    # Save
    dns_file = os.path.join(output_dir, "dns_map.json")
    os.makedirs(output_dir, exist_ok=True)
    with open(dns_file, "w") as f:
        json.dump(dns_map, f, indent=2, default=str)
    console.print(f"  [dim]→ {dns_file}[/dim]")

    return dns_map
