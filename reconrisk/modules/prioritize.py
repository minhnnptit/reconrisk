"""
Phase 3 — Subdomain Prioritization

Score mỗi subdomain dựa trên prefix, CNAME, unique IP.
Filter wildcard, dead hosts. Sort by interest score.
"""

import re
from rich.console import Console

console = Console()

# ─── Scoring patterns ────────────────────────────────────────────

# Prefix nhạy cảm — dev/staging environments (security thường yếu hơn)
HIGH_VALUE_PREFIXES = {
    "dev", "develop", "development", "staging", "stg",
    "admin", "administrator", "panel", "dashboard",
    "api", "api-v1", "api-v2", "api-v3", "rest",
    "internal", "intranet", "corp", "private",
    "vpn", "remote", "gateway",
}

# Non-production
MEDIUM_VALUE_PREFIXES = {
    "test", "testing", "beta", "alpha", "uat", "qa",
    "sandbox", "demo", "preview", "canary",
    "old", "legacy", "backup", "bak", "temp",
    "debug", "lab", "poc",
}

# Infrastructure
INFRA_PREFIXES = {
    "mail", "smtp", "pop", "imap", "webmail", "mx",
    "ftp", "sftp", "ssh", "rdp",
    "ns1", "ns2", "dns",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "jenkins", "ci", "cd", "git", "gitlab", "bitbucket",
    "monitor", "grafana", "prometheus", "nagios",
    "docker", "k8s", "kubernetes", "registry",
}


def _score_subdomain(subdomain, dns_data):
    """Score a single subdomain. Higher = more interesting."""
    score = 0
    tags = []
    host_data = dns_data.get("hosts", {}).get(subdomain, {})

    # Base: resolved?
    if not host_data.get("resolved", False):
        return -1, ["dead"]  # Will be filtered

    score += 10  # Resolved bonus

    # Extract first part of subdomain
    parts = subdomain.split(".")
    prefix = parts[0].lower() if parts else ""

    # Check prefixes
    if prefix in HIGH_VALUE_PREFIXES:
        score += 30
        tags.append("high-value")
    elif prefix in MEDIUM_VALUE_PREFIXES:
        score += 20
        tags.append("non-prod")
    elif prefix in INFRA_PREFIXES:
        score += 15
        tags.append("infra")

    # Multi-level subdomains (deeper = less common = more interesting)
    # e.g. admin.dev.example.com
    domain_depth = len(parts) - 2  # minus domain + tld
    if domain_depth >= 2:
        score += 10
        tags.append("deep-sub")

    # CNAME → third-party (takeover potential)
    if host_data.get("cname"):
        score += 15
        tags.append("cname")

    # Check takeovers from dns_data
    takeovers = dns_data.get("takeovers", [])
    for t in takeovers:
        if t["subdomain"] == subdomain:
            score += 40
            tags.append("takeover!")

    # Unique IP — if only 1 subdomain points to this IP, more interesting
    ips = host_data.get("ips", [])
    ip_map = dns_data.get("ip_map", {})
    for ip in ips:
        subs_on_ip = ip_map.get(ip, [])
        if len(subs_on_ip) <= 2:
            score += 10
            tags.append("unique-ip")
            break

    return score, tags


def _detect_wildcard(dns_data):
    """
    Detect wildcard DNS: if many subdomains resolve to the same IP.
    Returns set of wildcard IPs.
    """
    ip_map = dns_data.get("ip_map", {})
    wildcard_ips = set()

    for ip, subs in ip_map.items():
        # If >60% of subdomains share one IP, likely wildcard
        total = len(dns_data.get("hosts", {}))
        if total > 5 and len(subs) > total * 0.6:
            wildcard_ips.add(ip)

    return wildcard_ips


def run_prioritize(config, results):
    """
    Main entry point cho Phase 3.
    Input: subdomain list + dns_map
    Returns: prioritized list of subdomain dicts
    """
    subdomains = results.get("subdomain", [])
    dns_data = results.get("resolve", {})

    if not subdomains:
        console.print("  [yellow]⚠ No subdomains to prioritize[/yellow]")
        return []

    # Detect wildcard
    wildcard_ips = _detect_wildcard(dns_data)
    if wildcard_ips:
        console.print(
            f"  [yellow]⚠ Wildcard DNS detected ({len(wildcard_ips)} IPs), "
            f"filtering affected subdomains[/yellow]"
        )

    # Score each subdomain
    scored = []
    filtered_count = 0

    for sub in subdomains:
        score, tags = _score_subdomain(sub, dns_data)

        # Filter dead
        if score < 0:
            filtered_count += 1
            continue

        # Filter wildcard (keep 1 representative per wildcard IP)
        host_data = dns_data.get("hosts", {}).get(sub, {})
        ips = set(host_data.get("ips", []))
        if ips & wildcard_ips:
            # Only keep if it has a high-value prefix
            if score < 20:
                filtered_count += 1
                continue

        scored.append({
            "subdomain": sub,
            "score": score,
            "tags": tags,
            "ips": host_data.get("ips", []),
            "cname": host_data.get("cname"),
        })

    # Sort by score descending
    scored.sort(key=lambda x: x["score"], reverse=True)

    # Apply --top if set
    top_n = config.get("top_n")
    if top_n and top_n > 0 and len(scored) > top_n:
        console.print(f"  [dim]Limiting to top {top_n} subdomains[/dim]")
        scored = scored[:top_n]

    # Print summary
    console.print(
        f"  [green]✓ Prioritized: {len(scored)} subdomains "
        f"(filtered {filtered_count} dead/wildcard)[/green]"
    )

    # Print top 10
    for item in scored[:10]:
        tags_str = ", ".join(item["tags"]) if item["tags"] else "normal"
        color = "red" if "takeover!" in item["tags"] else \
                "yellow" if "high-value" in item["tags"] else \
                "cyan" if "non-prod" in item["tags"] else "dim"
        console.print(
            f"    [{color}]★{item['score']:3d}  {item['subdomain']}"
            f"  ({tags_str})[/{color}]"
        )

    if len(scored) > 10:
        console.print(f"    [dim]... +{len(scored)-10} more[/dim]")

    return scored
