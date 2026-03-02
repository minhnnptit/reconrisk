"""
Phase 3 — Subdomain Prioritization (v2.1)

2-pass scoring:
  Pass 1 (DNS only): prefix analysis, CNAME, IP patterns, negative signals
  Pass 2 (optional, after probe): HTTP status, tech stack, response patterns

Scoring range: -20 to +80 (pre-probe), capped at 100 post-probe.
"""

import re
from collections import Counter
from rich.console import Console

console = Console()

# ─── Positive scoring patterns ────────────────────────────────────

# High-value: dev/staging environments → security usually weaker
HIGH_VALUE_PREFIXES = {
    "dev", "develop", "development", "staging", "stg",
    "admin", "administrator", "panel", "dashboard", "manage",
    "api", "api-v1", "api-v2", "api-v3", "api-internal",
    "internal", "intranet", "corp", "private", "secret",
    "vpn", "remote", "gateway", "sso", "auth", "login",
    "console", "portal",
}

# Non-production → may have debug features
MEDIUM_VALUE_PREFIXES = {
    "test", "testing", "beta", "alpha", "uat", "qa",
    "sandbox", "demo", "preview", "canary",
    "old", "legacy", "backup", "bak", "temp",
    "debug", "lab", "poc", "trial", "pre-prod",
    "new", "v2", "v3", "next",
}

# Infrastructure → potential misconfigs
INFRA_PREFIXES = {
    "mail", "smtp", "pop", "pop3", "imap", "webmail", "mx",
    "ftp", "sftp", "ssh", "rdp",
    "ns1", "ns2", "ns3", "dns",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "jenkins", "ci", "cd", "git", "gitlab", "bitbucket", "svn",
    "monitor", "grafana", "prometheus", "nagios", "zabbix",
    "docker", "k8s", "kubernetes", "registry", "harbor",
    "jira", "confluence", "wiki", "docs",
    "elastic", "kibana", "logstash", "elk",
}

# ─── Negative scoring patterns (low attack surface) ──────────────

LOW_VALUE_PREFIXES = {
    # CDN / Static assets
    "cdn", "cdn1", "cdn2", "cdn3", "static", "assets", "media",
    "img", "images", "image", "pic", "photo", "photos",
    "css", "js", "fonts", "font", "video", "videos",
    # Object storage
    "s3", "storage", "blob", "bucket", "download", "downloads",
    "files", "file", "upload", "uploads",
    # Marketing / Tracking
    "track", "tracking", "analytics", "pixel", "tag",
    "ads", "ad", "banner", "promo",
    "email", "newsletter", "marketing", "campaign",
    # Public-facing (usually hardened)
    "www", "web", "home", "shop", "store", "blog",
}

# Pattern-based negative signals
LOW_VALUE_PATTERNS = [
    r"^[0-9]+$",                    # pure numeric: 1, 2, 3
    r"^[0-9]+\.[0-9]+$",           # numeric.numeric: 1.3
    r"\.s3[-.]",                     # S3 bucket: xxx.s3-hn-2
    r"\.cdn[-.]",                    # CDN: xxx.cdn-1
    r"comwww\.",                     # garbage crt.sh: xxx.comwww
    r"^auto[0-9]*$",               # autodiscover, autoconfig
    r"^_",                          # underscore prefix (DNS records)
    r"^selector[0-9]*$",           # DKIM selectors
    r"^dkim",                       # DKIM
    r"^spf",                        # SPF records
]


def _score_subdomain(subdomain, dns_data, root_domain):
    """
    Score a single subdomain. Higher = more interesting for pentesting.
    Returns: (score, tags)
    """
    score = 0
    tags = []
    host_data = dns_data.get("hosts", {}).get(subdomain, {})

    # ── Not resolved → dead ──────────────────────────
    if not host_data.get("resolved", False):
        return -1, ["dead"]

    score += 5  # Resolved baseline

    # ── Extract hostname parts ────────────────────────
    # Remove root domain to get prefix parts
    if subdomain.endswith("." + root_domain):
        prefix_part = subdomain[: -(len(root_domain) + 1)]
    elif subdomain == root_domain:
        return 15, ["root"]  # root domain always mid-priority
    else:
        prefix_part = subdomain.split(".")[0]

    prefix = prefix_part.split(".")[0].lower()
    full_prefix = prefix_part.lower()

    # ── Negative scoring (check first) ────────────────
    # Low-value prefix
    if prefix in LOW_VALUE_PREFIXES:
        score -= 10
        tags.append("low-value")

    # Pattern-based negatives
    for pattern in LOW_VALUE_PATTERNS:
        if re.search(pattern, full_prefix):
            score -= 15
            if "low-value" not in tags:
                tags.append("low-value")
            break

    # ── Positive scoring ──────────────────────────────
    # High-value prefix
    if prefix in HIGH_VALUE_PREFIXES:
        score += 35
        tags.append("high-value")
    # Check if ANY part of the prefix is high-value (e.g. dev.api)
    elif any(p in HIGH_VALUE_PREFIXES for p in full_prefix.split(".")):
        score += 30
        tags.append("high-value")
    # Medium-value prefix
    elif prefix in MEDIUM_VALUE_PREFIXES:
        score += 20
        tags.append("non-prod")
    # Infrastructure
    elif prefix in INFRA_PREFIXES:
        score += 15
        tags.append("infra")

    # ── CNAME analysis ────────────────────────────────
    cname = host_data.get("cname", "")
    if cname:
        # Third-party CNAME → potential takeover
        if root_domain not in cname:
            score += 20
            tags.append("external-cname")
        else:
            score += 5
            tags.append("cname")

    # ── Subdomain takeover ────────────────────────────
    takeovers = dns_data.get("takeovers", [])
    for t in takeovers:
        if t.get("subdomain") == subdomain:
            score += 40
            tags.append("takeover!")

    # ── IP analysis ───────────────────────────────────
    ips = host_data.get("ips", [])
    ip_map = dns_data.get("ip_map", {})

    if ips:
        # Unique IP — only this subdomain uses it
        for ip in ips:
            subs_on_ip = ip_map.get(ip, [])
            if len(subs_on_ip) == 1:
                score += 15
                tags.append("unique-ip")
                break
            elif len(subs_on_ip) <= 3:
                score += 5
                tags.append("rare-ip")
                break

        # Private/internal IP ranges → interesting!
        for ip in ips:
            if ip.startswith(("10.", "172.16.", "172.17.", "172.18.",
                              "172.19.", "172.2", "172.3", "192.168.")):
                score += 20
                tags.append("internal-ip")
                break

    # ── Deep subdomain scoring (smarter) ──────────────
    depth = len(subdomain.split(".")) - len(root_domain.split("."))
    if depth >= 3:
        # Very deep (e.g. admin.dev.api.example.com) — only valuable
        # if the prefix parts are interesting
        deep_parts = prefix_part.split(".")
        has_interesting_part = any(
            p in HIGH_VALUE_PREFIXES or p in MEDIUM_VALUE_PREFIXES or p in INFRA_PREFIXES
            for p in deep_parts
        )
        if has_interesting_part:
            score += 15
            tags.append("deep-interesting")
        else:
            score += 3  # minimal bonus for depth alone
            tags.append("deep-sub")
    elif depth == 2:
        score += 5
        tags.append("sub-sub")

    return score, tags


def _detect_wildcard(dns_data):
    """
    Detect wildcard DNS: if many subdomains resolve to the same IP.
    Uses threshold-based detection.
    """
    ip_map = dns_data.get("ip_map", {})
    hosts = dns_data.get("hosts", {})
    total_resolved = sum(1 for h in hosts.values() if h.get("resolved"))
    wildcard_ips = set()

    if total_resolved < 5:
        return wildcard_ips  # Too few to detect wildcard

    for ip, subs in ip_map.items():
        # If >50% of resolved subdomains share one IP → wildcard
        if len(subs) > total_resolved * 0.5:
            wildcard_ips.add(ip)
        # Also detect if >20 subdomains share one IP (even if <50%)
        elif len(subs) > 20:
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
    root_domain = config.get("domain", "")

    if not subdomains:
        console.print("  [yellow]⚠ No subdomains to prioritize[/yellow]")
        if root_domain:
            return [{"subdomain": root_domain, "score": 15, "tags": ["root"],
                      "ips": [], "cname": None}]
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
    root_included = False
    filter_reasons = Counter()

    for sub in subdomains:
        score, tags = _score_subdomain(sub, dns_data, root_domain)

        # ALWAYS keep root domain
        if sub == root_domain:
            root_included = True
            scored.append({
                "subdomain": sub,
                "score": max(score, 15),
                "tags": tags if tags != ["dead"] else ["root"],
                "ips": dns_data.get("hosts", {}).get(sub, {}).get("ips", []),
                "cname": dns_data.get("hosts", {}).get(sub, {}).get("cname"),
            })
            continue

        # Filter dead
        if "dead" in tags:
            filtered_count += 1
            filter_reasons["dead"] += 1
            continue

        # Filter wildcard (keep only if high-value)
        host_data = dns_data.get("hosts", {}).get(sub, {})
        ips = set(host_data.get("ips", []))
        if ips & wildcard_ips:
            if score < 25:  # Only keep high-scoring wildcard hosts
                filtered_count += 1
                filter_reasons["wildcard"] += 1
                continue

        # Filter very low-value subdomains (score <= 0)
        if score <= 0:
            filtered_count += 1
            filter_reasons["low-value"] += 1
            continue

        scored.append({
            "subdomain": sub,
            "score": score,
            "tags": tags,
            "ips": host_data.get("ips", []),
            "cname": host_data.get("cname"),
        })

    # Safety: always include root domain
    if not root_included and root_domain:
        scored.append({"subdomain": root_domain, "score": 15,
                       "tags": ["root"], "ips": [], "cname": None})

    # Sort by score descending
    scored.sort(key=lambda x: x["score"], reverse=True)

    # Apply --top if set
    top_n = config.get("top_n")
    if top_n and top_n > 0 and len(scored) > top_n:
        console.print(f"  [dim]Limiting to top {top_n} subdomains[/dim]")
        scored = scored[:top_n]

    # Print summary
    filter_detail = ""
    if filter_reasons:
        parts = [f"{v} {k}" for k, v in filter_reasons.most_common()]
        filter_detail = f" ({', '.join(parts)})"
    console.print(
        f"  [green]✓ Prioritized: {len(scored)} subdomains "
        f"(filtered {filtered_count}{filter_detail})[/green]"
    )

    # Print top entries with better formatting
    for item in scored[:10]:
        tags_str = ", ".join(item["tags"]) if item["tags"] else "normal"
        s = item["score"]
        if "takeover!" in item["tags"]:
            color = "bold red"
        elif s >= 35:
            color = "red"
        elif s >= 20:
            color = "yellow"
        elif s >= 10:
            color = "cyan"
        else:
            color = "dim"

        console.print(
            f"    [{color}]★{s:3d}  {item['subdomain']}"
            f"  ({tags_str})[/{color}]"
        )

    if len(scored) > 10:
        console.print(f"    [dim]... +{len(scored)-10} more[/dim]")

    return scored
