"""
Phase 10 — Risk Score (v2)

Pure computation — không gọi network.
Score mỗi host 0–100 dựa trên CVE, ports, HTTPS, fuzz, params, tech.

State Machine:
  CollectHostData → ScoreHosts (loop per host) → SortByScore → Return
"""

from rich.console import Console

console = Console()

# ─── Scoring constants ───────────────────────────────────────────────
SENSITIVE_PORTS = {22, 23, 3306, 5432, 1433, 6379, 27017, 11211, 5900, 2049}
ADMIN_PORTS = {8080, 8443, 9000, 9090, 9200, 8000, 8888, 4443, 2222, 10000}

SCORE_CRITICAL_CVE = 40   # CVSS >= 9.0
SCORE_HIGH_CVE = 25       # CVSS 7.0-8.9
SCORE_MEDIUM_CVE = 10     # CVSS 4.0-6.9 (max +20)
SCORE_SENSITIVE_PORT = 15
SCORE_ADMIN_PORT = 10
SCORE_HTTP_ONLY = 10
SCORE_CONFIG_LEAK = 20    # .git, .env found by fuzz
SCORE_ADMIN_PANEL = 10    # admin panel found by fuzz
SCORE_BACKUP_FILE = 15    # backup found by fuzz
SCORE_DANGER_PARAM = 15   # SSRF/LFI/RCE param
SCORE_DEBUG_PARAM = 10    # debug/admin param
SCORE_TAKEOVER = 40       # subdomain takeover

# Max scores để tránh inflate
MAX_MEDIUM_CVE_SCORE = 20


def _score_host(host, probe_data, port_data, cve_data, fuzz_data, param_data, dns_data):
    """
    Tính risk score cho một host.
    Returns: (score: int, breakdown: dict)
    """
    score = 0
    breakdown = {
        "critical_cves": 0,
        "high_cves": 0,
        "medium_cves": 0,
        "sensitive_ports": [],
        "admin_ports": [],
        "http_only": False,
        "config_leak": False,
        "admin_panel": False,
        "backup_found": False,
        "danger_params": 0,
        "debug_params": 0,
        "takeover": False,
    }

    # ── CVE scoring ──────────────────────────────────────────────
    medium_score = 0
    for svc_key, svc_data in cve_data.items():
        if svc_data.get("host", "") != host and host not in svc_key:
            continue
        for cve in svc_data.get("cves", []):
            cvss = cve.get("cvss", 0)
            if cvss >= 9.0:
                score += SCORE_CRITICAL_CVE
                breakdown["critical_cves"] += 1
            elif cvss >= 7.0:
                score += SCORE_HIGH_CVE
                breakdown["high_cves"] += 1
            elif cvss >= 4.0:
                medium_score += SCORE_MEDIUM_CVE
                breakdown["medium_cves"] += 1

    score += min(medium_score, MAX_MEDIUM_CVE_SCORE)

    # ── Port scoring ─────────────────────────────────────────────
    host_ports = set()
    for hostname, host_data in port_data.items():
        if hostname == host or host_data.get("ip") == host:
            for p in host_data.get("ports", []):
                port_num = p.get("port", 0)
                host_ports.add(port_num)

    sensitive = host_ports & SENSITIVE_PORTS
    if sensitive:
        score += SCORE_SENSITIVE_PORT
        breakdown["sensitive_ports"] = sorted(sensitive)

    admin = host_ports & ADMIN_PORTS
    if admin:
        score += SCORE_ADMIN_PORT
        breakdown["admin_ports"] = sorted(admin)

    # ── HTTPS check ──────────────────────────────────────────────
    for probe in probe_data:
        if probe.get("host") == host:
            url = probe.get("url", "")
            tls = probe.get("tls", {})
            if url.startswith("http://") and not tls.get("enabled", False):
                score += SCORE_HTTP_ONLY
                breakdown["http_only"] = True
            break

    # ── Fuzz scoring (NEW) ───────────────────────────────────────
    for fuzz_result in fuzz_data:
        if fuzz_result.get("host") != host:
            continue
        for finding in fuzz_result.get("findings", []):
            for flag in finding.get("flags", []):
                category = flag.get("category", "")
                if category == "config_leak" and not breakdown["config_leak"]:
                    score += SCORE_CONFIG_LEAK
                    breakdown["config_leak"] = True
                elif category == "admin_panel" and not breakdown["admin_panel"]:
                    score += SCORE_ADMIN_PANEL
                    breakdown["admin_panel"] = True
                elif category == "backup_file" and not breakdown["backup_found"]:
                    score += SCORE_BACKUP_FILE
                    breakdown["backup_found"] = True

    # ── Param scoring (NEW) ──────────────────────────────────────
    for param_result in param_data:
        if param_result.get("host") != host:
            continue
        for param in param_result.get("params", []):
            for flag in param.get("flags", []):
                category = flag.get("category", "")
                if category in ("ssrf_redirect", "lfi_rfi", "rce"):
                    score += min(SCORE_DANGER_PARAM, 15)  # cap at 15
                    breakdown["danger_params"] += 1
                elif category == "debug_admin":
                    score += min(SCORE_DEBUG_PARAM, 10)   # cap at 10
                    breakdown["debug_params"] += 1

    # ── Subdomain takeover (NEW) ─────────────────────────────────
    if dns_data:
        for t in dns_data.get("takeovers", []):
            if t.get("subdomain") == host:
                score += SCORE_TAKEOVER
                breakdown["takeover"] = True

    # Clamp to 0-100
    score = max(0, min(100, score))

    return score, breakdown


def _get_band(score):
    """Map score to risk band."""
    if score >= 70:
        return "CRITICAL", "🔴"
    elif score >= 50:
        return "HIGH", "🟠"
    elif score >= 30:
        return "MEDIUM", "🟡"
    else:
        return "LOW", "🟢"


def run_risk_score(config, results):
    """
    Main entry point cho Phase 10.
    Input: probe, port, cve, fuzz, param, dns data
    Returns: list of {host, score, band, emoji, breakdown, probe, ports, cves}
    """
    probe_data = results.get("probe", [])
    port_data = results.get("port", {})
    cve_data = results.get("cve", {})
    fuzz_data = results.get("fuzz", []) or []
    param_data = results.get("paramfind", []) or []
    dns_data = results.get("resolve", {}) or {}

    if not probe_data and not port_data:
        console.print("  [yellow]⚠ No probe or port data for scoring[/yellow]")
        return []

    # Collect all unique hosts
    hosts = set()
    for probe in probe_data:
        hosts.add(probe.get("host", ""))
    for hostname in port_data:
        hosts.add(hostname)

    hosts.discard("")

    console.print(f"  [dim]Scoring {len(hosts)} hosts...[/dim]")

    scored_hosts = []
    for host in hosts:
        score, breakdown = _score_host(
            host, probe_data, port_data, cve_data,
            fuzz_data, param_data, dns_data,
        )
        band, emoji = _get_band(score)

        # Collect host-specific data
        host_probe = next((p for p in probe_data if p.get("host") == host), {})
        host_ports = port_data.get(host, {}).get("ports", [])
        host_cves = []
        for svc_data in cve_data.values():
            if svc_data.get("host", "") == host or host in str(svc_data):
                host_cves.extend(svc_data.get("cves", []))

        scored_hosts.append({
            "host": host,
            "score": score,
            "band": band,
            "emoji": emoji,
            "breakdown": breakdown,
            "probe": host_probe,
            "ports": host_ports,
            "cves": host_cves,
        })

    # Sort by score, highest first
    scored_hosts.sort(key=lambda x: x["score"], reverse=True)

    # Print summary
    for h in scored_hosts[:10]:
        bd = h["breakdown"]
        extras = []
        if bd.get("config_leak"):
            extras.append("🔴leak")
        if bd.get("admin_panel"):
            extras.append("🔴admin")
        if bd.get("takeover"):
            extras.append("🔴takeover")
        if bd.get("danger_params"):
            extras.append(f"⚠{bd['danger_params']}params")

        extra_str = f"  {' '.join(extras)}" if extras else ""

        console.print(
            f"    {h['emoji']} [{h['band'].lower()}]{h['host']}[/{h['band'].lower()}]"
            f"  score={h['score']}  "
            f"[dim]({bd['critical_cves']}C "
            f"{bd['high_cves']}H "
            f"{bd['medium_cves']}M)[/dim]"
            f"{extra_str}"
        )

    if len(scored_hosts) > 10:
        console.print(f"    [dim]... +{len(scored_hosts)-10} more hosts[/dim]")

    return scored_hosts
