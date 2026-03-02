"""
Phase 5 — Tech Stack Detection

Strategy (priority):
  1. whatweb CLI (comprehensive) 
  2. Manual: HTTP headers + HTML body patterns (fallback)

Output: per-host tech profile {cms, language, server, framework, extras}
"""

import json
import re
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console

console = Console()

# ─── Header-based detection rules ────────────────────────────────

HEADER_RULES = [
    # (header_name, pattern, tech_name)
    ("X-Powered-By", r"PHP[/\s]*([\d.]+)?", "PHP"),
    ("X-Powered-By", r"ASP\.NET", "ASP.NET"),
    ("X-Powered-By", r"Express", "Express.js"),
    ("X-Powered-By", r"Next\.js", "Next.js"),
    ("X-Powered-By", r"Servlet", "Java Servlet"),
    ("Server", r"Apache[/\s]*([\d.]+)?", "Apache"),
    ("Server", r"nginx[/\s]*([\d.]+)?", "Nginx"),
    ("Server", r"Microsoft-IIS[/\s]*([\d.]+)?", "IIS"),
    ("Server", r"LiteSpeed", "LiteSpeed"),
    ("Server", r"Cloudflare", "Cloudflare"),
    ("X-Drupal-Cache", r".*", "Drupal"),
    ("X-Generator", r"WordPress[/\s]*([\d.]+)?", "WordPress"),
    ("X-Generator", r"Joomla", "Joomla"),
    ("X-Generator", r"Drupal", "Drupal"),
]

COOKIE_RULES = [
    # (cookie_name_pattern, tech_name)
    (r"PHPSESSID", "PHP"),
    (r"JSESSIONID", "Java/Tomcat"),
    (r"ASP\.NET_SessionId", "ASP.NET"),
    (r"connect\.sid", "Node.js/Express"),
    (r"_rails_session", "Ruby on Rails"),
    (r"laravel_session", "Laravel"),
    (r"ci_session", "CodeIgniter"),
    (r"wp-settings", "WordPress"),
    (r"csrftoken", "Django"),
    (r"_flask", "Flask"),
]

# ─── Body-based detection patterns ───────────────────────────────

BODY_PATTERNS = [
    # (regex_pattern, tech_name)
    (r"/wp-content/|/wp-includes/|wp-json", "WordPress"),
    (r"/_next/static|__NEXT_DATA__", "Next.js"),
    (r"/static/js/main\.\w+\.js", "React (CRA)"),
    (r"ng-version|ng-app|angular", "Angular"),
    (r"__vue__|vue\.js|vue\.min\.js", "Vue.js"),
    (r'<meta name="generator" content="WordPress\s*([\d.]+)?"', "WordPress"),
    (r'<meta name="generator" content="Joomla', "Joomla"),
    (r'<meta name="generator" content="Drupal', "Drupal"),
    (r"powered by.*shopify", "Shopify"),
    (r"cdnjs\.cloudflare\.com/ajax/libs/jquery/([\d.]+)", "jQuery"),
    (r"/assets/application-\w+\.js", "Ruby on Rails"),
    (r"django|csrfmiddlewaretoken", "Django"),
    (r"laravel|Laravel", "Laravel"),
    (r"/static/admin/", "Django Admin"),
    (r"Powered by.*Flask", "Flask"),
]


def _detect_from_headers(headers):
    """Detect tech from HTTP response headers."""
    detected = []

    for header_name, pattern, tech_name in HEADER_RULES:
        value = headers.get(header_name, "")
        if value:
            match = re.search(pattern, value, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else ""
                full = f"{tech_name}/{version}" if version else tech_name
                detected.append({"tech": full, "source": "header", "confidence": "high"})

    # Cookie analysis
    cookies = headers.get("Set-Cookie", "")
    for cookie_pattern, tech_name in COOKIE_RULES:
        if re.search(cookie_pattern, cookies, re.IGNORECASE):
            detected.append({"tech": tech_name, "source": "cookie", "confidence": "medium"})

    return detected


def _detect_from_body(body):
    """Detect tech from HTML body."""
    detected = []
    if not body:
        return detected

    # Limit body scan to first 50KB
    body_scan = body[:50000]

    for pattern, tech_name in BODY_PATTERNS:
        match = re.search(pattern, body_scan, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else ""
            full = f"{tech_name}/{version}" if version else tech_name
            detected.append({"tech": full, "source": "body", "confidence": "medium"})

    return detected


def _run_whatweb(url, timeout=15):
    """Run whatweb CLI on a single URL."""
    try:
        result = subprocess.run(
            ["whatweb", "--color=never", "-q", "--log-json=-", url],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.stdout.strip():
            data = json.loads(result.stdout.strip().split("\n")[0])
            techs = []
            for plugin_name, plugin_data in data.get("plugins", {}).items():
                if plugin_name in ("Title", "IP", "Country", "HTTPServer", "UncommonHeaders"):
                    continue
                version = ""
                if isinstance(plugin_data, dict):
                    ver_list = plugin_data.get("version", [])
                    version = ver_list[0] if ver_list else ""
                full = f"{plugin_name}/{version}" if version else plugin_name
                techs.append({"tech": full, "source": "whatweb", "confidence": "high"})
            return techs
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return []


def _detect_single_host(probe, use_whatweb=False, timeout=10):
    """Detect tech stack for a single host."""
    url = probe.get("url", "")
    host = probe.get("host", "")

    all_tech = []

    # Method 1: whatweb (if available)
    if use_whatweb:
        whatweb_tech = _run_whatweb(url, timeout)
        all_tech.extend(whatweb_tech)

    # Method 2: Parse headers from probe data
    server = probe.get("server", "")
    if server:
        # Parse Server header
        for _, pattern, tech_name in HEADER_RULES:
            match = re.search(pattern, server, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else ""
                full = f"{tech_name}/{version}" if version else tech_name
                all_tech.append({"tech": full, "source": "probe-header", "confidence": "high"})

    # Method 3: Fetch page and analyze (if not using whatweb)
    if not use_whatweb:
        try:
            resp = requests.get(
                url, timeout=timeout, verify=False,
                headers={"User-Agent": "ReconRisk/1.0"},
                allow_redirects=True,
            )
            all_tech.extend(_detect_from_headers(dict(resp.headers)))
            all_tech.extend(_detect_from_body(resp.text))
        except Exception:
            pass

    # Probe tech (already collected during probe phase)
    for t in probe.get("tech", []):
        all_tech.append({"tech": t, "source": "httpx", "confidence": "high"})

    # Deduplicate by tech name (keep highest confidence)
    seen = {}
    for item in all_tech:
        tech_base = item["tech"].split("/")[0].lower()
        if tech_base not in seen:
            seen[tech_base] = item
        elif item["confidence"] == "high" and seen[tech_base]["confidence"] != "high":
            seen[tech_base] = item

    return {
        "host": host,
        "url": url,
        "tech": list(seen.values()),
    }


def run_tech_detect(config, results):
    """
    Main entry point cho Phase 5.
    Input: probe data (alive hosts)
    Returns: list of tech profiles
    """
    probes = results.get("probe", [])
    if not probes:
        console.print("  [yellow]⚠ No alive hosts to analyze[/yellow]")
        return []

    threads = config.get("threads", 5)
    timeout = min(config.get("timeout", 120), 15)
    use_whatweb = shutil.which("whatweb") is not None

    if use_whatweb:
        console.print("  [dim]Using whatweb + header/body analysis...[/dim]")
    else:
        console.print("  [dim]whatweb not found, using header/body analysis...[/dim]")

    console.print(f"  [dim]Analyzing {len(probes)} hosts...[/dim]")

    tech_results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_detect_single_host, probe, use_whatweb, timeout): probe
            for probe in probes
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                tech_results.append(result)
                if result["tech"]:
                    techs_str = ", ".join(t["tech"] for t in result["tech"][:5])
                    if len(result["tech"]) > 5:
                        techs_str += f" +{len(result['tech'])-5}"
                    console.print(f"    [cyan]{result['host']}[/cyan]: {techs_str}")
                else:
                    console.print(f"    [dim]{result['host']}: no tech detected[/dim]")
            except Exception:
                pass

    console.print(f"  [green]✓ Detected tech on {sum(1 for r in tech_results if r['tech'])} hosts[/green]")

    return tech_results
