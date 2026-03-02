"""
Phase 4 — CVE Enrichment (NVD API v2)

State Machine:
  CollectServices → PickService → CheckCache → CacheHit/CacheMiss
    CacheMiss → RateLimit → CallNVD → ParseCVEs → SaveToCache
  Loop until all services done → ReturnCVEData
"""

import json
import os
import time
import hashlib
from pathlib import Path

import requests as req
from rich.console import Console

console = Console()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = os.path.join(str(Path.home()), ".reconrisk")
CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")


def _load_cache():
    """Load CVE cache from disk."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _save_cache(cache):
    """Save CVE cache to disk."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        console.print(f"  [yellow]⚠ Cannot save cache: {e}[/yellow]")


def _cache_key(service, version):
    """Tạo cache key từ service + version."""
    raw = f"{service}:{version}".lower().strip()
    return hashlib.md5(raw.encode()).hexdigest()


def _query_nvd(keyword, nvd_key=None, max_results=50):
    """
    Query NVD API v2 cho keyword.
    Returns list of CVE dicts, sorted by CVSS descending.
    Lọc bỏ CVSS < 4.0 (noise).
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    headers = {}
    if nvd_key:
        headers["apiKey"] = nvd_key

    try:
        resp = req.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=30,
        )

        if resp.status_code == 429:
            console.print("  [yellow]⚠ NVD rate limited (429), waiting...[/yellow]")
            return "RATE_LIMITED"

        if resp.status_code != 200:
            console.print(f"  [yellow]⚠ NVD API returned {resp.status_code}[/yellow]")
            return []

        data = resp.json()
        cves = []

        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            # CVSS score — try v3.1 first, then v3.0, then v2
            cvss = 0.0
            metrics = cve_data.get("metrics", {})
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss = cvss_data.get("baseScore", 0.0)
                    break

            # Description
            desc = ""
            descs = cve_data.get("descriptions", [])
            for d in descs:
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break

            if cve_id and cvss >= 4.0:
                cves.append({
                    "id": cve_id,
                    "cvss": cvss,
                    "severity": "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM",
                    "description": desc,
                })

        # Sort by CVSS descending — critical first
        cves.sort(key=lambda c: c["cvss"], reverse=True)
        return cves

    except req.exceptions.Timeout:
        console.print("  [yellow]⚠ NVD API timeout[/yellow]")
        return []
    except req.exceptions.RequestException as e:
        console.print(f"  [yellow]⚠ NVD API error: {e}[/yellow]")
        return []
    except (json.JSONDecodeError, KeyError) as e:
        console.print(f"  [yellow]⚠ NVD response parse error: {e}[/yellow]")
        return []


def _extract_services(config, results):
    """
    Trích xuất danh sách (service, version) từ probe + port data.
    Lọc bỏ noise: tcpwrapped, unknown, services không có version.
    """
    # Noise filter — skip các service không có ý nghĩa cho CVE lookup
    NOISE_SERVICES = {
        "tcpwrapped", "unknown", "filtered", "closed",
        "", "none", "general", "unrecognized",
    }

    services = []
    seen = set()

    # Từ probe data (server header)
    probe_data = results.get("probe", [])
    for probe in probe_data:
        server = probe.get("server", "").strip()
        if not server or server.lower() in NOISE_SERVICES:
            continue

        # Parse "Apache/2.4.7 (Ubuntu)" → ("Apache", "2.4.7")
        # Strip OS info trong ngoặc
        import re
        clean = re.sub(r"\s*\(.*?\)\s*", " ", server).strip()
        parts = clean.split("/", 1)
        service = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else ""

        key = f"{service}:{version}".lower()
        if key not in seen and service and version:
            seen.add(key)
            services.append({
                "service": service,
                "version": version,
                "source": "probe",
                "host": probe.get("host", ""),
            })

    # Từ port scan data (nmap service detection)
    port_data = results.get("port", {})
    for hostname, host_data in port_data.items():
        for port_info in host_data.get("ports", []):
            product = port_info.get("product", "")
            version = port_info.get("version", "")
            service_name = port_info.get("service", "")

            # Skip noise
            if (product or service_name).lower() in NOISE_SERVICES:
                continue

            # Skip nếu không có version — query sẽ trả về noise
            if not version:
                continue

            key = f"{product or service_name}:{version}".lower()
            if key not in seen and (product or service_name):
                seen.add(key)
                services.append({
                    "service": product or service_name,
                    "version": version,
                    "source": "nmap",
                    "host": hostname,
                })

    return services


def run_cve_lookup(config, results):
    """
    Main entry point cho Phase 4.
    Returns: dict {service_key: {service, version, cves: [...]}}
    """
    nvd_key = config.get("nvd_key")
    no_cache = config.get("no_cache", False)

    # Rate limit intervals
    rate_limit = 0.6 if nvd_key else 6.0

    # Extract services to lookup
    services = _extract_services(config, results)
    if not services:
        console.print("  [yellow]⚠ No services found for CVE lookup[/yellow]")
        return {}

    console.print(f"  [dim]Found {len(services)} unique services to check[/dim]")

    # Load cache
    cache = {} if no_cache else _load_cache()

    cve_results = {}

    for i, svc in enumerate(services):
        service = svc["service"]
        version = svc["version"]
        host = svc["host"]
        keyword = f"{service} {version}".strip()
        key = _cache_key(service, version)

        console.print(
            f"  [{i+1}/{len(services)}] "
            f"[dim]{service} {version}[/dim]  [dim]({host})[/dim]",
            end="",
        )

        # Check cache
        if key in cache and not no_cache:
            cves = cache[key]
            console.print(f"  [cyan](cached: {len(cves)} CVEs)[/cyan]")
        else:
            # Rate limit
            if i > 0:
                time.sleep(rate_limit)

            # Query NVD
            result = _query_nvd(keyword, nvd_key)

            if result == "RATE_LIMITED":
                # Wait and retry once
                time.sleep(30)
                result = _query_nvd(keyword, nvd_key)
                if result == "RATE_LIMITED":
                    result = []

            cves = result if isinstance(result, list) else []

            # Save to cache
            cache[key] = cves
            console.print(f"  [green]({len(cves)} CVEs)[/green]")

        cve_results[keyword] = {
            "service": service,
            "version": version,
            "host": host,
            "cves": cves,
        }

    # Save cache
    if not no_cache:
        _save_cache(cache)
        console.print(f"  [dim]Cache saved: {CACHE_FILE}[/dim]")

    # Summary
    total_cves = sum(len(v["cves"]) for v in cve_results.values())
    critical = sum(
        1
        for v in cve_results.values()
        for c in v["cves"]
        if c.get("cvss", 0) >= 9.0
    )
    console.print(
        f"  [green]✓ Total: {total_cves} CVEs "
        f"({critical} critical)[/green]"
    )

    return cve_results
