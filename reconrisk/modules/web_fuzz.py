"""
Phase 7 — Web Directory Fuzzing (ffuf)

Smart filtering: chỉ hiện results có ý nghĩa cho pentester.
Auto-flag: admin panels, config leaks, backup files.
"""

import json
import os
import subprocess
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console

console = Console()

# ─── Auto-flag patterns (HIGH INTEREST) ──────────────────────────

FLAG_PATTERNS = {
    "admin_panel": {
        "patterns": [
            r"admin", r"login", r"dashboard", r"panel",
            r"manager", r"control", r"wp-admin", r"cpanel",
            r"phpmyadmin", r"adminer",
        ],
        "emoji": "🔴",
        "label": "Admin Panel",
        "risk_add": 10,
    },
    "config_leak": {
        "patterns": [
            r"\.git", r"\.env", r"\.htaccess", r"\.htpasswd",
            r"config", r"\.config", r"web\.config",
            r"phpinfo", r"info\.php",
            r"\.svn", r"\.hg",
        ],
        "emoji": "🔴",
        "label": "Config Leak",
        "risk_add": 20,
    },
    "backup_file": {
        "patterns": [
            r"\.bak$", r"\.sql$", r"\.zip$", r"\.tar",
            r"\.gz$", r"\.rar$", r"backup", r"dump",
            r"\.old$", r"\.orig$", r"\.save$",
        ],
        "emoji": "🔴",
        "label": "Backup File",
        "risk_add": 15,
    },
    "api_endpoint": {
        "patterns": [
            r"api", r"graphql", r"swagger", r"openapi",
            r"rest", r"v1", r"v2", r"endpoint",
        ],
        "emoji": "🟠",
        "label": "API Endpoint",
        "risk_add": 5,
    },
    "info_disclosure": {
        "patterns": [
            r"server-status", r"server-info",
            r"status", r"health", r"metrics",
            r"debug", r"trace", r"test",
        ],
        "emoji": "🟠",
        "label": "Info Disclosure",
        "risk_add": 10,
    },
    "file_upload": {
        "patterns": [
            r"upload", r"file", r"media", r"attachment",
        ],
        "emoji": "🟡",
        "label": "File Upload",
        "risk_add": 5,
    },
}


def _classify_path(path):
    """Auto-flag a discovered path."""
    import re
    path_lower = path.lower()
    flags = []
    for category, info in FLAG_PATTERNS.items():
        for pattern in info["patterns"]:
            if re.search(pattern, path_lower):
                flags.append({
                    "category": category,
                    "emoji": info["emoji"],
                    "label": info["label"],
                    "risk_add": info["risk_add"],
                })
                break  # One match per category
    return flags


def _get_wordlist(depth):
    """Get wordlist path based on depth."""
    script_dir = Path(__file__).parent.parent
    if depth == "deep":
        wl = script_dir / "wordlists" / "dirs_large.txt"
    else:
        wl = script_dir / "wordlists" / "dirs_small.txt"

    if wl.exists():
        return str(wl)

    # Fallback: check common SecLists locations
    seclists_paths = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]
    for p in seclists_paths:
        if os.path.exists(p):
            return p

    return None


def _run_ffuf(url, wordlist, timeout=120):
    """Run ffuf on a single URL."""
    cmd = [
        "ffuf",
        "-u", f"{url}/FUZZ",
        "-w", wordlist,
        "-mc", "200,201,301,302,307,401,403,405,500",
        "-o", "/dev/stdout",
        "-of", "json",
        "-s",  # silent
        "-t", "20",
        "-timeout", "10",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            return data.get("results", [])
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return []


def _fallback_fuzz(url, wordlist, timeout=60):
    """Fallback: simple requests-based directory brute."""
    results = []
    if not wordlist or not os.path.exists(wordlist):
        return results

    # Read wordlist (limit to 500 for fallback)
    with open(wordlist, "r") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    words = words[:500]

    for word in words:
        test_url = f"{url.rstrip('/')}/{word}"
        try:
            resp = requests.get(
                test_url, timeout=5, verify=False,
                headers={"User-Agent": "ReconRisk/1.0"},
                allow_redirects=False,
            )
            if resp.status_code in (200, 201, 301, 302, 307, 401, 403, 500):
                results.append({
                    "input": {"FUZZ": word},
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "url": test_url,
                })
        except Exception:
            continue

    return results


def _fuzz_single_host(probe, wordlist, use_ffuf, timeout):
    """Fuzz a single host and classify results."""
    url = probe.get("url", "").rstrip("/")
    host = probe.get("host", "")

    if use_ffuf:
        raw_results = _run_ffuf(url, wordlist, timeout)
    else:
        raw_results = _fallback_fuzz(url, wordlist, timeout)

    # Process and classify
    findings = []
    for r in raw_results:
        path = r.get("input", {}).get("FUZZ", "")
        status = r.get("status", 0)
        length = r.get("length", 0)

        # Skip empty responses
        if status == 200 and length == 0:
            continue

        flags = _classify_path(path)

        findings.append({
            "path": f"/{path}",
            "url": r.get("url", f"{url}/{path}"),
            "status": status,
            "length": length,
            "flags": flags,
        })

    return {
        "host": host,
        "url": url,
        "findings": findings,
        "total": len(findings),
    }


def run_web_fuzz(config, results):
    """
    Main entry point cho Phase 7.
    Input: alive probe data
    Returns: list of fuzz results per host
    """
    probes = results.get("probe", [])
    if not probes:
        console.print("  [yellow]⚠ No alive hosts to fuzz[/yellow]")
        return []

    depth = config.get("depth", "fast")
    timeout = config.get("timeout", 120)

    # Get wordlist
    wordlist = _get_wordlist(depth)
    if not wordlist:
        console.print("  [yellow]⚠ No wordlist found. Create wordlists/dirs_small.txt[/yellow]")
        console.print("  [dim]Or install SecLists: apt-get install seclists[/dim]")
        return []

    use_ffuf = shutil.which("ffuf") is not None
    tool_name = "ffuf" if use_ffuf else "requests"
    console.print(f"  [dim]Using {tool_name}, wordlist: {os.path.basename(wordlist)}[/dim]")
    console.print(f"  [dim]Fuzzing {len(probes)} hosts...[/dim]")

    fuzz_results = []
    for i, probe in enumerate(probes):
        host = probe.get("host", "")
        console.print(f"  [{i+1}/{len(probes)}] [dim]{host}...[/dim]", end="")

        result = _fuzz_single_host(probe, wordlist, use_ffuf, timeout)
        fuzz_results.append(result)

        if result["findings"]:
            console.print(f"  [green]{result['total']} paths found[/green]")
            # Print flagged items
            for f in result["findings"]:
                if f["flags"]:
                    flag_str = " ".join(fl["emoji"] + fl["label"] for fl in f["flags"])
                    console.print(f"      {flag_str}: {f['path']} [{f['status']}]")
        else:
            console.print("  [dim]nothing interesting[/dim]")

    # Summary
    total_findings = sum(r["total"] for r in fuzz_results)
    flagged = sum(
        1 for r in fuzz_results
        for f in r["findings"] if f["flags"]
    )
    console.print(
        f"  [green]✓ Total: {total_findings} paths, "
        f"{flagged} flagged as interesting[/green]"
    )

    # Save
    output_dir = config["output_dir"]
    os.makedirs(output_dir, exist_ok=True)
    fuzz_file = os.path.join(output_dir, "fuzz_results.json")
    with open(fuzz_file, "w") as f:
        json.dump(fuzz_results, f, indent=2)

    return fuzz_results
