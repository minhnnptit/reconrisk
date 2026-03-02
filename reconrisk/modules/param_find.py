"""
Phase 9 — Parameter Discovery (arjun)

Tìm hidden GET/POST parameters trên alive web hosts.
Auto-flag dangerous params: SSRF, LFI, RCE, IDOR patterns.
"""

import json
import os
import subprocess
import shutil
import re
import tempfile

from rich.console import Console

console = Console()

# ─── Dangerous parameter patterns ────────────────────────────────

DANGER_PARAMS = {
    "ssrf_redirect": {
        "patterns": [
            r"^url$", r"^redirect", r"^next$", r"^return",
            r"^target$", r"^dest", r"^goto", r"^link",
            r"^callback$", r"^continue$", r"^rurl$",
        ],
        "emoji": "🔴",
        "label": "SSRF/Redirect",
        "attack": "SSRF, Open Redirect",
        "risk_add": 15,
    },
    "lfi_rfi": {
        "patterns": [
            r"^file", r"^path$", r"^page$", r"^include",
            r"^dir$", r"^doc$", r"^folder$", r"^load",
            r"^template$", r"^read$", r"^view$",
        ],
        "emoji": "🔴",
        "label": "LFI/RFI",
        "attack": "Local/Remote File Inclusion",
        "risk_add": 15,
    },
    "rce": {
        "patterns": [
            r"^cmd$", r"^exec", r"^command", r"^run$",
            r"^shell$", r"^ping$", r"^process",
        ],
        "emoji": "🔴",
        "label": "RCE",
        "attack": "Remote Code Execution",
        "risk_add": 20,
    },
    "idor": {
        "patterns": [
            r"^id$", r"^uid$", r"^user_?id", r"^account",
            r"^pid$", r"^profile", r"^order_?id",
        ],
        "emoji": "🟠",
        "label": "IDOR",
        "attack": "Insecure Direct Object Reference",
        "risk_add": 10,
    },
    "sqli_xss": {
        "patterns": [
            r"^q$", r"^search", r"^query", r"^keyword",
            r"^s$", r"^input$", r"^name$", r"^comment",
            r"^message$", r"^text$", r"^body$",
        ],
        "emoji": "🟠",
        "label": "SQLi/XSS",
        "attack": "SQL Injection, XSS",
        "risk_add": 10,
    },
    "debug_admin": {
        "patterns": [
            r"^debug$", r"^test$", r"^admin$", r"^mode$",
            r"^verbose$", r"^dev$", r"^internal",
        ],
        "emoji": "🟠",
        "label": "Debug/Admin",
        "attack": "Hidden Debug Functionality",
        "risk_add": 10,
    },
    "ssti": {
        "patterns": [
            r"^template$", r"^render$", r"^tpl$",
            r"^engine$", r"^layout$",
        ],
        "emoji": "🟡",
        "label": "SSTI",
        "attack": "Server-Side Template Injection",
        "risk_add": 10,
    },
}


def _classify_param(param_name):
    """Auto-flag a parameter based on name."""
    flags = []
    for category, info in DANGER_PARAMS.items():
        for pattern in info["patterns"]:
            if re.search(pattern, param_name.lower()):
                flags.append({
                    "category": category,
                    "emoji": info["emoji"],
                    "label": info["label"],
                    "attack": info["attack"],
                    "risk_add": info["risk_add"],
                })
                break
    return flags


def _run_arjun(url, timeout=60):
    """
    Run arjun on a single URL.
    Uses temp file for JSON output to avoid parsing banner/ANSI junk from stdout.
    """
    # Create temp file for JSON output
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="arjun_"
        ) as tmp:
            tmp_path = tmp.name
    except Exception:
        return []

    try:
        result = subprocess.run(
            [
                "arjun", "-u", url,
                "-oJ", tmp_path,
                "-t", "10",
                "--stable",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        # Read params from temp JSON file
        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 2:
            with open(tmp_path, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    return []

            # Arjun JSON format: [{url: ..., params: [...]}] or {url: [...]}
            if isinstance(data, list):
                # v2.2+: [{"url": "...", "params": ["p1", "p2"]}]
                params = []
                for entry in data:
                    if isinstance(entry, dict):
                        params.extend(entry.get("params", []))
                    elif isinstance(entry, str):
                        params.append(entry)
                return params
            elif isinstance(data, dict):
                # Older format: {"url": ["param1", "param2"]}
                for key, val in data.items():
                    if isinstance(val, list):
                        return val
                return []

        return []

    except subprocess.TimeoutExpired:
        console.print(f"    [yellow]⚠ arjun timed out ({timeout}s)[/yellow]")
    except FileNotFoundError:
        pass
    finally:
        # Clean up temp file
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass

    return []


def _scan_single_host(probe, timeout):
    """Find params on a single host."""
    url = probe.get("url", "")
    host = probe.get("host", "")

    raw_params = _run_arjun(url, timeout)

    params = []
    for p in raw_params:
        name = p if isinstance(p, str) else p.get("name", str(p))
        # Skip ANSI/garbage strings
        if not name or "\x1b" in name or "[" in name or len(name) > 50:
            continue
        # Skip if it looks like a log line
        if name.startswith("*") or name.startswith("Scanning") or "://" in name:
            continue
        flags = _classify_param(name)
        params.append({
            "name": name,
            "source": "arjun",
            "flags": flags,
        })

    return {
        "host": host,
        "url": url,
        "params": params,
        "total": len(params),
    }


def run_param_find(config, results):
    """
    Main entry point cho Phase 9.
    Input: probe data (alive web hosts)
    Returns: list of param results per host
    """
    probes = results.get("probe", [])
    if not probes:
        console.print("  [yellow]⚠ No alive hosts for param discovery[/yellow]")
        return []

    # Only scan hosts with useful status (skip 503/5xx)
    scannable = [
        p for p in probes
        if p.get("status", 0) in (200, 201, 301, 302, 307, 401, 403)
    ]
    if not scannable:
        console.print("  [yellow]⚠ No hosts with scannable status[/yellow]")
        return []

    # Limit hosts: fast=10, deep=25
    depth = config.get("depth", "fast")
    max_hosts = 25 if depth == "deep" else 10
    if len(scannable) > max_hosts:
        console.print(f"  [dim]Limiting to {max_hosts} hosts (total: {len(scannable)})[/dim]")
        scannable = scannable[:max_hosts]

    # Per-host timeout: 60s fast, 90s deep
    timeout = 90 if depth == "deep" else 60

    use_arjun = shutil.which("arjun") is not None
    if not use_arjun:
        console.print("  [yellow]⚠ arjun not found — skipping param discovery[/yellow]")
        console.print("  [dim]Install: pip3 install arjun[/dim]")
        return []

    console.print(
        f"  [dim]Using arjun on {len(scannable)} hosts "
        f"(filtered from {len(probes)} alive, {timeout}s/host)...[/dim]"
    )

    param_results = []
    for i, probe in enumerate(scannable):
        host = probe.get("host", "")
        console.print(f"  [{i+1}/{len(scannable)}] [dim]{host}...[/dim]", end="")

        result = _scan_single_host(probe, timeout)
        param_results.append(result)

        if result["params"]:
            console.print(f"  [green]{result['total']} params found[/green]")
            for p in result["params"]:
                if p["flags"]:
                    flag_str = " ".join(f["emoji"] + f["label"] for f in p["flags"])
                    console.print(f"      {flag_str}: ?{p['name']}=")
                else:
                    console.print(f"      [dim]?{p['name']}=[/dim]")
        else:
            console.print("  [dim]no params[/dim]")

    # Summary
    total_params = sum(r["total"] for r in param_results)
    dangerous = sum(
        1 for r in param_results
        for p in r["params"] if p["flags"]
    )
    console.print(
        f"  [green]✓ Total: {total_params} params, "
        f"{dangerous} flagged as dangerous[/green]"
    )

    # Save
    output_dir = config["output_dir"]
    os.makedirs(output_dir, exist_ok=True)
    param_file = os.path.join(output_dir, "params.json")
    with open(param_file, "w") as f:
        json.dump(param_results, f, indent=2)

    return param_results
