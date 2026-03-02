"""
Phase 8 — Parameter Discovery (arjun)

Tìm hidden GET/POST parameters trên alive web hosts.
Auto-flag dangerous params: SSRF, LFI, RCE, IDOR patterns.
"""

import json
import os
import subprocess
import shutil
import re

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


def _run_arjun(url, timeout=120):
    """Run arjun on a single URL."""
    try:
        result = subprocess.run(
            [
                "arjun", "-u", url,
                "-oJ", "/dev/stdout",
                "-t", "10",
                "--stable",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                # Arjun output format varies by version
                if isinstance(data, dict):
                    return data.get(url, data.get("params", []))
                elif isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                # Parse text output: param1, param2, ...
                params = []
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("["):
                        params.extend(p.strip() for p in line.split(",") if p.strip())
                return params
    except subprocess.TimeoutExpired:
        console.print(f"    [yellow]⚠ arjun timed out on {url}[/yellow]")
    except FileNotFoundError:
        pass
    return []


def _scan_single_host(probe, use_arjun, timeout):
    """Find params on a single host."""
    url = probe.get("url", "")
    host = probe.get("host", "")

    params = []

    if use_arjun:
        raw_params = _run_arjun(url, timeout)
        for p in raw_params:
            name = p if isinstance(p, str) else p.get("name", str(p))
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
    Main entry point cho Phase 8.
    Input: probe data (alive web hosts)
    Returns: list of param results per host
    """
    probes = results.get("probe", [])
    if not probes:
        console.print("  [yellow]⚠ No alive hosts for param discovery[/yellow]")
        return []

    timeout = config.get("timeout", 120)
    use_arjun = shutil.which("arjun") is not None

    if not use_arjun:
        console.print("  [yellow]⚠ arjun not found — skipping param discovery[/yellow]")
        console.print("  [dim]Install: pip3 install arjun[/dim]")
        return []

    console.print(f"  [dim]Using arjun on {len(probes)} hosts...[/dim]")

    param_results = []
    for i, probe in enumerate(probes):
        host = probe.get("host", "")
        console.print(f"  [{i+1}/{len(probes)}] [dim]{host}...[/dim]", end="")

        result = _scan_single_host(probe, use_arjun, timeout)
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
