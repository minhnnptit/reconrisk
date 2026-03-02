"""
Phase 2 — HTTP Probe (Optimized)

Strategy (priority order):
  1. ProjectDiscovery httpx (Go binary) — nhanh nhất, feature đầy đủ
  2. Python httpx library (async, HTTP/2) — tốt hơn requests
  3. requests library — fallback cuối cùng

Binary conflict: Kali có Python `httpx` CLI khác với Go `httpx`.
Fix: tìm Go binary ở ~/go/bin/httpx trực tiếp.
"""

import json
import os
import re
import subprocess
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console

console = Console()


def _find_go_httpx():
    """
    Tìm ProjectDiscovery httpx binary.
    Returns: full path hoặc None
    
    Priority:
      1. ~/go/bin/httpx
      2. $(go env GOPATH)/bin/httpx
      3. httpx trong PATH (verify là ProjectDiscovery version)
    """
    # Check ~/go/bin/httpx
    home_go = os.path.join(str(Path.home()), "go", "bin", "httpx")
    if os.path.isfile(home_go) and os.access(home_go, os.X_OK):
        return home_go

    # Check GOPATH/bin/httpx
    try:
        result = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True, text=True, timeout=5,
        )
        gopath = result.stdout.strip()
        if gopath:
            gopath_httpx = os.path.join(gopath, "bin", "httpx")
            if os.path.isfile(gopath_httpx) and os.access(gopath_httpx, os.X_OK):
                return gopath_httpx
    except Exception:
        pass

    # Check httpx trong PATH — verify là ProjectDiscovery
    httpx_path = shutil.which("httpx")
    if httpx_path:
        try:
            result = subprocess.run(
                [httpx_path, "-version"],
                capture_output=True, text=True, timeout=5,
            )
            output = (result.stdout + result.stderr).lower()
            if "projectdiscovery" in output or "current version" in output:
                return httpx_path
        except Exception:
            pass

    return None


def _run_go_httpx(httpx_path, subdomains, depth, timeout):
    """
    Chạy ProjectDiscovery httpx (Go binary).
    Returns list of probe dicts.
    """
    input_data = "\n".join(subdomains)

    cmd = [httpx_path, "-silent", "-sc", "-title", "-server", "-json"]
    if depth == "deep":
        cmd.extend(["-follow-redirects", "-tls-probe", "-tech-detect"])

    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        probes = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                probe = {
                    "url": data.get("url", ""),
                    "host": data.get("host", data.get("input", "")),
                    "status": data.get("status_code", data.get("status-code", 0)),
                    "title": data.get("title", ""),
                    "server": data.get("webserver", data.get("server", "")),
                    "tech": data.get("tech", []),
                    "tls": data.get("tls", {}),
                    "content_length": data.get("content_length", data.get("content-length", 0)),
                }
                probes.append(probe)
            except json.JSONDecodeError:
                continue

        return probes

    except subprocess.TimeoutExpired:
        console.print(f"  [yellow]⚠ httpx timed out after {timeout}s[/yellow]")
        return []
    except FileNotFoundError:
        console.print(f"  [yellow]⚠ httpx binary not found at {httpx_path}[/yellow]")
        return []


def _probe_single(subdomain, timeout_sec=10):
    """
    Probe một subdomain bằng requests.
    Thử HTTPS trước, rồi HTTP.
    Collect headers bổ sung cho security analysis.
    """
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(
                url,
                timeout=timeout_sec,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "ReconRisk/1.0"},
            )
            # Trích title từ HTML
            title = ""
            if resp.text:
                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    title = match.group(1).strip()[:100]

            # Collect security-relevant headers
            headers = resp.headers
            tech = []
            for header in ["X-Powered-By", "X-AspNet-Version", "X-Generator"]:
                val = headers.get(header, "")
                if val:
                    tech.append(val)

            return {
                "url": resp.url,  # URL sau redirect
                "host": subdomain,
                "status": resp.status_code,
                "title": title,
                "server": headers.get("Server", ""),
                "tech": tech,
                "tls": {
                    "enabled": scheme == "https",
                    "redirected_to_https": resp.url.startswith("https://") and scheme == "http",
                },
                "content_length": len(resp.content),
                "headers": {
                    "x_frame_options": headers.get("X-Frame-Options", ""),
                    "content_security_policy": headers.get("Content-Security-Policy", ""),
                    "strict_transport_security": headers.get("Strict-Transport-Security", ""),
                },
            }
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.RequestException:
            continue

    return None


def _fallback_probe(subdomains, threads, timeout):
    """
    Fallback: dùng requests + thread pool.
    """
    probes = []
    timeout_per_req = min(10, timeout // max(len(subdomains), 1))

    console.print(f"  [dim]Probing {len(subdomains)} hosts (threads={threads})...[/dim]")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_probe_single, sub, timeout_per_req): sub
            for sub in subdomains
        }
        for future in as_completed(futures):
            sub = futures[future]
            try:
                result = future.result()
                if result:
                    probes.append(result)
                    status = result["status"]
                    status_color = "green" if status < 400 else "yellow" if status < 500 else "red"
                    tls_icon = "🔒" if result["tls"].get("enabled") else "⚠️"
                    console.print(
                        f"    [{status_color}]{status}[/{status_color}] "
                        f"{tls_icon} {result['url']}  [dim]{result['title'][:50]}[/dim]"
                    )
            except Exception:
                pass

    return probes


def run_probe(config, results):
    """
    Main entry point cho Phase 2.
    Input: subdomains từ Phase 1
    Returns: list of probe dicts
    """
    depth = config["depth"]
    timeout = config["timeout"]
    threads = config["threads"]

    # Lấy subdomains từ Phase 1
    subdomains = results.get("subdomain", [])
    if not subdomains:
        console.print("  [yellow]⚠ No subdomains to probe (subdomain phase not run?)[/yellow]")
        return []

    console.print(f"  [dim]Probing {len(subdomains)} subdomains...[/dim]")

    # Strategy 1: Tìm ProjectDiscovery httpx Go binary
    go_httpx = _find_go_httpx()

    if go_httpx:
        console.print(f"  [dim]Using ProjectDiscovery httpx ({depth} mode) → {go_httpx}[/dim]")
        probes = _run_go_httpx(go_httpx, subdomains, depth, timeout)
        if probes:
            console.print(f"  [green]✓ httpx found {len(probes)} alive hosts[/green]")
            return probes
        console.print("  [yellow]⚠ httpx returned no results, falling back...[/yellow]")
    else:
        console.print("  [dim]ProjectDiscovery httpx not found, using requests probe[/dim]")

    # Strategy 2: requests fallback (with thread pool)
    probes = _fallback_probe(subdomains, threads, timeout)
    console.print(f"  [green]✓ Found {len(probes)} alive hosts[/green]")

    return probes
