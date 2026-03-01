"""
Phase 2 — HTTP Probe

State Machine:
  CheckInput → CheckHttpx → UseHttpx / UseFallback → BuildProbeData → Return
  
  - httpx: chạy subprocess, parse JSON lines
  - Fallback: requests.get() với thread pool
"""

import json
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console

console = Console()


def _check_tool(name):
    """Kiểm tra tool có trong PATH không."""
    return shutil.which(name) is not None


def _run_httpx(subdomains, depth, timeout):
    """
    Chạy httpx subprocess, parse JSON output.
    Returns list of probe dicts.
    """
    # httpx đọc từ stdin
    input_data = "\n".join(subdomains)

    cmd = ["httpx", "-silent", "-sc", "-title", "-server", "-json"]
    if depth == "deep":
        cmd.extend(["-follow-redirects", "-tls-probe"])

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
        console.print("  [yellow]⚠ httpx not found[/yellow]")
        return []


def _probe_single(subdomain, timeout_sec=10):
    """
    Fallback: probe một subdomain bằng requests.
    Thử HTTPS trước, rồi HTTP.
    """
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(
                url,
                timeout=timeout_sec,
                allow_redirects=True,
                verify=False,  # Chấp nhận self-signed cert
                headers={"User-Agent": "ReconRisk/1.0"},
            )
            # Trích title từ HTML
            title = ""
            if resp.text:
                import re
                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    title = match.group(1).strip()[:100]

            return {
                "url": url,
                "host": subdomain,
                "status": resp.status_code,
                "title": title,
                "server": resp.headers.get("Server", ""),
                "tech": [],
                "tls": {"enabled": scheme == "https"},
                "content_length": len(resp.content),
            }
        except requests.exceptions.SSLError:
            # HTTPS failed, try HTTP
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

    console.print(f"  [dim]Probing {len(subdomains)} hosts with requests (threads={threads})...[/dim]")

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
                    status_color = "green" if result["status"] < 400 else "yellow"
                    console.print(
                        f"    [{status_color}]{result['status']}[/{status_color}] "
                        f"{result['url']}  [dim]{result['title'][:50]}[/dim]"
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

    has_httpx = _check_tool("httpx")

    if has_httpx:
        console.print(f"  [dim]Using httpx ({depth} mode)...[/dim]")
        probes = _run_httpx(subdomains, depth, timeout)
        if probes:
            console.print(f"  [green]✓ httpx found {len(probes)} alive hosts[/green]")
            return probes
        console.print("  [yellow]⚠ httpx returned no results, falling back to requests[/yellow]")

    # Fallback
    probes = _fallback_probe(subdomains, threads, timeout)
    console.print(f"  [green]✓ Found {len(probes)} alive hosts[/green]")

    return probes
