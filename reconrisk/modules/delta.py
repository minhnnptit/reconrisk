"""
Phase 6 — Delta / Diff

State Machine:
  CheckCompareFlag → LoadBaseline → BaselineExists?
    NoBaseline → SaveAsBaseline → PrintFirstRun
    BaselineExists → ParseBaseline → ComputeDiff → UpdateBaseline → ReturnDelta
"""

import json
import os

from rich.console import Console

console = Console()


def _load_baseline(filepath):
    """Load baseline JSON."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def _save_baseline(filepath, data):
    """Save current scan as baseline."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _build_snapshot(results):
    """
    Build a serializable snapshot từ tất cả phase results.
    Structure: {host: {status, ports, cves, score}}
    """
    snapshot = {}

    # Từ risk data (đã tổng hợp tất cả)
    risk_data = results.get("risk", [])
    if risk_data:
        for item in risk_data:
            host = item.get("host", "")
            if not host:
                continue
            snapshot[host] = {
                "score": item.get("score", 0),
                "band": item.get("band", "LOW"),
                "ports": [
                    {"port": p.get("port"), "service": p.get("service", "")}
                    for p in item.get("ports", [])
                ],
                "cves": [
                    {"id": c.get("id", ""), "cvss": c.get("cvss", 0)}
                    for c in item.get("cves", [])
                ],
                "status": item.get("probe", {}).get("status", 0),
                "url": item.get("probe", {}).get("url", ""),
            }
    else:
        # Fallback: build from probe data
        probe_data = results.get("probe", [])
        for probe in probe_data:
            host = probe.get("host", "")
            if host:
                snapshot[host] = {
                    "score": 0,
                    "band": "LOW",
                    "ports": [],
                    "cves": [],
                    "status": probe.get("status", 0),
                    "url": probe.get("url", ""),
                }

    return snapshot


def _compute_diff(old_snapshot, new_snapshot):
    """
    So sánh 2 snapshots.
    Returns list of change dicts.
    """
    changes = []

    old_hosts = set(old_snapshot.keys())
    new_hosts = set(new_snapshot.keys())

    # NEW hosts
    for host in sorted(new_hosts - old_hosts):
        data = new_snapshot[host]
        detail = ""
        if data.get("ports"):
            ports_str = ", ".join(str(p["port"]) for p in data["ports"][:3])
            detail = f"ports: {ports_str}"
        changes.append({
            "type": "NEW",
            "host": host,
            "detail": detail or "new host discovered",
            "severity": "info",
        })

    # GONE hosts
    for host in sorted(old_hosts - new_hosts):
        changes.append({
            "type": "GONE",
            "host": host,
            "detail": "host offline or not responding",
            "severity": "info",
        })

    # CHANGED hosts
    for host in sorted(old_hosts & new_hosts):
        old = old_snapshot[host]
        new = new_snapshot[host]

        # Score change
        old_score = old.get("score", 0)
        new_score = new.get("score", 0)
        if old_score != new_score:
            diff = new_score - old_score
            sign = "+" if diff > 0 else ""
            severity = "warning" if diff > 0 else "info"
            changes.append({
                "type": "CHANGED",
                "host": host,
                "detail": f"risk score: {old_score} → {new_score} ({sign}{diff})",
                "severity": severity,
            })

        # New ports
        old_ports = {p["port"] for p in old.get("ports", [])}
        new_ports = {p["port"] for p in new.get("ports", [])}
        added_ports = new_ports - old_ports
        removed_ports = old_ports - new_ports

        for port in sorted(added_ports):
            # Sensitive port check
            sensitive = port in {22, 23, 3306, 5432, 1433, 6379, 27017}
            severity = "warning" if sensitive else "info"
            extra = " ⚠️ sensitive port" if sensitive else ""
            changes.append({
                "type": "NEW",
                "host": host,
                "detail": f"port {port} opened{extra}",
                "severity": severity,
            })

        for port in sorted(removed_ports):
            changes.append({
                "type": "GONE",
                "host": host,
                "detail": f"port {port} closed",
                "severity": "info",
            })

        # New CVEs
        old_cve_ids = {c["id"] for c in old.get("cves", [])}
        new_cve_ids = {c["id"] for c in new.get("cves", [])}
        added_cves = new_cve_ids - old_cve_ids

        for cve_id in sorted(added_cves):
            cve = next(
                (c for c in new.get("cves", []) if c["id"] == cve_id), {}
            )
            cvss = cve.get("cvss", 0)
            severity = "critical" if cvss >= 9.0 else "warning" if cvss >= 7.0 else "info"
            changes.append({
                "type": "CHANGED",
                "host": host,
                "detail": f"{cve_id} appeared (CVSS {cvss})",
                "severity": severity,
            })

    return changes


def run_delta(config, results):
    """
    Main entry point cho Phase 6.
    Returns: list of change dicts, hoặc None nếu --compare không set
    """
    if not config.get("compare", False):
        return None

    baseline_path = os.path.join(config["output_dir"], "baseline.json")

    # Build current snapshot
    current_snapshot = _build_snapshot(results)

    if not current_snapshot:
        console.print("  [yellow]⚠ No data to compare[/yellow]")
        return []

    # Load baseline
    old_snapshot = _load_baseline(baseline_path)

    if old_snapshot is None:
        # First run — save baseline
        _save_baseline(baseline_path, current_snapshot)
        console.print(
            f"  [cyan]📋 First scan — baseline saved: {baseline_path}[/cyan]"
        )
        console.print("  [dim]Run again with --compare to see changes[/dim]")
        return []

    # Compute diff
    changes = _compute_diff(old_snapshot, current_snapshot)

    # Update baseline
    _save_baseline(baseline_path, current_snapshot)

    # Print changes
    if changes:
        console.print(f"\n  [bold]📊 Changes since last scan ({len(changes)} items):[/bold]")
        for change in changes:
            tag = change["type"]
            host = change["host"]
            detail = change["detail"]

            if tag == "NEW":
                console.print(f"    [green][NEW]     {host}[/green] → {detail}")
            elif tag == "GONE":
                console.print(f"    [red][GONE]    {host}[/red] → {detail}")
            elif tag == "CHANGED":
                sev = change.get("severity", "info")
                color = "red" if sev == "critical" else "yellow" if sev == "warning" else "cyan"
                console.print(f"    [{color}][CHANGED] {host}[/{color}] → {detail}")
    else:
        console.print("  [green]✓ No changes detected since last scan[/green]")

    return changes
