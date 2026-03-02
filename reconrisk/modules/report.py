"""
Phase 7 — Terminal Report

State Machine:
  CollectAllData → BuildTable → PrintToTerminal → SaveJSON
  Optional: PrintDeltaSection nếu --compare

Renders rich colored table, sorted by risk score.
"""

import json
import os
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


def _build_report_data(config, results):
    """Aggregate tất cả data vào report dict."""
    report = {
        "domain": config["domain"],
        "timestamp": datetime.now().isoformat(),
        "depth": config["depth"],
        "steps": config["steps"],
        "hosts": [],
        "summary": {},
    }

    risk_data = results.get("risk", [])

    if risk_data:
        for item in risk_data:
            cves = item.get("cves", [])
            # Count by severity
            crit_count = sum(1 for c in cves if c.get("cvss", 0) >= 9.0)
            high_count = sum(1 for c in cves if 7.0 <= c.get("cvss", 0) < 9.0)
            med_count = sum(1 for c in cves if 4.0 <= c.get("cvss", 0) < 7.0)

            host_entry = {
                "host": item.get("host", ""),
                "url": item.get("probe", {}).get("url", ""),
                "status": item.get("probe", {}).get("status", 0),
                "title": item.get("probe", {}).get("title", ""),
                "server": item.get("probe", {}).get("server", ""),
                "ports": [
                    f"{p.get('port', '')}/{p.get('service', '')}"
                    for p in item.get("ports", [])
                ],
                "cves": cves,
                "cve_count": len(cves),
                "cve_critical": crit_count,
                "cve_high": high_count,
                "cve_medium": med_count,
                "score": item.get("score", 0),
                "band": item.get("band", "LOW"),
                "emoji": item.get("emoji", "🟢"),
            }

            report["hosts"].append(host_entry)
    else:
        # Fallback: chỉ có probe data
        probe_data = results.get("probe", [])
        for probe in probe_data:
            report["hosts"].append({
                "host": probe.get("host", ""),
                "url": probe.get("url", ""),
                "status": probe.get("status", 0),
                "title": probe.get("title", ""),
                "server": probe.get("server", ""),
                "ports": [],
                "cves": [],
                "cve_count": 0,
                "cve_critical": 0,
                "cve_high": 0,
                "cve_medium": 0,
                "score": 0,
                "band": "N/A",
                "emoji": "❓",
            })

    # Summary stats
    report["summary"] = {
        "total_hosts": len(report["hosts"]),
        "alive_hosts": sum(1 for h in report["hosts"] if h["status"] in range(200, 400)),
        "critical": sum(1 for h in report["hosts"] if h["band"] == "CRITICAL"),
        "high": sum(1 for h in report["hosts"] if h["band"] == "HIGH"),
        "medium": sum(1 for h in report["hosts"] if h["band"] == "MEDIUM"),
        "low": sum(1 for h in report["hosts"] if h["band"] == "LOW"),
    }

    return report


def _print_scan_table(report, top_n=None):
    """Print rich table to terminal."""
    table = Table(
        title=f"🔍 ReconRisk Report — {report['domain']}",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )

    table.add_column("Host", style="bold white", max_width=30)
    table.add_column("Status", justify="center", width=7)
    table.add_column("Open Ports", max_width=22)
    table.add_column("CVEs", justify="center", max_width=18)
    table.add_column("Score", justify="center", width=7)
    table.add_column("Risk", justify="center", width=10)

    hosts = report["hosts"]

    # Sort by score desc
    hosts.sort(key=lambda h: h.get("score", 0), reverse=True)

    # Top N filter
    if top_n and top_n > 0:
        hosts = hosts[:top_n]

    for h in hosts:
        # Status color
        status = h.get("status", 0)
        if 200 <= status < 300:
            status_str = f"[green]{status}[/green]"
        elif 300 <= status < 400:
            status_str = f"[yellow]{status}[/yellow]"
        elif status >= 400:
            status_str = f"[red]{status}[/red]"
        else:
            status_str = str(status)

        # Ports
        ports = h.get("ports", [])
        ports_str = ", ".join(ports[:4])
        if len(ports) > 4:
            ports_str += f" +{len(ports)-4}"

        # CVE summary — show count per severity
        cve_parts = []
        if h.get("cve_critical", 0):
            cve_parts.append(f"[red]{h['cve_critical']}C[/red]")
        if h.get("cve_high", 0):
            cve_parts.append(f"[yellow]{h['cve_high']}H[/yellow]")
        if h.get("cve_medium", 0):
            cve_parts.append(f"[dim]{h['cve_medium']}M[/dim]")
        cve_str = " ".join(cve_parts) if cve_parts else "[dim]0[/dim]"

        # Score color
        score = h.get("score", 0)
        band = h.get("band", "N/A")
        emoji = h.get("emoji", "")

        if band == "CRITICAL":
            score_style = "bold red"
            band_str = f"[bold red]{emoji} {band}[/bold red]"
        elif band == "HIGH":
            score_style = "bold yellow"
            band_str = f"[bold yellow]{emoji} {band}[/bold yellow]"
        elif band == "MEDIUM":
            score_style = "yellow"
            band_str = f"[yellow]{emoji} {band}[/yellow]"
        else:
            score_style = "green"
            band_str = f"[green]{emoji} {band}[/green]"

        table.add_row(
            h.get("host", ""),
            status_str,
            ports_str,
            cve_str,
            f"[{score_style}]{score}[/{score_style}]",
            band_str,
        )

    console.print()
    console.print(table)

    # Summary panel
    s = report.get("summary", {})
    summary_text = Text()
    summary_text.append(f"🎯 Total: {s.get('total_hosts', 0)} hosts", style="bold")
    summary_text.append(f"  |  Alive: {s.get('alive_hosts', 0)}", style="dim")
    summary_text.append(f"\n🔴 Critical: {s.get('critical', 0)}", style="red")
    summary_text.append(f"  🟠 High: {s.get('high', 0)}", style="yellow")
    summary_text.append(f"  🟡 Medium: {s.get('medium', 0)}", style="yellow")
    summary_text.append(f"  🟢 Low: {s.get('low', 0)}", style="green")
    summary_text.append(f"\n⏱  Timestamp: {report.get('timestamp', '')}", style="dim")
    summary_text.append(f"  |  Depth: {report.get('depth', 'fast')}", style="dim")

    console.print(Panel(summary_text, title="Summary", border_style="dim"))


def _print_delta_section(delta_data):
    """Print delta changes section."""
    if not delta_data:
        return

    console.print()
    console.print(Panel(
        f"[bold]📊 Changes Since Last Scan — {len(delta_data)} items[/bold]",
        border_style="magenta",
    ))

    table = Table(border_style="magenta", show_lines=False)
    table.add_column("Change", width=10, style="bold")
    table.add_column("Host", max_width=30)
    table.add_column("Detail", max_width=50)

    for change in delta_data:
        tag = change.get("type", "")
        if tag == "NEW":
            tag_str = "[green][NEW][/green]"
        elif tag == "GONE":
            tag_str = "[red][GONE][/red]"
        else:
            sev = change.get("severity", "info")
            color = "red" if sev == "critical" else "yellow"
            tag_str = f"[{color}][CHANGED][/{color}]"

        table.add_row(tag_str, change.get("host", ""), change.get("detail", ""))

    console.print(table)


def _print_cve_detail_table(report):
    """
    Print bảng chi tiết CVE cho tất cả hosts.
    Grouped by host, sorted by CVSS descending.
    """
    # Collect all CVEs across hosts
    all_cves = []
    for h in report["hosts"]:
        for cve in h.get("cves", []):
            all_cves.append({
                "host": h["host"],
                **cve,
            })

    if not all_cves:
        return

    console.print()
    console.print(Panel(
        f"[bold]🛡️  CVE Details — {len(all_cves)} vulnerabilities found[/bold]",
        border_style="red",
    ))

    table = Table(
        border_style="red",
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("Host", style="bold", max_width=25)
    table.add_column("CVE ID", style="cyan", width=18)
    table.add_column("CVSS", justify="center", width=6)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Description", max_width=60)

    # Sort by CVSS desc
    all_cves.sort(key=lambda c: c.get("cvss", 0), reverse=True)

    for cve in all_cves:
        cvss = cve.get("cvss", 0)
        severity = cve.get("severity", "MEDIUM")

        if severity == "CRITICAL":
            cvss_str = f"[bold red]{cvss}[/bold red]"
            sev_str = f"[bold red]🔴 {severity}[/bold red]"
        elif severity == "HIGH":
            cvss_str = f"[yellow]{cvss}[/yellow]"
            sev_str = f"[yellow]🟠 {severity}[/yellow]"
        else:
            cvss_str = f"[dim]{cvss}[/dim]"
            sev_str = f"[dim]🟡 {severity}[/dim]"

        desc = cve.get("description", "")[:80]
        if len(cve.get("description", "")) > 80:
            desc += "..."

        table.add_row(
            cve.get("host", ""),
            cve.get("id", ""),
            cvss_str,
            sev_str,
            desc,
        )

    console.print(table)


def _save_report(report, output_dir):
    """Save report as JSON file."""
    filepath = os.path.join(output_dir, "report.json")
    os.makedirs(output_dir, exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)
    console.print(f"\n  [dim]📁 Report saved: {filepath}[/dim]")
    return filepath


def run_report(config, results):
    """
    Main entry point cho Phase 7.
    Builds table, prints to terminal, saves JSON.
    """
    # Build report data
    report = _build_report_data(config, results)

    # Print main table (hosts overview)
    _print_scan_table(report, top_n=config.get("top_n"))

    # Print CVE detail table
    _print_cve_detail_table(report)

    # Print delta if available
    delta_data = results.get("delta")
    if delta_data:
        _print_delta_section(delta_data)

    # Save JSON
    _save_report(report, config["output_dir"])

    return report
