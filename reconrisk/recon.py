#!/usr/bin/env python3
"""
ReconRisk — Modular Recon CLI
Entry point: argparse → validate → build pipeline → run phases → report
"""

import argparse
import os
import sys
import time
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt

from modules import PHASES, PHASE_DEPS
from modules.subdomain import run_subdomain
from modules.dns_resolve import run_dns_resolve
from modules.prioritize import run_prioritize
from modules.http_probe import run_probe
from modules.tech_detect import run_tech_detect
from modules.port_scan import run_port_scan
from modules.web_fuzz import run_web_fuzz
from modules.cve_lookup import run_cve_lookup
from modules.param_find import run_param_find
from modules.risk_score import run_risk_score
from modules.delta import run_delta
from modules.report import run_report

console = Console()

# ─── Phase runner map ────────────────────────────────────────────────
PHASE_RUNNERS = {
    "subdomain": run_subdomain,
    "resolve": run_dns_resolve,
    "prioritize": run_prioritize,
    "probe": run_probe,
    "techdetect": run_tech_detect,
    "port": run_port_scan,
    "fuzz": run_web_fuzz,
    "cve": run_cve_lookup,
    "paramfind": run_param_find,
    "risk": run_risk_score,
    "delta": run_delta,
    "report": run_report,
}


def parse_args():
    """Parse và validate CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="ReconRisk — Modular Recon CLI with risk scoring & delta diff",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py -d example.com --steps subdomain,probe
  python3 recon.py -d example.com --all --depth deep --top 10
  python3 recon.py -d example.com --all --compare
        """,
    )

    # Required
    parser.add_argument(
        "-d", "--domain", required=True, help="Target domain (e.g. example.com)"
    )

    # Scope
    parser.add_argument(
        "--steps",
        type=str,
        default=None,
        help="Comma-separated phases: subdomain,resolve,prioritize,probe,"
             "techdetect,port,fuzz,cve,paramfind,risk,delta",
    )
    parser.add_argument(
        "--all", action="store_true", dest="run_all", help="Run all phases"
    )

    # Depth
    parser.add_argument(
        "--depth",
        choices=["fast", "deep"],
        default="fast",
        help="Scan depth: fast (default) or deep",
    )

    # Delta
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare with previous scan baseline",
    )

    # Output
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output directory (default: ./results/<domain>/)",
    )
    parser.add_argument(
        "--top", type=int, default=None, help="Show only top-N riskiest hosts"
    )

    # Misc
    parser.add_argument(
        "--threads", type=int, default=10, help="Concurrency level (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Timeout per phase in seconds (default: 120)",
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Disable CVE cache"
    )
    parser.add_argument("--nvd-key", type=str, default=None, help="NVD API key")
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Pause after subdomain enum to let user select targets",
    )

    args = parser.parse_args()
    return args


def validate_args(args):
    """Validate parsed arguments. Returns (config_dict, error_msg)."""
    # Validate domain
    domain = args.domain.strip().lower()
    if not domain or " " in domain:
        return None, f"Invalid domain: '{args.domain}'"

    # Xác định danh sách phase cần chạy
    if args.run_all or args.steps is None:
        # --all hoặc không chỉ định --steps → chạy tất cả
        steps = list(PHASES)
    else:
        steps = [s.strip().lower() for s in args.steps.split(",")]
        invalid = [s for s in steps if s not in PHASES]
        if invalid:
            return None, f"Unknown steps: {', '.join(invalid)}. Valid: {', '.join(PHASES)}"

    # Nếu --compare được set, thêm delta vào steps
    if args.compare and "delta" not in steps:
        steps.append("delta")

    # Report luôn chạy cuối cùng
    if "report" not in steps:
        steps.append("report")

    # Sắp xếp theo thứ tự PHASES
    phase_order = {p: i for i, p in enumerate(PHASES)}
    steps = sorted(steps, key=lambda s: phase_order.get(s, 999))

    # Output dir
    output_dir = args.output or os.path.join("results", domain)

    config = {
        "domain": domain,
        "steps": steps,
        "depth": args.depth,
        "compare": args.compare,
        "output_dir": output_dir,
        "top_n": args.top,
        "threads": args.threads,
        "timeout": args.timeout,
        "no_cache": args.no_cache,
        "nvd_key": args.nvd_key,
        "interactive": args.interactive,
    }
    return config, None


def check_phase_deps(phase, steps, results):
    """
    Kiểm tra dependencies của phase.
    Returns: (can_run: bool, missing: list)
    """
    deps = PHASE_DEPS.get(phase, [])
    missing = []
    for dep in deps:
        # Dependency satisfied nếu:
        # 1. Phase đó nằm trong steps VÀ có kết quả
        # 2. HOẶC phase đó không cần (không nằm trong steps) — optional dep
        if dep in steps and dep not in results:
            missing.append(dep)
        elif dep in results and not results[dep]:
            missing.append(dep)
    return len(missing) == 0, missing


def print_banner(config):
    """Print startup banner."""
    banner_text = Text()
    banner_text.append("ReconRisk", style="bold cyan")
    banner_text.append(" — Modular Recon CLI\n", style="dim")
    banner_text.append(f"Target:  ", style="dim")
    banner_text.append(f"{config['domain']}\n", style="bold white")
    banner_text.append(f"Steps:   ", style="dim")
    banner_text.append(f"{' → '.join(config['steps'])}\n", style="green")
    banner_text.append(f"Depth:   ", style="dim")
    banner_text.append(f"{config['depth']}\n", style="yellow")
    if config["compare"]:
        banner_text.append(f"Delta:   ", style="dim")
        banner_text.append("enabled (compare with baseline)\n", style="magenta")

    console.print(Panel(banner_text, title="🔍 ReconRisk", border_style="cyan"))


def _interactive_select(prioritized):
    """
    Hiện bảng subdomain có score + tags, cho user chọn.
    Returns: filtered list.
    """
    if not prioritized:
        return prioritized

    console.print()
    console.print(Panel(
        "[bold]🎯 Interactive Mode — Select subdomains to scan[/bold]",
        border_style="cyan",
    ))

    table = Table(
        title="Discovered Subdomains",
        border_style="cyan",
        show_lines=False,
    )
    table.add_column("#", justify="right", width=4, style="dim")
    table.add_column("Score", justify="center", width=6)
    table.add_column("Subdomain", style="bold white", max_width=45)
    table.add_column("Tags", max_width=30)
    table.add_column("IPs", style="dim", max_width=20)

    for i, item in enumerate(prioritized):
        score = item.get("score", 0)
        tags = item.get("tags", [])

        # Score color
        if score >= 30:
            score_str = f"[bold red]★{score}[/bold red]"
        elif score >= 20:
            score_str = f"[yellow]★{score}[/yellow]"
        else:
            score_str = f"[dim]★{score}[/dim]"

        # Tags color
        tag_parts = []
        for t in tags:
            if t in ("high-value", "takeover!"):
                tag_parts.append(f"[red]{t}[/red]")
            elif t in ("non-prod", "infra"):
                tag_parts.append(f"[yellow]{t}[/yellow]")
            else:
                tag_parts.append(f"[dim]{t}[/dim]")
        tags_str = ", ".join(tag_parts) if tag_parts else "[dim]normal[/dim]"

        ips = ", ".join(item.get("ips", [])[:2])
        if len(item.get("ips", [])) > 2:
            ips += "..."

        table.add_row(str(i + 1), score_str, item["subdomain"], tags_str, ips)

    console.print(table)

    # Show category counts
    tag_counts = {}
    for item in prioritized:
        for t in item.get("tags", []):
            tag_counts[t] = tag_counts.get(t, 0) + 1
    if tag_counts:
        cats = "  ".join(f"[cyan]{t}[/cyan]({c})" for t, c in sorted(tag_counts.items(), key=lambda x: -x[1]))
        console.print(f"\n  Categories: {cats}")

    console.print()
    console.print("  [bold]Selection options:[/bold]")
    console.print("    [cyan]all[/cyan]           → Select all subdomains")
    console.print("    [cyan]1-5,8,12[/cyan]     → Select by number (ranges supported)")
    console.print("    [cyan]high-value[/cyan]   → Select by tag name")
    console.print("    [cyan]top 10[/cyan]       → Select top N by score")
    console.print()

    selection = Prompt.ask("  [bold cyan]Select subdomains[/bold cyan]", default="all")
    selection = selection.strip().lower()

    if selection == "all":
        console.print(f"  [green]✓ Selected all {len(prioritized)} subdomains[/green]")
        return prioritized

    # "top N"
    if selection.startswith("top"):
        try:
            n = int(selection.replace("top", "").strip())
            selected = prioritized[:n]
            console.print(f"  [green]✓ Selected top {len(selected)} subdomains[/green]")
            return selected
        except ValueError:
            pass

    # Tag-based selection
    if selection in tag_counts:
        selected = [s for s in prioritized if selection in s.get("tags", [])]
        console.print(f"  [green]✓ Selected {len(selected)} subdomains with tag '{selection}'[/green]")
        return selected

    # Number-based: "1-5,8,12"
    try:
        indices = set()
        for part in selection.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                for i in range(int(start), int(end) + 1):
                    indices.add(i - 1)  # 1-indexed → 0-indexed
            else:
                indices.add(int(part) - 1)

        selected = [
            prioritized[i] for i in sorted(indices)
            if 0 <= i < len(prioritized)
        ]
        if selected:
            names = ", ".join(s["subdomain"] for s in selected[:5])
            extra = f" +{len(selected)-5}" if len(selected) > 5 else ""
            console.print(f"  [green]✓ Selected {len(selected)}: {names}{extra}[/green]")
            return selected
    except (ValueError, IndexError):
        pass

    console.print("  [yellow]⚠ Invalid selection, using all subdomains[/yellow]")
    return prioritized


def _interactive_select_hosts(probes):
    """
    Pause 2: Show alive hosts, let user select which to scan further.
    """
    if not probes:
        return probes

    console.print()
    console.print(Panel(
        f"[bold]🌐 Interactive Mode — Select alive hosts ({len(probes)} found)[/bold]",
        border_style="green",
    ))

    table = Table(border_style="green", show_lines=False)
    table.add_column("#", justify="right", width=4, style="dim")
    table.add_column("Status", justify="center", width=7)
    table.add_column("Host", style="bold white", max_width=40)
    table.add_column("Title", max_width=35)
    table.add_column("Server", style="dim", max_width=20)
    table.add_column("TLS", justify="center", width=4)

    for i, p in enumerate(probes):
        status = p.get("status", 0)
        if 200 <= status < 300:
            s_str = f"[green]{status}[/green]"
        elif 300 <= status < 400:
            s_str = f"[yellow]{status}[/yellow]"
        elif status == 403:
            s_str = f"[red]{status}[/red]"
        elif status >= 500:
            s_str = f"[dim]{status}[/dim]"
        else:
            s_str = str(status)

        tls = "🔒" if p.get("tls", {}).get("enabled") else "⚠️"
        title = (p.get("title", "") or "")[:35]

        table.add_row(
            str(i + 1), s_str, p.get("host", ""),
            title, p.get("server", ""), tls,
        )

    console.print(table)

    # Status summary
    status_counts = {}
    for p in probes:
        s = p.get("status", 0)
        bucket = f"{s // 100}xx"
        status_counts[bucket] = status_counts.get(bucket, 0) + 1
    summary = "  ".join(f"[cyan]{k}[/cyan]({v})" for k, v in sorted(status_counts.items()))
    console.print(f"\n  Status: {summary}")

    console.print()
    console.print("  [bold]Options:[/bold]  [cyan]all[/cyan] | [cyan]1-5,8[/cyan] | [cyan]top 10[/cyan]")
    console.print()

    selection = Prompt.ask("  [bold green]Select hosts[/bold green]", default="all")
    return _apply_selection(probes, selection, lambda p: p.get("host", ""))


def _interactive_select_ports(port_data, probes):
    """
    Pause 3: Show hosts with open ports, let user select.
    """
    if not port_data:
        return port_data, probes

    # Build display list
    hosts_with_ports = []
    for hostname, data in port_data.items():
        ports = data.get("ports", [])
        if ports:
            hosts_with_ports.append({
                "host": hostname,
                "ip": data.get("ip", hostname),
                "os": data.get("os", ""),
                "ports": ports,
            })

    if not hosts_with_ports:
        return port_data, probes

    console.print()
    console.print(Panel(
        f"[bold]🔍 Interactive Mode — Select hosts by ports/services ({len(hosts_with_ports)} found)[/bold]",
        border_style="yellow",
    ))

    table = Table(border_style="yellow", show_lines=False)
    table.add_column("#", justify="right", width=4, style="dim")
    table.add_column("Host", style="bold white", max_width=30)
    table.add_column("IP", style="dim", width=16)
    table.add_column("Open Ports", max_width=40)
    table.add_column("OS", style="dim", max_width=20)

    for i, h in enumerate(hosts_with_ports):
        ports_str = ", ".join(
            f"{p.get('port')}/{p.get('service', '?')}" for p in h["ports"][:6]
        )
        if len(h["ports"]) > 6:
            ports_str += f" +{len(h['ports'])-6}"

        table.add_row(
            str(i + 1), h["host"], h["ip"],
            ports_str, h.get("os", "")[:20],
        )

    console.print(table)
    console.print()
    console.print("  [bold]Options:[/bold]  [cyan]all[/cyan] | [cyan]1-3,5[/cyan] | [cyan]top 5[/cyan]")
    console.print()

    selection = Prompt.ask("  [bold yellow]Select hosts[/bold yellow]", default="all")
    selection = selection.strip().lower()

    if selection == "all":
        console.print(f"  [green]✓ Selected all {len(hosts_with_ports)} hosts[/green]")
        return port_data, probes

    # Parse selection
    selected_indices = _parse_number_selection(selection, len(hosts_with_ports))
    if selected_indices is None:
        # Try "top N"
        if selection.startswith("top"):
            try:
                n = int(selection.replace("top", "").strip())
                selected_indices = list(range(min(n, len(hosts_with_ports))))
            except ValueError:
                pass

    if not selected_indices:
        console.print("  [yellow]⚠ Invalid selection, using all[/yellow]")
        return port_data, probes

    selected_hosts = {hosts_with_ports[i]["host"] for i in selected_indices}
    filtered_port = {k: v for k, v in port_data.items() if k in selected_hosts}
    filtered_probes = [p for p in probes if p.get("host") in selected_hosts]

    names = ", ".join(list(selected_hosts)[:3])
    console.print(f"  [green]✓ Selected {len(selected_hosts)} hosts: {names}[/green]")

    return filtered_port, filtered_probes


def _parse_number_selection(selection, total):
    """Parse '1-5,8,12' style selection. Returns list of 0-indexed indices or None."""
    try:
        indices = []
        for part in selection.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                for i in range(int(start) - 1, int(end)):
                    if 0 <= i < total:
                        indices.append(i)
            else:
                idx = int(part) - 1
                if 0 <= idx < total:
                    indices.append(idx)
        return indices if indices else None
    except (ValueError, IndexError):
        return None


def _apply_selection(items, selection, name_fn):
    """Generic selection: all, top N, or number ranges."""
    selection = selection.strip().lower()

    if selection == "all":
        console.print(f"  [green]✓ Selected all {len(items)}[/green]")
        return items

    if selection.startswith("top"):
        try:
            n = int(selection.replace("top", "").strip())
            selected = items[:n]
            console.print(f"  [green]✓ Selected top {len(selected)}[/green]")
            return selected
        except ValueError:
            pass

    indices = _parse_number_selection(selection, len(items))
    if indices:
        selected = [items[i] for i in indices]
        names = ", ".join(name_fn(s) for s in selected[:3])
        extra = f" +{len(selected)-3}" if len(selected) > 3 else ""
        console.print(f"  [green]✓ Selected {len(selected)}: {names}{extra}[/green]")
        return selected

    console.print("  [yellow]⚠ Invalid selection, using all[/yellow]")
    return items


def run_pipeline(config):
    """Pipeline chính — chạy từng phase theo thứ tự."""
    results = {}
    start_time = time.time()

    # Tạo output dir
    os.makedirs(config["output_dir"], exist_ok=True)

    for phase in config["steps"]:
        # Skip report ở đây — chạy cuối cùng
        if phase == "report":
            continue

        # Check dependencies — soft deps: warn but still try to run
        can_run, missing = check_phase_deps(phase, config["steps"], results)
        if not can_run:
            console.print(
                f"  [dim]⚠ deps incomplete: {', '.join(missing)} "
                f"— running anyway with available data[/dim]"
            )

        # Run phase
        console.print(f"\n[cyan]{'═' * 50}[/cyan]")
        console.print(f"[bold cyan]▶ Phase: {phase}[/bold cyan]  [dim]depth={config['depth']}[/dim]")
        console.print(f"[cyan]{'═' * 50}[/cyan]")

        phase_start = time.time()
        runner = PHASE_RUNNERS.get(phase)
        if not runner:
            console.print(f"  [red]✗ No runner for phase: {phase}[/red]")
            continue

        try:
            result = runner(config, results)
            results[phase] = result
            elapsed = time.time() - phase_start
            count = len(result) if isinstance(result, (list, dict)) else 0
            console.print(
                f"  [green]✓ {phase}[/green] completed — "
                f"[dim]{count} items, {elapsed:.1f}s[/dim]"
            )

            # Interactive pauses
            if config.get("interactive") and result:
                if phase == "prioritize":
                    result = _interactive_select(result)
                    results["prioritize"] = result
                elif phase == "probe":
                    result = _interactive_select_hosts(result)
                    results["probe"] = result
                elif phase == "port":
                    probes = results.get("probe", [])
                    result, probes = _interactive_select_ports(result, probes)
                    results["port"] = result
                    results["probe"] = probes

        except Exception as e:
            console.print(f"  [red]✗ {phase} failed: {e}[/red]")
            results[phase] = None

    # Chạy report cuối cùng
    if "report" in config["steps"]:
        console.print(f"\n[cyan]{'═' * 50}[/cyan]")
        console.print("[bold cyan]▶ Phase: report[/bold cyan]")
        console.print(f"[cyan]{'═' * 50}[/cyan]")
        try:
            run_report(config, results)
        except Exception as e:
            console.print(f"  [red]✗ report failed: {e}[/red]")

    total_time = time.time() - start_time
    console.print(f"\n[bold green]✓ Pipeline finished in {total_time:.1f}s[/bold green]")

    return results


def main():
    args = parse_args()
    config, error = validate_args(args)

    if error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        sys.exit(1)

    print_banner(config)
    results = run_pipeline(config)


if __name__ == "__main__":
    main()
