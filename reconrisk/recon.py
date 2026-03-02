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
            # Đếm items trong result
            count = len(result) if isinstance(result, (list, dict)) else 0
            console.print(
                f"  [green]✓ {phase}[/green] completed — "
                f"[dim]{count} items, {elapsed:.1f}s[/dim]"
            )
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
