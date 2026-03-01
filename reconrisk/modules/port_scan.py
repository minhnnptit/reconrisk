"""
Phase 3 — Port Scan (nmap)

State Machine:
  CheckNmap → BuildCmd (fast/deep) → RunNmap → ParseXML → ExtractPorts/Services/OS → Return
  Missing nmap → WarnUser → ReturnEmpty
"""

import subprocess
import shutil
import xml.etree.ElementTree as ET

from rich.console import Console

console = Console()


def _check_tool(name):
    return shutil.which(name) is not None


def _build_nmap_cmd(targets, depth, timeout):
    """Build nmap command based on depth."""
    cmd = ["nmap"]

    if depth == "fast":
        cmd.extend(["-T4", "--top-ports", "100", "-sV"])
    else:  # deep
        cmd.extend(["-T4", "--top-ports", "1000", "-sV", "-O"])

    # XML output to stdout
    cmd.extend(["-oX", "-"])

    # Timeout
    cmd.extend(["--host-timeout", f"{timeout}s"])

    # Add targets
    cmd.extend(targets)

    return cmd


def _parse_nmap_xml(xml_output):
    """Parse nmap XML output into structured data."""
    results = {}

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        console.print(f"  [red]✗ Failed to parse nmap XML: {e}[/red]")
        return results

    for host_elem in root.findall(".//host"):
        # Status
        status = host_elem.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Address
        addr_elem = host_elem.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "unknown")

        # Hostname
        hostname = ip
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", ip)

        # Ports
        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_id = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "tcp")

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                if state != "open":
                    continue

                service_elem = port_elem.find("service")
                service_name = ""
                service_version = ""
                service_product = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    service_product = service_elem.get("product", "")
                    service_version = service_elem.get("version", "")

                ports.append({
                    "port": int(port_id) if port_id.isdigit() else port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                })

        # OS detection
        os_guess = ""
        os_elem = host_elem.find("os")
        if os_elem is not None:
            os_match = os_elem.find("osmatch")
            if os_match is not None:
                os_guess = os_match.get("name", "")

        results[hostname] = {
            "ip": ip,
            "hostname": hostname,
            "ports": ports,
            "os_guess": os_guess,
        }

    return results


def run_port_scan(config, results):
    """
    Main entry point cho Phase 3.
    Input: subdomains từ Phase 1
    Returns: dict {hostname: {ip, ports, os_guess}}
    """
    timeout = config["timeout"]
    depth = config["depth"]

    # Lấy targets
    subdomains = results.get("subdomain", [])
    if not subdomains:
        console.print("  [yellow]⚠ No targets for port scan[/yellow]")
        return {}

    # Check nmap
    if not _check_tool("nmap"):
        console.print("  [red]✗ nmap not found in PATH — skipping port scan[/red]")
        console.print("  [dim]Install: sudo apt-get install nmap[/dim]")
        return {}

    # Giới hạn số target cho prototype
    targets = subdomains[:50]  # Max 50 hosts
    if len(subdomains) > 50:
        console.print(f"  [yellow]⚠ Limiting to 50 targets (total: {len(subdomains)})[/yellow]")

    cmd = _build_nmap_cmd(targets, depth, timeout)
    console.print(f"  [dim]Running: {' '.join(cmd[:6])}... ({len(targets)} targets)[/dim]")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * 2,  # nmap có thể chạy lâu
        )

        if result.returncode != 0 and not result.stdout:
            console.print(f"  [red]✗ nmap error: {result.stderr.strip()[:200]}[/red]")
            return {}

        port_data = _parse_nmap_xml(result.stdout)

        # Summary
        total_ports = sum(len(h.get("ports", [])) for h in port_data.values())
        console.print(
            f"  [green]✓ Scanned {len(port_data)} hosts, "
            f"found {total_ports} open ports[/green]"
        )

        # Print summary per host
        for hostname, data in port_data.items():
            ports_str = ", ".join(
                f"{p['port']}/{p['service']}" for p in data["ports"][:5]
            )
            if len(data["ports"]) > 5:
                ports_str += f" +{len(data['ports'])-5} more"
            console.print(f"    [dim]{hostname}: {ports_str}[/dim]")

        return port_data

    except subprocess.TimeoutExpired:
        console.print(f"  [red]✗ nmap timed out after {timeout*2}s[/red]")
        return {}
    except FileNotFoundError:
        console.print("  [red]✗ nmap not found[/red]")
        return {}
