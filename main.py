#!/usr/bin/env python3
"""PortSentinel - Automated Network Reconnaissance & Open-Port Analysis Tool.

Phase 1 implementation for authorized systems and controlled lab environments.
"""

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from models.scan_result import HostResult, PortInfo
from reports.report_generator import ReportGenerator
from scanner.discovery import HostDiscovery
from scanner.nmap_manager import (
    NmapManager,
    NmapNotFoundError,
    NmapExecutionError,
    NmapTimeoutError,
)
from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from utils.logger import setup_logger, get_logger
from utils.validator import validate_target


BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║                       PORTSENTINEL v1.0                          ║
║           Automated Port & Service Reconnaissance Engine         ║
║          [ For Authorized Systems & Controlled Lab Tests ]       ║
╚══════════════════════════════════════════════════════════════════╝
"""


def print_banner() -> None:
    """Print the application banner."""
    print(BANNER)


def print_exposure_summary(result: HostResult, txt_file: Path, json_file: Path) -> None:
    """Print a clean exposure summary to the terminal.

    Args:
        result: HostResult containing scan findings.
        txt_file: Path to generated text report.
        json_file: Path to generated JSON report.
    """
    print("\n" + "═" * 60)
    print(f"{'EXPOSURE SUMMARY':^60}")
    print("═" * 60)
    print(f"Target          : {result.target}")
    print(f"Resolved IP     : {result.resolved_ip}")
    print(f"Host Status     : {result.host_status.upper()}")
    print(f"Scan Duration   : {round(result.scan_duration, 2)}s")
    print(f"Open TCP Ports  : {result.total_open_ports}")
    print("-" * 60)

    if result.open_ports:
        print(f"{'Port/Proto':<16}{'Service':<18}{'Category'}")
        print("-" * 60)
        for p in result.open_ports:
            port_proto = f"{p.port}/{p.protocol}"
            svc_name = p.service.upper() if p.service != "unknown" else "Unknown"
            print(f"{port_proto:<16}{svc_name:<18}{p.category}")
    else:
        print("No open TCP ports detected.")

    print("-" * 60)
    print("Service Groups")
    print("-" * 60)
    groups = result.service_groups
    if groups:
        for group, count in sorted(groups.items()):
            print(f"{group:<24}: {count}")
    else:
        print("None")

    print("═" * 60)
    print("Reports Generated:")
    print(f"  [Text Report] -> {txt_file}")
    print(f"  [JSON Report] -> {json_file}")
    print("═" * 60)
    print("\nScan completed successfully.\n")


def run_orchestrator(
    target_input: str,
    output_dir: str = "output",
    port_range: Optional[str] = None,
    timeout: int = 300,
    verbose: bool = False,
) -> int:
    """Orchestrate the end-to-end PortSentinel reconnaissance pipeline.

    Workflow:
      Target -> Validation -> Host Discovery -> Port Scan -> Service Detection -> Reporting

    Args:
        target_input: User provided hostname or IP.
        output_dir: Destination directory for reports.
        port_range: Optional custom port range (e.g., '1-1000').
        timeout: Maximum seconds per scan phase.
        verbose: If True, log verbose output.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    logger = setup_logger(verbose=verbose)
    report_gen = ReportGenerator(output_dir=output_dir)
    nmap_mgr = NmapManager()

    start_time = time.time()
    iso_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.info(f"--- PortSentinel Reconnaissance Started for target: {target_input} ---")

    # Step 1: Target Validation
    print(f"\n[1/5] Target validation", end="", flush=True)
    val_result = validate_target(target_input)

    if not val_result.is_valid:
        print("       ✗")
        print(f"\nError: {val_result.error_message}\n")
        logger.error(f"Target validation failed: {val_result.error_message}")
        return 1

    print("       ✓")
    print(f"      Target:      {val_result.target}")
    print(f"      Resolved IP: {val_result.resolved_ip}")
    logger.info(f"Target validated: {val_result.target} -> {val_result.resolved_ip}")

    # Step 2: Nmap Dependency Check
    print(f"\n[2/5] Nmap availability", end="", flush=True)
    if not nmap_mgr.is_available():
        print("       ✗")
        print("\nError: Nmap is required to run PortSentinel.")
        print("Please install Nmap and ensure it is available in PATH.\n")
        logger.error("Nmap binary not found on system.")
        return 1

    has_ver, ver_str = nmap_mgr.get_version()
    if not has_ver:
        print("       ✗")
        print(f"\nError: Unable to verify Nmap installation: {ver_str}\n")
        return 1

    print("       ✓")
    print(f"      Nmap Engine: {ver_str}")
    logger.info(f"Nmap detected version: {ver_str}")

    # Step 3: Host Discovery
    print(f"\n[3/5] Host discovery", end="", flush=True)
    discovery = HostDiscovery(nmap_mgr)
    try:
        is_up, disc_result = discovery.discover(
            target=val_result.target,
            resolved_ip=val_result.resolved_ip,
            timeout=min(timeout, 60),
        )
    except NmapTimeoutError:
        print("          ✗")
        print("\nError: Host discovery scan timed out.")
        return 1
    except NmapExecutionError as exc:
        print("          ✗")
        print(f"\nError during host discovery: {exc}")
        return 1

    if not is_up:
        print("          ✗")
        print(f"\nStatus: HOST UNREACHABLE ({val_result.resolved_ip})")
        print("Scan stopped. Target could not be reached.\n")
        logger.warning(f"Host unreachable: {val_result.resolved_ip}")
        return 0

    print("          ✓")
    print(f"      Status: UP ✓")
    logger.info(f"Host is UP: {val_result.resolved_ip}")

    # Step 4: Port Discovery
    print(f"\n[4/5] Discovering TCP ports", end="", flush=True)
    port_scanner = PortScanner(nmap_mgr)
    try:
        discovered_ports = port_scanner.scan_ports(
            target=val_result.target,
            resolved_ip=val_result.resolved_ip,
            port_range=port_range,
            timeout=timeout,
        )
    except NmapTimeoutError:
        print("   ✗")
        print("\nError: TCP port scan timed out.")
        return 1
    except NmapExecutionError as exc:
        print("   ✗")
        print(f"\nError during port scan: {exc}")
        return 1

    print("   ✓")
    open_ports_list = [p for p in discovered_ports if p.state.lower() == "open"]

    if not open_ports_list:
        print("\nNo open TCP ports detected.")
        duration = time.time() - start_time
        final_result = HostResult(
            target=val_result.target,
            resolved_ip=val_result.resolved_ip,
            host_status="up",
            scan_duration=duration,
            start_time=iso_start,
            end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            nmap_version=ver_str,
            ports=[],
        )
        txt_path, json_path = report_gen.save_reports(final_result)
        print_exposure_summary(final_result, txt_path, json_path)
        return 0

    print(f"      Open ports found ({len(open_ports_list)}):")
    for p in open_ports_list:
        print(f"        • {p.port}/{p.protocol}")

    # Step 5: Service & Version Detection
    print(f"\n[5/5] Detecting services", end="", flush=True)
    service_detector = ServiceDetector(nmap_mgr)
    open_port_nums = [p.port for p in open_ports_list]

    try:
        enriched_ports = service_detector.detect_services(
            target=val_result.target,
            resolved_ip=val_result.resolved_ip,
            open_ports=open_port_nums,
            timeout=timeout,
        )
    except NmapTimeoutError:
        print("      ✗")
        print("\nWarning: Service detection timed out. Using basic port discovery data.")
        enriched_ports = open_ports_list
    except NmapExecutionError as exc:
        print("      ✗")
        print(f"\nWarning: Service detection error ({exc}). Using basic port discovery data.")
        enriched_ports = open_ports_list

    print("      ✓")
    if enriched_ports:
        print("      Identified Services:")
        for p in enriched_ports:
            if p.state.lower() == "open":
                prod_ver = []
                if p.product and p.product != "Not detected":
                    prod_ver.append(p.product)
                if p.version and p.version != "Not detected":
                    prod_ver.append(p.version)
                detail = f" ({' '.join(prod_ver)})" if prod_ver else ""
                print(f"        • {p.port}/{p.protocol:<4} -> {p.service.upper()}{detail}")

    # Step 6: Generate Reports & Exposure Summary
    duration = time.time() - start_time
    final_result = HostResult(
        target=val_result.target,
        resolved_ip=val_result.resolved_ip,
        host_status="up",
        scan_duration=duration,
        start_time=iso_start,
        end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        nmap_version=ver_str,
        ports=enriched_ports or open_ports_list,
    )

    txt_path, json_path = report_gen.save_reports(final_result)
    print_exposure_summary(final_result, txt_path, json_path)
    return 0


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="PortSentinel",
        description="PortSentinel - Automated Network Reconnaissance & Open-Port Analysis Tool (Phase 1)",
        epilog="Notice: Only scan targets that you own or are explicitly authorized to test.",
    )
    parser.add_argument(
        "-t", "--target",
        dest="target",
        type=str,
        help="Target IP address or hostname (e.g. 192.168.1.10, localhost)",
    )
    parser.add_argument(
        "-p", "--ports",
        dest="ports",
        type=str,
        default=None,
        help="Custom TCP port range to scan (e.g. 1-1024, 22,80,443). Defaults to top 1000 ports.",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        type=str,
        default="output",
        help="Output directory for generated text and JSON reports (default: 'output')",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=300,
        help="Timeout in seconds for scan operations (default: 300)",
    )
    parser.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose debug logging to logs/portsentinel.log",
    )
    return parser.parse_args()


def main() -> None:
    """Main CLI entrypoint supporting both interactive mode and command line flags."""
    print_banner()
    args = parse_arguments()

    target = args.target
    if not target:
        try:
            print("Enter target IP/hostname:")
            target = input("> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled by user.")
            sys.exit(0)

    try:
        exit_code = run_orchestrator(
            target_input=target,
            output_dir=args.output,
            port_range=args.ports,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nScan aborted by user.")
        sys.exit(130)
    except Exception as exc:
        print(f"\nUnexpected error during reconnaissance: {exc}")
        get_logger().exception("Fatal unexpected error in main execution:")
        sys.exit(1)


if __name__ == "__main__":
    main()
