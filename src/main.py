#!/usr/bin/env python3
"""
main.py — CLI Entry Point for the Network Scanner + Packet Analyzer.

Provides subcommands:
    lab       Start the local lab environment only
    scan      Run Nmap port scan only
    capture   Run packet capture only
    analyze   Analyze an existing capture file
    full      Execute the complete autopilot workflow

Usage:
    python3 src/main.py --help
    python3 src/main.py full
    python3 src/main.py scan
    python3 src/main.py full --authorized-target 192.168.1.50
"""

import argparse
import sys
import time
from typing import Any

# Ensure project root is on the path so src.* imports work
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils import (
    check_all_dependencies,
    load_config,
    print_banner,
    print_error,
    print_footer,
    print_info,
    print_ok,
    print_section,
    print_table,
    print_warn,
    setup_logging,
    validate_target,
)
from src.lab_server import LabEnvironment
from src.network_info import get_all_network_info
from src.port_scanner import run_nmap_scan, format_scan_results
from src.process_mapper import map_ports_to_processes, format_process_mappings
from src.packet_capture import PacketCapture
from src.traffic_generator import generate_all_traffic
from src.packet_analyzer import analyze_capture, format_analysis_summary
from src.suspicious_ports import classify_ports, get_detection_summary, format_classifications
from src.report_generator import generate_report, save_report, print_report_summary


# ---------------------------------------------------------------------------
# Total steps in the full workflow
# ---------------------------------------------------------------------------
TOTAL_STEPS = 9


def cmd_full(args: argparse.Namespace) -> None:
    """Execute the complete autopilot lab workflow."""
    logger = setup_logging()
    config = load_config()

    target = config.get("target", "127.0.0.1")
    authorized = getattr(args, "authorized_target", None)
    if authorized:
        target = authorized

    target = validate_target(target, authorized=bool(authorized))

    http_port: int = config["lab_ports"]["http_port"]
    tcp_port: int = config["lab_ports"]["tcp_port"]
    scan_args: str = config.get("scan_arguments", "-sT -sV")
    capture_duration: int = config.get("capture_duration", 15)
    capture_iface: str = config.get("capture_interface", "lo")
    detection_rules = config.get("detection_rules", {})

    # Collect errors throughout the run
    all_errors: list[str] = []

    # Lab environment — ensure cleanup on exit
    lab = LabEnvironment(http_port=http_port, tcp_port=tcp_port)
    capture = PacketCapture(
        interface=capture_iface,
        duration=capture_duration,
        lab_ports=[http_port, tcp_port],
    )

    try:
        print_banner()

        # ---- Step 1: Check Dependencies ----
        print_section(1, TOTAL_STEPS, "Checking dependencies")
        if not check_all_dependencies():
            print_error("Missing dependencies. Please install them and retry.")
            sys.exit(1)

        # ---- Step 2: Start Local Lab ----
        print_section(2, TOTAL_STEPS, "Starting local lab")
        lab_results = lab.start()
        if "http" in lab_results:
            print_ok("HTTP server", lab_results["http"])
        else:
            msg = lab_results.get("http_error", "Failed to start HTTP server")
            print_error(msg)
            all_errors.append(msg)

        if "tcp" in lab_results:
            print_ok("TCP listener", lab_results["tcp"])
        else:
            msg = lab_results.get("tcp_error", "Failed to start TCP listener")
            print_error(msg)
            all_errors.append(msg)

        # ---- Step 3: Detect Network Info ----
        print_section(3, TOTAL_STEPS, "Detecting network information")
        net_info = get_all_network_info()
        print_ok("Hostname", net_info.get("hostname", "N/A"))
        print_ok("Local IP", net_info.get("local_ip", "N/A"))
        print_ok("Loopback", net_info.get("loopback", "127.0.0.1"))
        iface = net_info.get("interface")
        if iface:
            print_ok("Interface", iface)
        gateway = net_info.get("default_gateway")
        if gateway:
            print_ok("Gateway", gateway)

        # ---- Step 4: Run Nmap ----
        print_section(4, TOTAL_STEPS, "Running Nmap port scan")
        print_info(f"Target: {target}")
        print_info(f"Arguments: {scan_args}")

        scan_results = run_nmap_scan(
            target=target,
            scan_args=scan_args,
            ports=[http_port, tcp_port],
            authorized=bool(authorized),
        )

        if scan_results["errors"]:
            for err in scan_results["errors"]:
                print_warn(err)
                all_errors.append(err)

        open_ports = [p for p in scan_results.get("ports", []) if p.get("state") == "open"]
        print_ok(f"Scan complete — {len(open_ports)} open port(s) found")

        if open_ports:
            print()
            print_table(
                ["PORT", "STATE", "SERVICE", "VERSION"],
                format_scan_results({"ports": open_ports}),
            )

        # ---- Step 5: Map Ports to Processes ----
        print_section(5, TOTAL_STEPS, "Mapping ports to processes")
        process_mappings = map_ports_to_processes(scan_results.get("ports", []))

        if process_mappings:
            print_table(
                ["PORT", "PROCESS", "PID"],
                format_process_mappings(process_mappings),
            )
        else:
            print_warn("No process mappings found (may need root privileges)")

        # ---- Step 6: Capture Packets ----
        print_section(6, TOTAL_STEPS, "Capturing packets")
        capture_started = capture.start()

        if capture_started:
            print_ok("Capture started", f"{capture_iface} for {capture_duration}s")

            # Generate traffic while capture is running
            print_ok("Generating test traffic")
            traffic_results = generate_all_traffic(
                host=target,
                http_port=http_port,
                tcp_port=tcp_port,
            )
            print_ok(
                "Traffic sent",
                f"{traffic_results['total_success']} success, "
                f"{traffic_results['total_errors']} errors",
            )

            # Wait for capture to finish
            print_info("Waiting for capture to complete...")
            capture.wait()
            print_ok("Capture complete", capture.output_file)
        else:
            print_error("Failed to start packet capture")
            print_info(
                "Tshark may require root or 'wireshark' group membership. "
                "Try: sudo usermod -aG wireshark $USER"
            )
            all_errors.append("Packet capture failed to start")
            traffic_results = {"total_success": 0, "total_errors": 0, "http": {}, "tcp": {}}

        # ---- Step 7: Analyze Packets ----
        print_section(7, TOTAL_STEPS, "Analyzing packets")
        capture_info = capture.get_capture_info()

        if capture_info.get("file_exists"):
            analysis = analyze_capture(capture.output_file)
            total_pkts = analysis.get("total_packets", 0)
            print_ok("Packets analyzed", str(total_pkts))

            if total_pkts > 0:
                print()
                print(format_analysis_summary(analysis))
        else:
            print_warn("No capture file to analyze")
            analysis = {"total_packets": 0}

        # ---- Step 8: Check Suspicious Ports ----
        print_section(8, TOTAL_STEPS, "Checking suspicious ports")

        classifications = classify_ports(
            discovered_ports=scan_results.get("ports", []),
            expected_ports=detection_rules.get("expected_ports", []),
            review_ports=detection_rules.get("review_ports", []),
            severity_map=detection_rules.get("severity", {}),
            descriptions=detection_rules.get("descriptions", {}),
        )

        det_summary = get_detection_summary(classifications)

        review_count = det_summary["counts"].get("REVIEW", 0)
        if review_count > 0:
            print_warn(f"{review_count} port(s) flagged for review")
        else:
            print_ok("No unexpected high-risk ports detected")

        if classifications:
            print()
            print_table(
                ["PORT", "SERVICE", "CLASS", "SEVERITY", "REASON"],
                format_classifications(classifications),
            )

        print()
        print_info(det_summary["disclaimer"])

        # ---- Step 9: Generate Report ----
        print_section(9, TOTAL_STEPS, "Generating report")

        report = generate_report(
            network_info=net_info,
            scan_results=scan_results,
            process_mappings=process_mappings,
            packet_analysis=analysis,
            classifications=classifications,
            detection_summary=det_summary,
            lab_services=lab.get_services_info(),
            capture_info=capture_info,
            traffic_results=traffic_results,
            target=target,
            errors=all_errors,
        )

        report_path = save_report(report)
        if report_path:
            print_ok("Report saved", report_path)
            print_ok("Latest report", "reports/network_scan_report.json")
        else:
            print_error("Failed to save report")

        print_report_summary(report)
        print_footer(success=not all_errors)

    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted by user (Ctrl+C)")
        print_footer(success=False)

    finally:
        # Always clean up
        print_info("Cleaning up lab services...")
        lab.stop()
        capture.stop()
        print_ok("Cleanup complete")


# ---------------------------------------------------------------------------
# Individual subcommands
# ---------------------------------------------------------------------------

def cmd_lab(args: argparse.Namespace) -> None:
    """Start the lab environment and keep it running until Ctrl+C."""
    setup_logging()
    config = load_config()

    http_port = config["lab_ports"]["http_port"]
    tcp_port = config["lab_ports"]["tcp_port"]

    print_banner()
    print_section(1, 1, "Starting local lab")

    lab = LabEnvironment(http_port=http_port, tcp_port=tcp_port)
    try:
        results = lab.start()
        for key, val in results.items():
            if "error" in key:
                print_error(val)
            else:
                print_ok(key.upper(), val)

        print_info("Lab is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [!] Stopping lab...")
    finally:
        lab.stop()
        print_ok("Lab stopped")


def cmd_scan(args: argparse.Namespace) -> None:
    """Run an Nmap scan only."""
    setup_logging()
    config = load_config()

    target = config.get("target", "127.0.0.1")
    authorized = getattr(args, "authorized_target", None)
    if authorized:
        target = authorized
    target = validate_target(target, authorized=bool(authorized))

    scan_args = config.get("scan_arguments", "-sT -sV")

    print_banner()
    print_section(1, 2, "Running Nmap port scan")
    print_info(f"Target: {target}")

    scan_results = run_nmap_scan(
        target=target,
        scan_args=scan_args,
        authorized=bool(authorized),
    )

    for err in scan_results.get("errors", []):
        print_warn(err)

    open_ports = [p for p in scan_results.get("ports", []) if p.get("state") == "open"]
    print_ok(f"Found {len(open_ports)} open port(s)")

    if open_ports:
        print()
        print_table(
            ["PORT", "STATE", "SERVICE", "VERSION"],
            format_scan_results({"ports": open_ports}),
        )

    # Process mapping
    print_section(2, 2, "Mapping ports to processes")
    mappings = map_ports_to_processes(scan_results.get("ports", []))
    if mappings:
        print_table(
            ["PORT", "PROCESS", "PID"],
            format_process_mappings(mappings),
        )

    print_footer()


def cmd_capture(args: argparse.Namespace) -> None:
    """Run a packet capture only."""
    setup_logging()
    config = load_config()

    duration = config.get("capture_duration", 15)
    iface = config.get("capture_interface", "lo")
    lab_ports_cfg = config.get("lab_ports", {})
    ports = [lab_ports_cfg.get("http_port", 8080), lab_ports_cfg.get("tcp_port", 9090)]

    print_banner()
    print_section(1, 1, f"Capturing packets on {iface} for {duration}s")

    cap = PacketCapture(interface=iface, duration=duration, lab_ports=ports)
    try:
        if cap.start():
            print_ok("Capture started")
            cap.wait()
            print_ok("Capture complete", cap.output_file)
            info = cap.get_capture_info()
            print_ok("File size", f"{info.get('file_size_bytes', 0)} bytes")
        else:
            print_error("Failed to start capture")
    except KeyboardInterrupt:
        print("\n  [!] Stopping capture...")
        cap.stop()

    print_footer()


def cmd_analyze(args: argparse.Namespace) -> None:
    """Analyze an existing capture file."""
    setup_logging()

    capture_file = args.file
    if not Path(capture_file).exists():
        print_error(f"Capture file not found: {capture_file}")
        sys.exit(1)

    print_banner()
    print_section(1, 1, f"Analyzing {capture_file}")

    analysis = analyze_capture(capture_file)

    total = analysis.get("total_packets", 0)
    print_ok("Packets analyzed", str(total))

    if total > 0:
        print()
        print(format_analysis_summary(analysis))

    print_footer()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cli-network-scanner",
        description=(
            "CLI Network Scanner + Packet Analyzer — "
            "Educational cybersecurity lab for localhost analysis."
        ),
        epilog=(
            "This tool is designed for authorized local lab use only. "
            "Do not use it to scan systems you do not own or have explicit "
            "permission to test."
        ),
    )

    parser.add_argument(
        "--authorized-target",
        metavar="IP",
        help=(
            "Explicitly authorize scanning a private-network IP. "
            "Only use for lab machines you own."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available commands",
    )

    # full
    sub_full = subparsers.add_parser(
        "full",
        help="Execute the complete autopilot lab workflow",
    )
    sub_full.set_defaults(func=cmd_full)

    # lab
    sub_lab = subparsers.add_parser(
        "lab",
        help="Start the local lab environment (HTTP + TCP servers)",
    )
    sub_lab.set_defaults(func=cmd_lab)

    # scan
    sub_scan = subparsers.add_parser(
        "scan",
        help="Run Nmap port scan and process mapping",
    )
    sub_scan.set_defaults(func=cmd_scan)

    # capture
    sub_capture = subparsers.add_parser(
        "capture",
        help="Run tshark packet capture",
    )
    sub_capture.set_defaults(func=cmd_capture)

    # analyze
    sub_analyze = subparsers.add_parser(
        "analyze",
        help="Analyze an existing packet capture file",
    )
    sub_analyze.add_argument(
        "file",
        help="Path to the .pcapng capture file",
    )
    sub_analyze.set_defaults(func=cmd_analyze)

    return parser


def main() -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
