#!/usr/bin/env python3
"""
port_scanner.py — Nmap Port Scanner Wrapper.

Runs Nmap against an authorized target, parses XML output, and returns
structured scan results.

Security:
    - Target is validated before scanning
    - Only TCP connect scans (-sT) are used by default
    - No stealth, exploit, or aggressive scanning features
"""

import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

from src.utils import get_reports_dir, is_safe_target, print_error, print_info

logger = logging.getLogger("cli_network_scanner.port_scanner")


def run_nmap_scan(
    target: str,
    scan_args: str = "-sT -sV",
    ports: Optional[list[int]] = None,
    timeout: int = 120,
    authorized: bool = False,
) -> dict[str, Any]:
    """Execute an Nmap scan and return parsed results.

    Args:
        target: Target IP address (must pass safety validation).
        scan_args: Nmap command-line arguments.
        ports: Optional list of specific ports to scan.
        timeout: Subprocess timeout in seconds.
        authorized: Allow private-network targets.

    Returns:
        Dictionary with 'ports', 'raw_xml_path', 'scan_info', and 'errors'.
    """
    result: dict[str, Any] = {
        "ports": [],
        "raw_xml_path": None,
        "scan_info": {},
        "errors": [],
    }

    # Security check
    if not is_safe_target(target, allow_private=authorized):
        msg = f"Target '{target}' is not authorized for scanning."
        logger.error(msg)
        result["errors"].append(msg)
        return result

    # Build command
    xml_output = get_reports_dir() / "nmap_raw.xml"
    cmd = ["nmap"]
    cmd.extend(scan_args.split())

    if ports:
        port_str = ",".join(str(p) for p in ports)
        cmd.extend(["-p", port_str])

    cmd.extend(["-oX", str(xml_output), target])

    logger.info("Running Nmap: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            logger.warning("Nmap exited with code %d: %s", proc.returncode, stderr)

            # Common issue: version detection needs root
            if "requires root" in stderr.lower() or "permission" in stderr.lower():
                result["errors"].append(
                    "Some Nmap features require root privileges. "
                    "Retrying with basic scan flags."
                )
                # Retry without -sV
                fallback_args = scan_args.replace("-sV", "").strip()
                if fallback_args != scan_args:
                    return run_nmap_scan(
                        target=target,
                        scan_args=fallback_args,
                        ports=ports,
                        timeout=timeout,
                        authorized=authorized,
                    )
            else:
                result["errors"].append(f"Nmap error: {stderr}")

        result["raw_xml_path"] = str(xml_output)
        result.update(_parse_nmap_xml(xml_output))

    except FileNotFoundError:
        msg = "Nmap is not installed or not found on PATH."
        logger.error(msg)
        result["errors"].append(msg)
    except subprocess.TimeoutExpired:
        msg = f"Nmap scan timed out after {timeout} seconds."
        logger.error(msg)
        result["errors"].append(msg)
    except Exception as exc:
        msg = f"Unexpected error during Nmap scan: {exc}"
        logger.exception(msg)
        result["errors"].append(msg)

    return result


def _parse_nmap_xml(xml_path: Path) -> dict[str, Any]:
    """Parse Nmap XML output into structured data.

    Args:
        xml_path: Path to the Nmap XML output file.

    Returns:
        Dictionary with 'ports' and 'scan_info'.
    """
    parsed: dict[str, Any] = {"ports": [], "scan_info": {}}

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError) as exc:
        logger.error("Failed to parse Nmap XML: %s", exc)
        return parsed

    # Scan metadata
    parsed["scan_info"] = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start_time": root.get("startstr", ""),
    }

    # Parse hosts → ports
    for host in root.findall(".//host"):
        host_addr = ""
        addr_elem = host.find("address")
        if addr_elem is not None:
            host_addr = addr_elem.get("addr", "")

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            port_info = _parse_port_element(port_elem, host_addr)
            if port_info:
                parsed["ports"].append(port_info)

    logger.info("Parsed %d ports from Nmap XML", len(parsed["ports"]))
    return parsed


def _parse_port_element(
    port_elem: ET.Element, host_addr: str
) -> Optional[dict[str, Any]]:
    """Parse a single <port> element from Nmap XML.

    Args:
        port_elem: The XML <port> element.
        host_addr: The host address this port belongs to.

    Returns:
        Structured port information dictionary, or None on parse failure.
    """
    try:
        port_id = int(port_elem.get("portid", "0"))
        protocol = port_elem.get("protocol", "tcp")

        state_elem = port_elem.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

        service_elem = port_elem.find("service")
        service_name = ""
        service_version = ""
        if service_elem is not None:
            service_name = service_elem.get("name", "")
            product = service_elem.get("product", "")
            version = service_elem.get("version", "")
            service_version = f"{product} {version}".strip()

        return {
            "port": port_id,
            "protocol": protocol,
            "state": state,
            "service": service_name,
            "version": service_version,
            "host": host_addr,
        }
    except (ValueError, AttributeError) as exc:
        logger.warning("Failed to parse port element: %s", exc)
        return None


def format_scan_results(scan_data: dict[str, Any]) -> list[list[str]]:
    """Format scan results as table rows for display.

    Args:
        scan_data: Parsed scan results from run_nmap_scan().

    Returns:
        List of rows, each containing [port/proto, state, service, version].
    """
    rows: list[list[str]] = []
    for port in scan_data.get("ports", []):
        port_str = f"{port['port']}/{port['protocol']}"
        rows.append([
            port_str,
            port["state"],
            port.get("service", ""),
            port.get("version", ""),
        ])
    return rows
