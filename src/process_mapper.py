#!/usr/bin/env python3
"""
process_mapper.py — Port-to-Process Mapping.

Uses psutil to map each discovered listening TCP/UDP port to the local
process that owns it.  Handles permission restrictions gracefully and
never fabricates process information.
"""

import logging
from typing import Any, Optional

logger = logging.getLogger("cli_network_scanner.process_mapper")

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]


def get_listening_connections() -> list[dict[str, Any]]:
    """Return all listening TCP and UDP connections with process info.

    Returns:
        List of dicts with keys: port, protocol, pid, process_name, cmdline, status.
        If psutil is unavailable, returns an empty list with a warning.
    """
    if psutil is None:
        logger.error("psutil is not installed — cannot map ports to processes")
        return []

    connections: list[dict[str, Any]] = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            # Only interested in LISTEN state for TCP, or bound UDP
            if conn.status not in ("LISTEN", "NONE", psutil.CONN_LISTEN):
                continue

            laddr = conn.laddr
            if not laddr:
                continue

            port = laddr.port
            pid = conn.pid

            proc_info = _get_process_info(pid)

            connections.append({
                "port": port,
                "address": laddr.ip,
                "protocol": "tcp" if conn.type.name == "SOCK_STREAM" else "udp",
                "pid": pid,
                "process_name": proc_info.get("name", ""),
                "cmdline": proc_info.get("cmdline", ""),
                "status": conn.status,
            })

    except psutil.AccessDenied:
        logger.warning(
            "Access denied when listing connections. "
            "Run with sudo for complete process mapping."
        )
    except Exception:
        logger.exception("Error enumerating network connections")

    # Remove duplicates (same port+protocol)
    seen: set[tuple[int, str]] = set()
    unique: list[dict[str, Any]] = []
    for c in connections:
        key = (c["port"], c["protocol"])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    logger.info("Mapped %d listening ports to processes", len(unique))
    return unique


def _get_process_info(pid: Optional[int]) -> dict[str, str]:
    """Retrieve process name and command line for a given PID.

    Args:
        pid: The process ID. May be None if the OS did not report it.

    Returns:
        Dictionary with 'name' and 'cmdline' keys.
    """
    if pid is None or psutil is None:
        return {"name": "(unknown — access denied or no PID)", "cmdline": ""}

    try:
        proc = psutil.Process(pid)
        name = proc.name()
        try:
            cmdline = " ".join(proc.cmdline())
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cmdline = "(access denied)"
        return {"name": name, "cmdline": cmdline}
    except psutil.NoSuchProcess:
        return {"name": "(process exited)", "cmdline": ""}
    except psutil.AccessDenied:
        return {
            "name": "(access denied — run as root to see this process)",
            "cmdline": "",
        }


def map_ports_to_processes(
    discovered_ports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map a list of discovered ports (from Nmap) to their owning processes.

    Args:
        discovered_ports: List of port dicts from the port scanner, each
                          containing at least 'port' and 'protocol' keys.

    Returns:
        List of mappings with port, protocol, pid, process_name, cmdline.
    """
    listening = get_listening_connections()
    listening_lookup: dict[tuple[int, str], dict[str, Any]] = {
        (c["port"], c["protocol"]): c for c in listening
    }

    mappings: list[dict[str, Any]] = []

    for port_info in discovered_ports:
        port_num = port_info.get("port", 0)
        proto = port_info.get("protocol", "tcp")
        key = (port_num, proto)

        if key in listening_lookup:
            conn = listening_lookup[key]
            mappings.append({
                "port": port_num,
                "protocol": proto,
                "pid": conn["pid"],
                "process_name": conn["process_name"],
                "cmdline": conn["cmdline"],
            })
        else:
            mappings.append({
                "port": port_num,
                "protocol": proto,
                "pid": None,
                "process_name": "(not found — may require root)",
                "cmdline": "",
            })

    return mappings


def format_process_mappings(mappings: list[dict[str, Any]]) -> list[list[str]]:
    """Format process mappings as table rows for display.

    Args:
        mappings: List of mapping dicts from map_ports_to_processes().

    Returns:
        List of rows: [port, process, PID].
    """
    rows: list[list[str]] = []
    for m in mappings:
        rows.append([
            str(m["port"]),
            m["process_name"],
            str(m["pid"]) if m["pid"] is not None else "N/A",
        ])
    return rows
