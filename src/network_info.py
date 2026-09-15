#!/usr/bin/env python3
"""
network_info.py — Local Network Information Detection.

Detects and reports:
    - Hostname
    - Local IPv4 address (non-loopback)
    - Loopback address
    - Active network interface
    - Default gateway (Linux /proc/net/route)
"""

import logging
import socket
from typing import Any, Optional

logger = logging.getLogger("cli_network_scanner.network_info")

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]


def get_hostname() -> str:
    """Return the system hostname."""
    return socket.gethostname()


def get_loopback_address() -> str:
    """Return the loopback address."""
    return "127.0.0.1"


def get_local_ip() -> str:
    """Determine the primary local IPv4 address.

    Uses a UDP connect trick to find the default outgoing IP without
    actually sending traffic.  Falls back to gethostbyname if that fails.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to a public DNS address — no data is sent
            s.connect(("8.8.8.8", 80))
            ip: str = s.getsockname()[0]
            return ip
    except OSError:
        pass

    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        return "127.0.0.1"


def get_active_interface() -> Optional[str]:
    """Return the name of the active non-loopback network interface.

    Requires psutil.  Returns None if detection fails.
    """
    if psutil is None:
        logger.warning("psutil not available; cannot detect interface")
        return None

    local_ip = get_local_ip()

    try:
        addrs = psutil.net_if_addrs()
        for iface_name, iface_addrs in addrs.items():
            for addr in iface_addrs:
                if (
                    addr.family == socket.AF_INET
                    and addr.address == local_ip
                    and iface_name != "lo"
                ):
                    return iface_name
    except Exception:
        logger.exception("Error detecting network interface")

    # Fallback: return first non-loopback interface with an IPv4 address
    try:
        addrs = psutil.net_if_addrs()
        for iface_name, iface_addrs in addrs.items():
            if iface_name == "lo":
                continue
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                    return iface_name
    except Exception:
        pass

    return None


def get_default_gateway() -> Optional[str]:
    """Attempt to read the default gateway from /proc/net/route (Linux).

    Returns:
        Gateway IP string, or None if not obtainable.
    """
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    # Gateway is in hex, little-endian
                    gw_hex = parts[2]
                    gw_bytes = bytes.fromhex(gw_hex)
                    gw_ip = f"{gw_bytes[3]}.{gw_bytes[2]}.{gw_bytes[1]}.{gw_bytes[0]}"
                    if gw_ip != "0.0.0.0":
                        return gw_ip
    except (FileNotFoundError, PermissionError, ValueError):
        logger.debug("Could not read /proc/net/route for default gateway")

    return None


def get_all_network_info() -> dict[str, Any]:
    """Gather all available network information.

    Returns:
        Dictionary with hostname, local_ip, loopback, interface, and gateway.
    """
    info: dict[str, Any] = {
        "hostname": get_hostname(),
        "local_ip": get_local_ip(),
        "loopback": get_loopback_address(),
        "interface": get_active_interface(),
        "default_gateway": get_default_gateway(),
    }
    logger.info("Network info collected: %s", info)
    return info
