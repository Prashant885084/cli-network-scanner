#!/usr/bin/env python3
"""
Tests for network_info module.
"""

import socket
import sys
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.network_info import (
    get_hostname,
    get_loopback_address,
    get_local_ip,
    get_active_interface,
    get_default_gateway,
    get_all_network_info,
)


class TestGetHostname:
    """Tests for hostname detection."""

    def test_returns_string(self) -> None:
        hostname = get_hostname()
        assert isinstance(hostname, str)

    def test_not_empty(self) -> None:
        hostname = get_hostname()
        assert len(hostname) > 0

    def test_matches_socket(self) -> None:
        hostname = get_hostname()
        assert hostname == socket.gethostname()


class TestGetLoopback:
    """Tests for loopback address."""

    def test_returns_127_0_0_1(self) -> None:
        assert get_loopback_address() == "127.0.0.1"


class TestGetLocalIP:
    """Tests for local IP detection."""

    def test_returns_string(self) -> None:
        ip = get_local_ip()
        assert isinstance(ip, str)

    def test_is_valid_ipv4(self) -> None:
        ip = get_local_ip()
        parts = ip.split(".")
        assert len(parts) == 4
        for part in parts:
            assert 0 <= int(part) <= 255

    def test_not_public_claim(self) -> None:
        """Ensure we don't falsely return a public IP."""
        ip = get_local_ip()
        # Should be a private or loopback address
        assert (
            ip.startswith("10.")
            or ip.startswith("172.")
            or ip.startswith("192.168.")
            or ip.startswith("127.")
        )


class TestGetAllNetworkInfo:
    """Tests for the combined info function."""

    def test_returns_dict(self) -> None:
        info = get_all_network_info()
        assert isinstance(info, dict)

    def test_has_required_keys(self) -> None:
        info = get_all_network_info()
        assert "hostname" in info
        assert "local_ip" in info
        assert "loopback" in info
        assert "interface" in info
        assert "default_gateway" in info

    def test_loopback_is_correct(self) -> None:
        info = get_all_network_info()
        assert info["loopback"] == "127.0.0.1"

    def test_hostname_matches(self) -> None:
        info = get_all_network_info()
        assert info["hostname"] == socket.gethostname()
