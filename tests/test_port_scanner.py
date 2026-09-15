#!/usr/bin/env python3
"""
Tests for port_scanner module.

Tests focus on XML parsing logic and target validation rather than
running actual Nmap scans (which require nmap and root).
"""

import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.port_scanner import _parse_nmap_xml, format_scan_results
from src.utils import is_safe_target


# ---------------------------------------------------------------------------
# Sample Nmap XML for testing
# ---------------------------------------------------------------------------

SAMPLE_NMAP_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" args="nmap -sT -sV -p 8080,9090 127.0.0.1"
             startstr="Tue Sep 15 10:00:00 2026">
        <host>
            <address addr="127.0.0.1" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="8080">
                    <state state="open"/>
                    <service name="http-proxy" product="Python" version="3.11"/>
                </port>
                <port protocol="tcp" portid="9090">
                    <state state="open"/>
                    <service name="unknown"/>
                </port>
                <port protocol="tcp" portid="22">
                    <state state="closed"/>
                    <service name="ssh"/>
                </port>
            </ports>
        </host>
    </nmaprun>
""")


class TestParseNmapXML:
    """Tests for Nmap XML parsing."""

    def _write_xml(self, content: str) -> Path:
        """Write XML content to a temp file and return its path."""
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        )
        f.write(content)
        f.close()
        return Path(f.name)

    def test_parses_open_ports(self) -> None:
        xml_path = self._write_xml(SAMPLE_NMAP_XML)
        result = _parse_nmap_xml(xml_path)

        ports = result["ports"]
        assert len(ports) == 3  # 2 open + 1 closed

        open_ports = [p for p in ports if p["state"] == "open"]
        assert len(open_ports) == 2

    def test_port_numbers(self) -> None:
        xml_path = self._write_xml(SAMPLE_NMAP_XML)
        result = _parse_nmap_xml(xml_path)

        port_nums = {p["port"] for p in result["ports"]}
        assert 8080 in port_nums
        assert 9090 in port_nums
        assert 22 in port_nums

    def test_service_names(self) -> None:
        xml_path = self._write_xml(SAMPLE_NMAP_XML)
        result = _parse_nmap_xml(xml_path)

        services = {p["port"]: p["service"] for p in result["ports"]}
        assert services[8080] == "http-proxy"
        assert services[22] == "ssh"

    def test_service_version(self) -> None:
        xml_path = self._write_xml(SAMPLE_NMAP_XML)
        result = _parse_nmap_xml(xml_path)

        port_8080 = [p for p in result["ports"] if p["port"] == 8080][0]
        assert "Python" in port_8080["version"]
        assert "3.11" in port_8080["version"]

    def test_scan_info(self) -> None:
        xml_path = self._write_xml(SAMPLE_NMAP_XML)
        result = _parse_nmap_xml(xml_path)

        assert result["scan_info"]["scanner"] == "nmap"

    def test_handles_missing_file(self) -> None:
        result = _parse_nmap_xml(Path("/nonexistent/path.xml"))
        assert result["ports"] == []

    def test_handles_malformed_xml(self) -> None:
        xml_path = self._write_xml("<invalid><xml>")
        result = _parse_nmap_xml(xml_path)
        # Should not crash; may return empty or partial results
        assert isinstance(result, dict)


class TestFormatScanResults:
    """Tests for scan result formatting."""

    def test_formats_rows(self) -> None:
        scan_data = {
            "ports": [
                {"port": 8080, "protocol": "tcp", "state": "open",
                 "service": "http", "version": ""},
                {"port": 22, "protocol": "tcp", "state": "closed",
                 "service": "ssh", "version": "OpenSSH 8.9"},
            ]
        }
        rows = format_scan_results(scan_data)
        assert len(rows) == 2
        assert rows[0][0] == "8080/tcp"

    def test_empty_data(self) -> None:
        rows = format_scan_results({"ports": []})
        assert rows == []


class TestTargetValidation:
    """Tests for target safety validation."""

    def test_localhost_is_safe(self) -> None:
        assert is_safe_target("127.0.0.1") is True

    def test_localhost_name_is_safe(self) -> None:
        assert is_safe_target("localhost") is True

    def test_public_ip_rejected(self) -> None:
        assert is_safe_target("8.8.8.8") is False

    def test_public_ip_rejected_2(self) -> None:
        assert is_safe_target("1.1.1.1") is False

    def test_private_ip_rejected_by_default(self) -> None:
        assert is_safe_target("192.168.1.1") is False

    def test_private_ip_allowed_when_authorized(self) -> None:
        assert is_safe_target("192.168.1.1", allow_private=True) is True

    def test_10_network_allowed_when_authorized(self) -> None:
        assert is_safe_target("10.0.0.5", allow_private=True) is True

    def test_random_hostname_rejected(self) -> None:
        assert is_safe_target("evil-server.com") is False
