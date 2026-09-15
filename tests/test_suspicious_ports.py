#!/usr/bin/env python3
"""
Tests for suspicious_ports module.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.suspicious_ports import (
    classify_ports,
    get_detection_summary,
    format_classifications,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

EXPECTED_PORTS = [8080, 9090]
REVIEW_PORTS = [23, 445, 3389]
SEVERITY_MAP = {"23": "high", "445": "medium", "3389": "medium"}
DESCRIPTIONS = {
    "23": "Telnet - insecure unencrypted protocol",
    "445": "SMB - file sharing, potential lateral movement vector",
    "3389": "RDP - remote desktop, verify authorization",
}


def _make_port(port: int, state: str = "open", service: str = "") -> dict:
    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "service": service,
    }


class TestClassifyPorts:
    """Tests for port classification."""

    def test_lab_port_is_expected(self) -> None:
        ports = [_make_port(8080, service="http")]
        result = classify_ports(ports, EXPECTED_PORTS, REVIEW_PORTS,
                                SEVERITY_MAP, DESCRIPTIONS)
        assert len(result) == 1
        assert result[0]["classification"] == "EXPECTED"

    def test_telnet_is_review(self) -> None:
        ports = [_make_port(23, service="telnet")]
        result = classify_ports(ports, EXPECTED_PORTS, REVIEW_PORTS,
                                SEVERITY_MAP, DESCRIPTIONS)
        assert len(result) == 1
        assert result[0]["classification"] == "REVIEW"
        assert result[0]["severity"] == "high"

    def test_smb_is_review(self) -> None:
        ports = [_make_port(445, service="smb")]
        result = classify_ports(ports, EXPECTED_PORTS, REVIEW_PORTS,
                                SEVERITY_MAP, DESCRIPTIONS)
        assert result[0]["classification"] == "REVIEW"
        assert result[0]["severity"] == "medium"

    def test_unknown_port(self) -> None:
        ports = [_make_port(12345, service="mystery")]
        result = classify_ports(ports, EXPECTED_PORTS, REVIEW_PORTS,
                                SEVERITY_MAP, DESCRIPTIONS)
        assert result[0]["classification"] == "UNKNOWN"

    def test_closed_ports_ignored(self) -> None:
        ports = [_make_port(8080, state="closed")]
        result = classify_ports(ports, EXPECTED_PORTS, REVIEW_PORTS,
                                SEVERITY_MAP, DESCRIPTIONS)
        assert len(result) == 0

    def test_multiple_ports(self) -> None:
        ports = [
            _make_port(8080),
            _make_port(9090),
            _make_port(23),
            _make_port(12345),
        ]
        result = classify_ports(ports, EXPECTED_PORTS, REVIEW_PORTS,
                                SEVERITY_MAP, DESCRIPTIONS)
        classifications = {c["port"]: c["classification"] for c in result}
        assert classifications[8080] == "EXPECTED"
        assert classifications[9090] == "EXPECTED"
        assert classifications[23] == "REVIEW"
        assert classifications[12345] == "UNKNOWN"

    def test_empty_input(self) -> None:
        result = classify_ports([], EXPECTED_PORTS, REVIEW_PORTS,
                                SEVERITY_MAP, DESCRIPTIONS)
        assert result == []


class TestGetDetectionSummary:
    """Tests for detection summary generation."""

    def test_all_expected(self) -> None:
        classifications = [
            {"port": 8080, "classification": "EXPECTED", "severity": "info"},
            {"port": 9090, "classification": "EXPECTED", "severity": "info"},
        ]
        summary = get_detection_summary(classifications)
        assert summary["risk_level"] == "LOW"
        assert summary["counts"]["EXPECTED"] == 2
        assert summary["counts"]["REVIEW"] == 0

    def test_with_review(self) -> None:
        classifications = [
            {"port": 8080, "classification": "EXPECTED", "severity": "info"},
            {"port": 23, "classification": "REVIEW", "severity": "high"},
        ]
        summary = get_detection_summary(classifications)
        assert summary["risk_level"] == "MEDIUM"
        assert summary["counts"]["REVIEW"] == 1
        assert len(summary["review_items"]) == 1

    def test_has_disclaimer(self) -> None:
        summary = get_detection_summary([])
        assert "disclaimer" in summary
        assert "Open" in summary["disclaimer"]

    def test_empty_classifications(self) -> None:
        summary = get_detection_summary([])
        assert summary["total_classified"] == 0
        assert summary["risk_level"] == "LOW"


class TestFormatClassifications:
    """Tests for classification table formatting."""

    def test_format_rows(self) -> None:
        classifications = [
            {
                "port": 8080,
                "service": "http",
                "classification": "EXPECTED",
                "severity": "info",
                "reason": "Lab service",
            },
        ]
        rows = format_classifications(classifications)
        assert len(rows) == 1
        assert rows[0][0] == "8080"
        assert rows[0][2] == "EXPECTED"
