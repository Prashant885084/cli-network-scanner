#!/usr/bin/env python3
"""
Tests for report_generator module.
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.report_generator import generate_report, save_report


# ---------------------------------------------------------------------------
# Test data fixtures
# ---------------------------------------------------------------------------

def _sample_network_info() -> dict:
    return {
        "hostname": "test-laptop",
        "local_ip": "192.168.1.10",
        "loopback": "127.0.0.1",
        "interface": "wlan0",
        "default_gateway": "192.168.1.1",
    }


def _sample_scan_results() -> dict:
    return {
        "ports": [
            {"port": 8080, "protocol": "tcp", "state": "open",
             "service": "http-proxy", "version": "Python 3.11"},
            {"port": 9090, "protocol": "tcp", "state": "open",
             "service": "unknown", "version": ""},
        ],
        "scan_info": {"scanner": "nmap", "args": "nmap -sT"},
        "errors": [],
    }


def _sample_process_mappings() -> list:
    return [
        {"port": 8080, "protocol": "tcp", "pid": 1234,
         "process_name": "python3", "cmdline": "python3 src/main.py"},
        {"port": 9090, "protocol": "tcp", "pid": 1234,
         "process_name": "python3", "cmdline": "python3 src/main.py"},
    ]


def _sample_analysis() -> dict:
    return {
        "total_packets": 50,
        "protocol_stats": {"tcp": 45, "udp": 5, "http": 10, "other": 0},
        "unique_ips": {"source": ["127.0.0.1"], "destination": ["127.0.0.1"],
                       "source_count": 1, "destination_count": 1},
        "conversations": [],
        "tcp_behavior": {"flag_counts": {}, "handshake_phases": []},
        "packet_size_stats": {"min": 54, "max": 1500, "average": 200, "total_bytes": 10000},
    }


def _sample_classifications() -> list:
    return [
        {"port": 8080, "classification": "EXPECTED", "severity": "info",
         "service": "http", "reason": "Lab service", "recommendation": ""},
    ]


def _sample_detection_summary() -> dict:
    return {
        "total_classified": 1,
        "counts": {"EXPECTED": 1, "UNKNOWN": 0, "REVIEW": 0},
        "risk_level": "LOW",
        "risk_description": "All detected ports are expected.",
        "review_items": [],
        "disclaimer": "Open != Vulnerable != Malicious",
    }


class TestGenerateReport:
    """Tests for report generation."""

    def test_returns_dict(self) -> None:
        report = generate_report(
            network_info=_sample_network_info(),
            scan_results=_sample_scan_results(),
            process_mappings=_sample_process_mappings(),
            packet_analysis=_sample_analysis(),
            classifications=_sample_classifications(),
            detection_summary=_sample_detection_summary(),
            lab_services=[],
            capture_info={"capture_file": "/tmp/test.pcapng"},
            traffic_results={"total_success": 5, "total_errors": 0},
        )
        assert isinstance(report, dict)

    def test_has_required_sections(self) -> None:
        report = generate_report(
            network_info=_sample_network_info(),
            scan_results=_sample_scan_results(),
            process_mappings=_sample_process_mappings(),
            packet_analysis=_sample_analysis(),
            classifications=_sample_classifications(),
            detection_summary=_sample_detection_summary(),
            lab_services=[],
            capture_info={"capture_file": "/tmp/test.pcapng"},
            traffic_results={"total_success": 5, "total_errors": 0},
        )
        assert "scan_metadata" in report
        assert "host" in report
        assert "open_ports" in report
        assert "process_mapping" in report
        assert "packet_statistics" in report
        assert "suspicious_ports" in report
        assert "detection_summary" in report
        assert "disclaimer" in report

    def test_metadata_is_correct(self) -> None:
        report = generate_report(
            network_info=_sample_network_info(),
            scan_results=_sample_scan_results(),
            process_mappings=_sample_process_mappings(),
            packet_analysis=_sample_analysis(),
            classifications=_sample_classifications(),
            detection_summary=_sample_detection_summary(),
            lab_services=[],
            capture_info={"capture_file": "/tmp/test.pcapng"},
            traffic_results={"total_success": 5, "total_errors": 0},
            target="127.0.0.1",
        )
        assert report["scan_metadata"]["target"] == "127.0.0.1"
        assert report["scan_metadata"]["authorized_lab"] is True

    def test_open_ports_filtered(self) -> None:
        report = generate_report(
            network_info=_sample_network_info(),
            scan_results=_sample_scan_results(),
            process_mappings=_sample_process_mappings(),
            packet_analysis=_sample_analysis(),
            classifications=_sample_classifications(),
            detection_summary=_sample_detection_summary(),
            lab_services=[],
            capture_info={"capture_file": "/tmp/test.pcapng"},
            traffic_results={"total_success": 5, "total_errors": 0},
        )
        # All sample ports are open
        assert len(report["open_ports"]) == 2

    def test_is_json_serializable(self) -> None:
        report = generate_report(
            network_info=_sample_network_info(),
            scan_results=_sample_scan_results(),
            process_mappings=_sample_process_mappings(),
            packet_analysis=_sample_analysis(),
            classifications=_sample_classifications(),
            detection_summary=_sample_detection_summary(),
            lab_services=[],
            capture_info={"capture_file": "/tmp/test.pcapng"},
            traffic_results={"total_success": 5, "total_errors": 0},
        )
        # Should not raise
        json_str = json.dumps(report, default=str)
        assert len(json_str) > 0

    def test_errors_included(self) -> None:
        report = generate_report(
            network_info=_sample_network_info(),
            scan_results=_sample_scan_results(),
            process_mappings=_sample_process_mappings(),
            packet_analysis=_sample_analysis(),
            classifications=_sample_classifications(),
            detection_summary=_sample_detection_summary(),
            lab_services=[],
            capture_info={"capture_file": "/tmp/test.pcapng"},
            traffic_results={"total_success": 5, "total_errors": 0},
            errors=["Test error 1", "Test error 2"],
        )
        assert len(report["errors"]) == 2


class TestSaveReport:
    """Tests for report saving."""

    def test_saves_to_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that save_report creates a JSON file."""
        # Monkey-patch get_reports_dir to use tmp_path
        monkeypatch.setattr(
            "src.report_generator.get_reports_dir",
            lambda: tmp_path,
        )

        report = {"test": "data", "nested": {"key": "value"}}
        result = save_report(report, filename="test_report.json")

        assert result != ""
        saved_path = Path(result)
        assert saved_path.exists()

        with open(saved_path, "r") as f:
            loaded = json.load(f)
        assert loaded["test"] == "data"

    def test_creates_latest_copy(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "src.report_generator.get_reports_dir",
            lambda: tmp_path,
        )

        report = {"test": "latest"}
        save_report(report, filename="test_report.json")

        latest = tmp_path / "network_scan_report.json"
        assert latest.exists()
