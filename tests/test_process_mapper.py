#!/usr/bin/env python3
"""
Tests for process_mapper module.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.process_mapper import (
    get_listening_connections,
    map_ports_to_processes,
    format_process_mappings,
    _get_process_info,
)


class TestGetListeningConnections:
    """Tests for listing network connections."""

    def test_returns_list(self) -> None:
        result = get_listening_connections()
        assert isinstance(result, list)

    def test_entries_have_required_keys(self) -> None:
        result = get_listening_connections()
        for entry in result:
            assert "port" in entry
            assert "protocol" in entry
            assert "pid" in entry
            assert "process_name" in entry


class TestMapPortsToProcesses:
    """Tests for port-to-process mapping."""

    def test_returns_list(self) -> None:
        discovered = [
            {"port": 99999, "protocol": "tcp", "state": "open"},
        ]
        result = map_ports_to_processes(discovered)
        assert isinstance(result, list)

    def test_unknown_port_handled(self) -> None:
        """An unlikely port should return 'not found' gracefully."""
        discovered = [
            {"port": 59999, "protocol": "tcp", "state": "open"},
        ]
        result = map_ports_to_processes(discovered)
        assert len(result) == 1
        # Should not crash; process may be unknown
        assert "port" in result[0]

    def test_empty_input(self) -> None:
        result = map_ports_to_processes([])
        assert result == []


class TestGetProcessInfo:
    """Tests for process info retrieval."""

    def test_none_pid(self) -> None:
        result = _get_process_info(None)
        assert "name" in result
        assert "access denied" in result["name"].lower() or "unknown" in result["name"].lower()

    def test_nonexistent_pid(self) -> None:
        result = _get_process_info(999999999)
        assert "name" in result
        # Should report process exited or similar
        assert isinstance(result["name"], str)

    def test_current_process(self) -> None:
        """Our own PID should be identifiable."""
        import os
        result = _get_process_info(os.getpid())
        assert result["name"] != ""
        assert "exited" not in result["name"].lower()


class TestFormatProcessMappings:
    """Tests for display formatting."""

    def test_formats_correctly(self) -> None:
        mappings = [
            {"port": 8080, "process_name": "python3", "pid": 1234},
            {"port": 22, "process_name": "sshd", "pid": 567},
        ]
        rows = format_process_mappings(mappings)
        assert len(rows) == 2
        assert rows[0][0] == "8080"
        assert rows[0][1] == "python3"
        assert rows[0][2] == "1234"

    def test_none_pid_shows_na(self) -> None:
        mappings = [
            {"port": 80, "process_name": "unknown", "pid": None},
        ]
        rows = format_process_mappings(mappings)
        assert rows[0][2] == "N/A"
