#!/usr/bin/env python3
"""
packet_capture.py — Tshark Packet Capture Manager.

Captures network traffic on the loopback interface (or a specified interface)
for a configurable duration.  Saves to captures/lab_capture.pcapng.

Only captures traffic relevant to the lab (filtered to lab ports).
Does not implement stealth, persistence, or credential interception.
"""

import logging
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from src.utils import get_captures_dir

logger = logging.getLogger("cli_network_scanner.packet_capture")


class PacketCapture:
    """Manages a tshark packet capture session."""

    def __init__(
        self,
        interface: str = "lo",
        duration: int = 15,
        lab_ports: Optional[list[int]] = None,
        output_file: Optional[str] = None,
    ) -> None:
        """Initialize the packet capture.

        Args:
            interface: Network interface to capture on (default: loopback).
            duration: Capture duration in seconds.
            lab_ports: Ports to filter on; captures all if empty.
            output_file: Override for the capture file path.
        """
        self.interface = interface
        self.duration = duration
        self.lab_ports = lab_ports or []
        self._output_file = output_file or str(
            get_captures_dir() / "lab_capture.pcapng"
        )
        self._process: Optional[subprocess.Popen] = None

    @property
    def output_file(self) -> str:
        return self._output_file

    def _build_capture_filter(self) -> str:
        """Build a BPF capture filter for the lab ports.

        Returns:
            A BPF filter string, or empty string for no filter.
        """
        if not self.lab_ports:
            return ""

        port_filters = [f"port {p}" for p in self.lab_ports]
        return " or ".join(port_filters)

    def start(self) -> bool:
        """Start tshark capture in the background.

        Returns:
            True if capture started successfully.
        """
        cmd = [
            "tshark",
            "-i", self.interface,
            "-a", f"duration:{self.duration}",
            "-w", self._output_file,
        ]

        capture_filter = self._build_capture_filter()
        if capture_filter:
            cmd.extend(["-f", capture_filter])

        logger.info("Starting capture: %s", " ".join(cmd))

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Brief wait to check if tshark started successfully
            time.sleep(1.0)
            if self._process.poll() is not None:
                stderr = self._process.stderr.read().decode() if self._process.stderr else ""
                logger.error("Tshark exited immediately: %s", stderr)
                return False

            logger.info("Capture started (PID %d)", self._process.pid)
            return True

        except FileNotFoundError:
            logger.error("tshark is not installed or not found on PATH")
            return False
        except PermissionError:
            logger.error(
                "Permission denied running tshark. "
                "You may need to run as root or add your user to the 'wireshark' group."
            )
            return False
        except Exception:
            logger.exception("Failed to start tshark capture")
            return False

    def wait(self) -> bool:
        """Wait for the capture to complete.

        Returns:
            True if capture completed successfully.
        """
        if self._process is None:
            return False

        try:
            self._process.wait(timeout=self.duration + 30)
            return_code = self._process.returncode
            if return_code == 0:
                logger.info("Capture completed successfully")
                return True
            else:
                stderr = self._process.stderr.read().decode() if self._process.stderr else ""
                logger.warning("tshark exited with code %d: %s", return_code, stderr)
                return return_code == 0
        except subprocess.TimeoutExpired:
            logger.warning("Capture timed out — stopping")
            self.stop()
            return False

    def stop(self) -> None:
        """Stop the capture process if running."""
        if self._process is not None and self._process.poll() is None:
            try:
                self._process.send_signal(signal.SIGINT)
                self._process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                self._process.kill()
            logger.info("Capture stopped")

    def get_capture_info(self) -> dict[str, Any]:
        """Return metadata about the capture.

        Returns:
            Dictionary with file path, size, and status.
        """
        info: dict[str, Any] = {
            "capture_file": self._output_file,
            "interface": self.interface,
            "duration": self.duration,
            "filter": self._build_capture_filter(),
        }

        capture_path = Path(self._output_file)
        if capture_path.exists():
            info["file_size_bytes"] = capture_path.stat().st_size
            info["file_exists"] = True
        else:
            info["file_size_bytes"] = 0
            info["file_exists"] = False

        return info


def read_capture_packets(
    capture_file: str,
    max_packets: int = 5000,
) -> list[dict[str, str]]:
    """Read packets from a pcapng file using tshark.

    Args:
        capture_file: Path to the capture file.
        max_packets: Maximum number of packets to read.

    Returns:
        List of packet dictionaries with standard fields.
    """
    if not Path(capture_file).exists():
        logger.error("Capture file not found: %s", capture_file)
        return []

    cmd = [
        "tshark",
        "-r", capture_file,
        "-c", str(max_packets),
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "tcp.flags.str",
        "-E", "header=y",
        "-E", "separator=|",
        "-E", "quote=n",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if proc.returncode != 0:
            logger.warning("tshark read error: %s", proc.stderr.strip())
            return []

        return _parse_tshark_fields(proc.stdout)

    except FileNotFoundError:
        logger.error("tshark not found")
        return []
    except subprocess.TimeoutExpired:
        logger.error("tshark read timed out")
        return []


def _parse_tshark_fields(output: str) -> list[dict[str, str]]:
    """Parse tshark tab-separated field output into dicts.

    Args:
        output: Raw tshark stdout.

    Returns:
        List of packet dictionaries.
    """
    lines = output.strip().split("\n")
    if len(lines) < 2:
        return []

    headers = [h.strip() for h in lines[0].split("|")]
    packets: list[dict[str, str]] = []

    for line in lines[1:]:
        values = line.split("|")
        if len(values) != len(headers):
            continue
        pkt = {headers[i]: values[i].strip() for i in range(len(headers))}
        packets.append(pkt)

    return packets
