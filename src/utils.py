#!/usr/bin/env python3
"""
utils.py — Utility functions for the CLI Network Scanner.

Provides:
    - Dependency checking (python3, nmap, tshark, psutil)
    - Styled terminal output with status indicators
    - Structured logging setup
    - Configuration loading
    - Path resolution relative to project root
    - Target validation (security safeguard)
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import ipaddress
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def get_project_root() -> Path:
    """Return the absolute path to the project root directory."""
    return Path(__file__).resolve().parent.parent


def get_config_path() -> Path:
    """Return the path to config/config.json."""
    return get_project_root() / "config" / "config.json"


def get_reports_dir() -> Path:
    """Return the path to the reports/ directory, creating it if needed."""
    d = get_project_root() / "reports"
    d.mkdir(exist_ok=True)
    return d


def get_captures_dir() -> Path:
    """Return the path to the captures/ directory, creating it if needed."""
    d = get_project_root() / "captures"
    d.mkdir(exist_ok=True)
    return d


def get_logs_dir() -> Path:
    """Return the path to the logs/ directory, creating it if needed."""
    d = get_project_root() / "logs"
    d.mkdir(exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    """Load and return the JSON configuration.

    Args:
        config_path: Optional override for the config file location.

    Returns:
        Parsed configuration dictionary.

    Raises:
        SystemExit: If the config file is missing or malformed.
    """
    path = config_path or get_config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print_error(f"Configuration file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print_error(f"Malformed configuration file: {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure and return the project logger.

    Logs to both the console (WARNING+) and a file (DEBUG+).
    """
    logger = logging.getLogger("cli_network_scanner")
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(logging.DEBUG)

    # File handler — verbose
    log_file = get_logs_dir() / "scanner.log"
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
    ))
    logger.addHandler(fh)

    # Console handler — warnings and above only (regular output uses print_*)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(ch)

    return logger


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Print the application banner."""
    banner = """
====================================================
 CLI NETWORK SCANNER + PACKET ANALYZER
              AUTOPILOT LAB
====================================================
"""
    print(banner)


def print_section(step: int, total: int, title: str) -> None:
    """Print a numbered section header."""
    print(f"\n[{step}/{total}] {title}...")
    print("-" * 52)


def print_ok(label: str, value: str = "") -> None:
    """Print a success line: [+] label : value."""
    if value:
        print(f"  [+] {label:<16}: {value}")
    else:
        print(f"  [+] {label}")


def print_warn(message: str) -> None:
    """Print a warning line: [!] message."""
    print(f"  [!] {message}")


def print_error(message: str) -> None:
    """Print an error line: [-] message."""
    print(f"  [-] {message}")


def print_info(message: str) -> None:
    """Print an info line: [*] message."""
    print(f"  [*] {message}")


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    """Print a simple aligned table.

    Args:
        headers: Column header strings.
        rows: List of rows, each row is a list of cell strings.
    """
    if not rows:
        print("  (no data)")
        return

    # Compute column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))

    # Header
    header_line = "  " + "  ".join(
        h.ljust(widths[i]) for i, h in enumerate(headers)
    )
    print(header_line)
    print("  " + "  ".join("-" * w for w in widths))

    # Rows
    for row in rows:
        line = "  " + "  ".join(
            str(cell).ljust(widths[i]) for i, cell in enumerate(row)
        )
        print(line)


def print_footer(success: bool = True) -> None:
    """Print the closing footer."""
    if success:
        print("""
====================================================
                 LAB COMPLETE
====================================================
""")
    else:
        print("""
====================================================
          LAB FINISHED WITH ERRORS
====================================================
""")


# ---------------------------------------------------------------------------
# Dependency checking
# ---------------------------------------------------------------------------

def check_command(name: str) -> bool:
    """Check if a system command is available on PATH."""
    return shutil.which(name) is not None


def check_python_module(name: str) -> bool:
    """Check if a Python module can be imported."""
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def check_all_dependencies() -> bool:
    """Verify all required dependencies are available.

    Returns:
        True if all dependencies are present, False otherwise.
    """
    all_ok = True

    # Python version
    major, minor = sys.version_info[:2]
    if major >= 3 and minor >= 11:
        print_ok("Python", f"{major}.{minor} (OK)")
    else:
        print_warn(f"Python {major}.{minor} — 3.11+ recommended")
        # Allow older 3.x to still run
        if major < 3:
            print_error("Python 3 is required.")
            all_ok = False

    # Nmap
    if check_command("nmap"):
        print_ok("Nmap", "OK")
    else:
        print_error("Nmap not found")
        print_info("Install: sudo apt update && sudo apt install nmap")
        all_ok = False

    # Tshark
    if check_command("tshark"):
        print_ok("Tshark", "OK")
    else:
        print_error("Tshark not found")
        print_info("Install: sudo apt update && sudo apt install tshark")
        all_ok = False

    # psutil
    if check_python_module("psutil"):
        print_ok("psutil", "OK")
    else:
        print_error("psutil not found")
        print_info("Install: pip install psutil")
        all_ok = False

    return all_ok


# ---------------------------------------------------------------------------
# Target validation (security safeguard)
# ---------------------------------------------------------------------------

def is_safe_target(target: str, allow_private: bool = False) -> bool:
    """Validate that a scan target is safe for educational use.

    By default, only 127.0.0.1 and localhost are allowed.
    If allow_private is True, RFC-1918 private addresses are also accepted.

    Args:
        target: The target IP or hostname.
        allow_private: Whether to allow private-network IPs.

    Returns:
        True if the target is considered safe.
    """
    # Localhost names
    if target in ("127.0.0.1", "localhost", "::1"):
        return True

    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        # Could be a hostname; only allow "localhost"
        return target.lower() == "localhost"

    if addr.is_loopback:
        return True

    if allow_private and addr.is_private:
        return True

    return False


def validate_target(target: str, authorized: bool = False) -> str:
    """Validate the scan target and return the validated IP string.

    Args:
        target: Requested scan target.
        authorized: If True, allow private-network targets.

    Returns:
        The validated target string.

    Raises:
        SystemExit: If the target is not allowed.
    """
    if is_safe_target(target, allow_private=authorized):
        return target

    print_error(f"Target '{target}' is not authorized for scanning.")
    print_info("This tool is designed for localhost / authorized lab use only.")
    print_info("To scan a private-network lab machine, use --authorized-target.")
    sys.exit(1)
