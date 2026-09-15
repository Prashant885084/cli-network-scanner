#!/usr/bin/env python3
"""
suspicious_ports.py — Rule-Based Suspicious Port Detection Engine.

Classifies discovered ports as EXPECTED, UNKNOWN, or REVIEW based on
configurable rules.  Provides severity ratings and descriptions.

IMPORTANT DISCLAIMER:
    An open port does NOT automatically mean the service is vulnerable
    or malicious.  This engine flags ports that warrant investigation,
    not ports that are confirmed threats.

    Open != Vulnerable != Malicious
"""

import logging
from typing import Any

logger = logging.getLogger("cli_network_scanner.suspicious_ports")

# Default well-known ports and their common service descriptions
WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6667: "IRC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9090: "Various",
}


def classify_ports(
    discovered_ports: list[dict[str, Any]],
    expected_ports: list[int],
    review_ports: list[int],
    severity_map: dict[str, str],
    descriptions: dict[str, str],
) -> list[dict[str, Any]]:
    """Classify each discovered port.

    Args:
        discovered_ports: List of port dicts from the scanner (with 'port',
                          'protocol', 'state', 'service' keys).
        expected_ports: Ports that are part of the authorized lab.
        review_ports: Ports that should be flagged for review.
        severity_map: Port-number-string to severity-level mapping.
        descriptions: Port-number-string to description mapping.

    Returns:
        List of classification dicts.
    """
    classifications: list[dict[str, Any]] = []

    for port_info in discovered_ports:
        port_num = port_info.get("port", 0)
        state = port_info.get("state", "unknown")

        # Only classify open ports
        if state != "open":
            continue

        classification = _classify_single_port(
            port_num=port_num,
            port_info=port_info,
            expected_ports=expected_ports,
            review_ports=review_ports,
            severity_map=severity_map,
            descriptions=descriptions,
        )
        classifications.append(classification)

    logger.info("Classified %d open ports", len(classifications))
    return classifications


def _classify_single_port(
    port_num: int,
    port_info: dict[str, Any],
    expected_ports: list[int],
    review_ports: list[int],
    severity_map: dict[str, str],
    descriptions: dict[str, str],
) -> dict[str, Any]:
    """Classify a single port.

    Args:
        port_num: The port number.
        port_info: Full port information from the scanner.
        expected_ports: Lab expected ports.
        review_ports: Ports requiring review.
        severity_map: Severity level per port.
        descriptions: Custom descriptions per port.

    Returns:
        Classification dictionary.
    """
    port_str = str(port_num)

    result: dict[str, Any] = {
        "port": port_num,
        "protocol": port_info.get("protocol", "tcp"),
        "service": port_info.get("service", WELL_KNOWN_SERVICES.get(port_num, "unknown")),
        "classification": "UNKNOWN",
        "severity": "info",
        "reason": "",
        "recommendation": "",
    }

    if port_num in expected_ports:
        result["classification"] = "EXPECTED"
        result["severity"] = "info"
        result["reason"] = "This port is part of the authorized lab environment."
        result["recommendation"] = "No action needed — lab service."

    elif port_num in review_ports:
        result["classification"] = "REVIEW"
        result["severity"] = severity_map.get(port_str, "medium")
        result["reason"] = descriptions.get(
            port_str,
            f"Port {port_num} is on the review list and should be investigated.",
        )
        result["recommendation"] = (
            f"Verify that the service on port {port_num} is authorized and "
            f"properly configured. An open port does NOT necessarily indicate "
            f"a vulnerability."
        )

    else:
        # Unknown — not in expected or review lists
        result["classification"] = "UNKNOWN"
        result["severity"] = "low"
        result["reason"] = (
            f"Port {port_num} is open but not in the expected or review lists. "
            f"This may be a legitimate system service."
        )
        result["recommendation"] = (
            f"Identify what service is running on port {port_num} using the "
            f"process mapping. Determine if it should be expected."
        )

    return result


def get_detection_summary(
    classifications: list[dict[str, Any]],
) -> dict[str, Any]:
    """Produce a summary of the detection results.

    Args:
        classifications: List of classification dicts.

    Returns:
        Summary dictionary with counts and risk assessment.
    """
    counts = {"EXPECTED": 0, "UNKNOWN": 0, "REVIEW": 0}
    review_items: list[dict[str, Any]] = []

    for c in classifications:
        cat = c.get("classification", "UNKNOWN")
        counts[cat] = counts.get(cat, 0) + 1
        if cat == "REVIEW":
            review_items.append(c)

    # Overall risk assessment
    if counts["REVIEW"] == 0 and counts["UNKNOWN"] == 0:
        risk_level = "LOW"
        risk_description = "All detected ports are expected lab services."
    elif counts["REVIEW"] > 0:
        risk_level = "MEDIUM"
        risk_description = (
            f"{counts['REVIEW']} port(s) flagged for review. "
            f"Investigate to confirm they are authorized."
        )
    else:
        risk_level = "LOW"
        risk_description = (
            f"{counts['UNKNOWN']} unknown port(s) detected. "
            f"These may be legitimate system services."
        )

    return {
        "total_classified": len(classifications),
        "counts": counts,
        "risk_level": risk_level,
        "risk_description": risk_description,
        "review_items": review_items,
        "disclaimer": (
            "IMPORTANT: An open port does NOT prove that a service is "
            "vulnerable or malicious. Open != Vulnerable != Malicious. "
            "Each finding should be investigated in context."
        ),
    }


def format_classifications(classifications: list[dict[str, Any]]) -> list[list[str]]:
    """Format classifications as table rows.

    Args:
        classifications: List of classification dicts.

    Returns:
        List of rows: [port, service, classification, severity, reason].
    """
    rows: list[list[str]] = []
    for c in classifications:
        rows.append([
            str(c["port"]),
            c.get("service", ""),
            c["classification"],
            c["severity"],
            c.get("reason", "")[:60],
        ])
    return rows
