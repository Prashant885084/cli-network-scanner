#!/usr/bin/env python3
"""
packet_analyzer.py — Packet Analysis Module.

Reads captured pcapng files (via tshark) and produces:
    - Protocol statistics (TCP, UDP, HTTP counts)
    - Unique source/destination IPs
    - Conversation tracking (src:port -> dst:port)
    - TCP handshake behavior description
    - Packet length distribution

Does NOT reconstruct passwords, cookies, authentication tokens, or
private user data.
"""

import logging
from collections import Counter
from typing import Any

from src.packet_capture import read_capture_packets

logger = logging.getLogger("cli_network_scanner.packet_analyzer")


def analyze_capture(capture_file: str) -> dict[str, Any]:
    """Perform full analysis of a packet capture file.

    Args:
        capture_file: Path to the .pcapng capture file.

    Returns:
        Dictionary with statistics, conversations, tcp_behavior, etc.
    """
    packets = read_capture_packets(capture_file)

    if not packets:
        logger.warning("No packets found in capture file: %s", capture_file)
        return {
            "total_packets": 0,
            "error": "No packets found or capture file is empty.",
        }

    analysis: dict[str, Any] = {
        "total_packets": len(packets),
        "protocol_stats": _count_protocols(packets),
        "unique_ips": _get_unique_ips(packets),
        "conversations": _extract_conversations(packets),
        "tcp_behavior": _analyze_tcp_flags(packets),
        "packet_size_stats": _packet_size_stats(packets),
    }

    logger.info("Analyzed %d packets from %s", len(packets), capture_file)
    return analysis


def _count_protocols(packets: list[dict[str, str]]) -> dict[str, int]:
    """Count packets by protocol type.

    Args:
        packets: List of packet dicts from tshark.

    Returns:
        Protocol count dictionary.
    """
    stats: dict[str, int] = {
        "tcp": 0,
        "udp": 0,
        "http": 0,
        "other": 0,
    }

    for pkt in packets:
        protocols = pkt.get("frame.protocols", "").lower()

        if "tcp" in protocols:
            stats["tcp"] += 1
        if "udp" in protocols:
            stats["udp"] += 1
        if "http" in protocols:
            stats["http"] += 1
        if "tcp" not in protocols and "udp" not in protocols:
            stats["other"] += 1

    return stats


def _get_unique_ips(packets: list[dict[str, str]]) -> dict[str, list[str]]:
    """Extract unique source and destination IPs.

    Args:
        packets: List of packet dicts.

    Returns:
        Dictionary with 'source' and 'destination' IP lists.
    """
    src_ips: set[str] = set()
    dst_ips: set[str] = set()

    for pkt in packets:
        src = pkt.get("ip.src", "")
        dst = pkt.get("ip.dst", "")
        if src:
            src_ips.add(src)
        if dst:
            dst_ips.add(dst)

    return {
        "source": sorted(src_ips),
        "destination": sorted(dst_ips),
        "source_count": len(src_ips),
        "destination_count": len(dst_ips),
    }


def _extract_conversations(packets: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Identify unique network conversations.

    A conversation is a unique combination of src_ip:src_port -> dst_ip:dst_port.
    We track by the server-side port (the lower/known port) to group flows.

    Args:
        packets: List of packet dicts.

    Returns:
        List of conversation dicts with endpoints and packet counts.
    """
    conv_counter: Counter[str] = Counter()

    for pkt in packets:
        src_ip = pkt.get("ip.src", "")
        dst_ip = pkt.get("ip.dst", "")

        # Determine ports (TCP or UDP)
        src_port = pkt.get("tcp.srcport", "") or pkt.get("udp.srcport", "")
        dst_port = pkt.get("tcp.dstport", "") or pkt.get("udp.dstport", "")

        if src_ip and dst_ip and dst_port:
            # Normalize: always show client -> server direction
            conv_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            conv_counter[conv_key] += 1

    # Build results, sorted by packet count descending
    conversations: list[dict[str, Any]] = []
    for conv_key, count in conv_counter.most_common(20):
        conversations.append({
            "flow": conv_key,
            "packet_count": count,
        })

    return conversations


def _analyze_tcp_flags(packets: list[dict[str, str]]) -> dict[str, Any]:
    """Analyze TCP flag patterns in the capture.

    Identifies handshake patterns (SYN, SYN-ACK, ACK) and teardown (FIN).

    Args:
        packets: List of packet dicts.

    Returns:
        Dictionary with flag counts and handshake description.
    """
    flag_counts: Counter[str] = Counter()
    handshake_phases: list[str] = []
    seen_phases: set[str] = set()

    for pkt in packets:
        flags_str = pkt.get("tcp.flags.str", "").strip()
        if not flags_str:
            continue

        # tshark flags format varies; normalize
        flags_upper = flags_str.upper()
        flag_counts[flags_str] += 1

        # Track handshake phases (in order of first occurrence)
        if "SYN" in flags_upper and "ACK" not in flags_upper:
            phase = "SYN (connection initiation)"
            if phase not in seen_phases:
                handshake_phases.append(phase)
                seen_phases.add(phase)
        elif "SYN" in flags_upper and "ACK" in flags_upper:
            phase = "SYN-ACK (connection accepted)"
            if phase not in seen_phases:
                handshake_phases.append(phase)
                seen_phases.add(phase)
        elif "FIN" in flags_upper:
            phase = "FIN (connection teardown)"
            if phase not in seen_phases:
                handshake_phases.append(phase)
                seen_phases.add(phase)
        elif "RST" in flags_upper:
            phase = "RST (connection reset)"
            if phase not in seen_phases:
                handshake_phases.append(phase)
                seen_phases.add(phase)
        elif "ACK" in flags_upper and "SYN" not in flags_upper:
            phase = "ACK (acknowledgment)"
            if phase not in seen_phases:
                handshake_phases.append(phase)
                seen_phases.add(phase)
        elif "PSH" in flags_upper:
            phase = "PSH-ACK (data transfer)"
            if phase not in seen_phases:
                handshake_phases.append(phase)
                seen_phases.add(phase)

    return {
        "flag_counts": dict(flag_counts.most_common()),
        "handshake_phases": handshake_phases,
        "description": (
            "TCP uses a three-way handshake (SYN -> SYN-ACK -> ACK) to "
            "establish connections, PSH-ACK for data transfer, and "
            "FIN-ACK to tear down connections gracefully."
        ),
    }


def _packet_size_stats(packets: list[dict[str, str]]) -> dict[str, Any]:
    """Calculate packet size statistics.

    Args:
        packets: List of packet dicts.

    Returns:
        Dictionary with min, max, average packet sizes.
    """
    sizes: list[int] = []

    for pkt in packets:
        try:
            size = int(pkt.get("frame.len", "0"))
            if size > 0:
                sizes.append(size)
        except ValueError:
            continue

    if not sizes:
        return {"min": 0, "max": 0, "average": 0, "total_bytes": 0}

    return {
        "min": min(sizes),
        "max": max(sizes),
        "average": round(sum(sizes) / len(sizes), 1),
        "total_bytes": sum(sizes),
    }


def format_analysis_summary(analysis: dict[str, Any]) -> str:
    """Format analysis results as a human-readable summary string.

    Args:
        analysis: Analysis dict from analyze_capture().

    Returns:
        Formatted multi-line string.
    """
    lines: list[str] = []

    total = analysis.get("total_packets", 0)
    lines.append(f"  Total packets        : {total}")

    stats = analysis.get("protocol_stats", {})
    lines.append(f"  TCP packets          : {stats.get('tcp', 0)}")
    lines.append(f"  UDP packets          : {stats.get('udp', 0)}")
    lines.append(f"  HTTP-related packets : {stats.get('http', 0)}")

    ips = analysis.get("unique_ips", {})
    lines.append(f"  Unique source IPs    : {ips.get('source_count', 0)}")
    lines.append(f"  Unique dest IPs      : {ips.get('destination_count', 0)}")

    size_stats = analysis.get("packet_size_stats", {})
    lines.append(f"  Total bytes          : {size_stats.get('total_bytes', 0)}")
    lines.append(f"  Avg packet size      : {size_stats.get('average', 0)} bytes")

    # Conversations
    conversations = analysis.get("conversations", [])
    if conversations:
        lines.append("")
        lines.append("  Top conversations:")
        for conv in conversations[:5]:
            lines.append(f"    {conv['flow']}  ({conv['packet_count']} pkts)")

    # TCP behavior
    tcp = analysis.get("tcp_behavior", {})
    phases = tcp.get("handshake_phases", [])
    if phases:
        lines.append("")
        lines.append("  TCP behavior observed:")
        for phase in phases:
            lines.append(f"    - {phase}")

    return "\n".join(lines)
