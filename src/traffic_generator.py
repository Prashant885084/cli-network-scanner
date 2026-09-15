#!/usr/bin/env python3
"""
traffic_generator.py — Harmless Lab Traffic Generator.

Generates safe HTTP and TCP traffic against local lab services so that
packet capture has meaningful data to analyze.

All traffic remains on 127.0.0.1 — nothing is sent to external hosts.
"""

import logging
import socket
import time
import urllib.request
import urllib.error
from typing import Any

logger = logging.getLogger("cli_network_scanner.traffic_generator")


def generate_http_traffic(
    host: str = "127.0.0.1",
    port: int = 8080,
    request_count: int = 5,
    delay: float = 0.3,
) -> dict[str, Any]:
    """Send HTTP GET requests to the lab HTTP server.

    Args:
        host: Target host (must be localhost).
        port: Target port.
        request_count: Number of requests to send.
        delay: Delay between requests in seconds.

    Returns:
        Dictionary with success_count, error_count, and details.
    """
    url = f"http://{host}:{port}/"
    results: dict[str, Any] = {
        "type": "http",
        "target": f"{host}:{port}",
        "success_count": 0,
        "error_count": 0,
        "responses": [],
    }

    for i in range(request_count):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CLI-Network-Scanner-Lab/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
                content_length = len(resp.read())
                results["success_count"] += 1
                results["responses"].append({
                    "request": i + 1,
                    "status": status,
                    "content_length": content_length,
                })
                logger.debug("HTTP request %d: status %d", i + 1, status)
        except urllib.error.URLError as exc:
            results["error_count"] += 1
            logger.warning("HTTP request %d failed: %s", i + 1, exc)
        except Exception as exc:
            results["error_count"] += 1
            logger.warning("HTTP request %d error: %s", i + 1, exc)

        if i < request_count - 1:
            time.sleep(delay)

    logger.info(
        "HTTP traffic: %d success, %d errors",
        results["success_count"],
        results["error_count"],
    )
    return results


def generate_tcp_traffic(
    host: str = "127.0.0.1",
    port: int = 9090,
    connection_count: int = 3,
    delay: float = 0.5,
) -> dict[str, Any]:
    """Open TCP connections to the lab TCP listener.

    Args:
        host: Target host (must be localhost).
        port: Target port.
        connection_count: Number of connections to make.
        delay: Delay between connections in seconds.

    Returns:
        Dictionary with success_count, error_count, and received data.
    """
    results: dict[str, Any] = {
        "type": "tcp",
        "target": f"{host}:{port}",
        "success_count": 0,
        "error_count": 0,
        "responses": [],
    }

    for i in range(connection_count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((host, port))

                # Send a simple message
                sock.sendall(b"HELLO FROM LAB CLIENT\r\n")

                # Receive response
                data = sock.recv(4096)
                response_text = data.decode("utf-8", errors="replace").strip()

                results["success_count"] += 1
                results["responses"].append({
                    "connection": i + 1,
                    "bytes_received": len(data),
                    "response_preview": response_text[:100],
                })
                logger.debug("TCP connection %d: received %d bytes", i + 1, len(data))

        except (ConnectionRefusedError, socket.timeout) as exc:
            results["error_count"] += 1
            logger.warning("TCP connection %d failed: %s", i + 1, exc)
        except Exception as exc:
            results["error_count"] += 1
            logger.warning("TCP connection %d error: %s", i + 1, exc)

        if i < connection_count - 1:
            time.sleep(delay)

    logger.info(
        "TCP traffic: %d success, %d errors",
        results["success_count"],
        results["error_count"],
    )
    return results


def generate_all_traffic(
    host: str = "127.0.0.1",
    http_port: int = 8080,
    tcp_port: int = 9090,
) -> dict[str, Any]:
    """Generate both HTTP and TCP traffic for the lab.

    Args:
        host: Target host.
        http_port: HTTP server port.
        tcp_port: TCP listener port.

    Returns:
        Combined traffic generation results.
    """
    logger.info("Generating lab traffic against %s", host)

    http_results = generate_http_traffic(host=host, port=http_port)
    tcp_results = generate_tcp_traffic(host=host, port=tcp_port)

    return {
        "http": http_results,
        "tcp": tcp_results,
        "total_success": http_results["success_count"] + tcp_results["success_count"],
        "total_errors": http_results["error_count"] + tcp_results["error_count"],
    }
