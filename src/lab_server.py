#!/usr/bin/env python3
"""
lab_server.py — Autopilot Lab Environment.

Starts safe, localhost-only services for the scanning lab:
    - HTTP server on a configurable port (default 8080)
    - TCP echo listener on a configurable port (default 9090)

Both services bind exclusively to 127.0.0.1 and run as daemon threads
so they shut down when the main process exits.
"""

import http.server
import logging
import socket
import threading
import time
from typing import Optional

logger = logging.getLogger("cli_network_scanner.lab_server")


# ---------------------------------------------------------------------------
# HTTP Server
# ---------------------------------------------------------------------------

class _LabHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP handler that serves a lab status page."""

    def do_GET(self) -> None:
        """Respond to GET requests with the lab status page."""
        body = (
            "<!DOCTYPE html>\n"
            "<html><head><title>CLI Network Scanner Lab</title></head>\n"
            "<body>\n"
            "<h1>CLI Network Scanner Lab</h1>\n"
            "<p><strong>Status:</strong> Running</p>\n"
            "<p><strong>Purpose:</strong> Authorized Local Security Testing</p>\n"
            "</body></html>\n"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Suppress default stderr logging; use structured logger instead."""
        logger.debug("HTTP %s", format % args)


class LabHTTPServer:
    """Localhost-only HTTP server running in a background thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.host = host
        self.port = port
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the HTTP server in a daemon thread."""
        self._server = http.server.HTTPServer(
            (self.host, self.port), _LabHTTPHandler
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="lab-http-server",
            daemon=True,
        )
        self._thread.start()
        logger.info("HTTP server started on %s:%d", self.host, self.port)

    def stop(self) -> None:
        """Shut down the HTTP server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            logger.info("HTTP server stopped")
            self._server = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ---------------------------------------------------------------------------
# TCP Echo Listener
# ---------------------------------------------------------------------------

class LabTCPListener:
    """Localhost-only TCP listener that echoes a simple response."""

    RESPONSE = (
        b"CLI Network Scanner Lab - TCP Listener\r\n"
        b"Status: Active\r\n"
        b"Purpose: Authorized Local Security Testing\r\n"
    )

    def __init__(self, host: str = "127.0.0.1", port: int = 9090) -> None:
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        """Start the TCP listener in a daemon thread."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)  # allow periodic shutdown checks
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._running = True

        self._thread = threading.Thread(
            target=self._accept_loop,
            name="lab-tcp-listener",
            daemon=True,
        )
        self._thread.start()
        logger.info("TCP listener started on %s:%d", self.host, self.port)

    def _accept_loop(self) -> None:
        """Accept connections and send the lab response."""
        while self._running:
            try:
                conn, addr = self._sock.accept()
                with conn:
                    logger.debug("TCP connection from %s:%d", *addr)
                    conn.sendall(self.RESPONSE)
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.exception("TCP listener error")
                break

    def stop(self) -> None:
        """Shut down the TCP listener."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            logger.info("TCP listener stopped")
            self._sock = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ---------------------------------------------------------------------------
# Combined Lab Manager
# ---------------------------------------------------------------------------

class LabEnvironment:
    """Manages the complete lab environment lifecycle."""

    def __init__(
        self,
        http_port: int = 8080,
        tcp_port: int = 9090,
        host: str = "127.0.0.1",
    ) -> None:
        self.host = host
        self.http_server = LabHTTPServer(host=host, port=http_port)
        self.tcp_listener = LabTCPListener(host=host, port=tcp_port)
        self.http_port = http_port
        self.tcp_port = tcp_port

    def start(self) -> dict[str, str]:
        """Start all lab services.

        Returns:
            Dict describing the started services.

        Raises:
            OSError: If a port is already in use.
        """
        results: dict[str, str] = {}

        try:
            self.http_server.start()
            results["http"] = f"{self.host}:{self.http_port}"
        except OSError as exc:
            results["http_error"] = str(exc)
            logger.error("Failed to start HTTP server: %s", exc)

        try:
            self.tcp_listener.start()
            results["tcp"] = f"{self.host}:{self.tcp_port}"
        except OSError as exc:
            results["tcp_error"] = str(exc)
            logger.error("Failed to start TCP listener: %s", exc)

        # Brief pause to allow threads to initialize
        time.sleep(0.3)
        return results

    def stop(self) -> None:
        """Stop all lab services."""
        self.http_server.stop()
        self.tcp_listener.stop()
        logger.info("Lab environment stopped")

    def get_services_info(self) -> list[dict[str, object]]:
        """Return structured info about lab services."""
        return [
            {
                "service": "HTTP Server",
                "host": self.host,
                "port": self.http_port,
                "status": "running" if self.http_server.is_running else "stopped",
            },
            {
                "service": "TCP Listener",
                "host": self.host,
                "port": self.tcp_port,
                "status": "running" if self.tcp_listener.is_running else "stopped",
            },
        ]
