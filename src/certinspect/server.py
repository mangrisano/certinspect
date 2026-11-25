"""Standalone Prometheus HTTP metrics server for ``--serve-metrics``.

Exposes ``/metrics`` (Prometheus text format) and ``/healthz`` over a
threaded stdlib HTTP server with TTL caching so Prometheus scrapes never
trigger a storm of live TLS handshakes.
"""

import http.server
import signal
import socket
import sys
import threading
import time
from collections.abc import Callable

_PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
_CLIENT_SOCKET_TIMEOUT_SECONDS = 10.0


def parse_listen_address(spec: str) -> tuple[str, int]:
    """Parse ``[host]:port``, ``host:port``, ``:port``, or ``port``.

    A bare port or ``:port`` binds ``127.0.0.1`` by default; pass
    ``0.0.0.0:9117`` explicitly to listen on all interfaces. IPv6 literals
    must be enclosed in square brackets (e.g. ``[::1]:9117``).
    Raises ``ValueError`` on malformed input or out-of-range ports.
    """
    raw = spec.strip()
    if not raw:
        raise ValueError("listen address must not be empty")
    if raw.startswith("["):
        host, sep, rest = raw[1:].partition("]")
        if not host or not sep or not rest.startswith(":"):
            raise ValueError(f"invalid IPv6 listen address: {spec!r}")
        port_str = rest[1:]
    elif ":" in raw:
        host, port_str = raw.rsplit(":", 1)
        if ":" in host:
            raise ValueError(f"IPv6 address must be enclosed in brackets: {spec!r}")
        host = host or "127.0.0.1"
    else:
        host, port_str = "127.0.0.1", raw
    try:
        port = int(port_str)
    except ValueError as err:
        raise ValueError(f"invalid port in listen address: {spec!r}") from err
    if not (1 <= port <= 65535):
        raise ValueError(f"port out of range (1-65535): {port}")
    return host, port


class MetricsCache:
    """Thread-safe TTL cache wrapping a metrics collection callback."""

    def __init__(self, collect: Callable[[], str], interval: float) -> None:
        self._collect = collect
        self._interval = interval
        self._lock = threading.Lock()
        self._payload: str | None = None
        self._updated_at: float = 0.0

    def get(self) -> str:
        """Return cached metrics, refreshing when stale or empty."""
        with self._lock:
            now = time.monotonic()
            if self._payload is None or (now - self._updated_at) >= self._interval:
                self._payload = self._collect()
                self._updated_at = time.monotonic()
            return self._payload


class _Shutdown(BaseException):
    """Raised by the SIGTERM handler to unwind serve_forever() cleanly."""


class _MetricsHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


class _IPv6MetricsHTTPServer(_MetricsHTTPServer):
    address_family = socket.AF_INET6


def create_metrics_server(
    listen: str,
    collect: Callable[[], str],
    interval: float = 300.0,
) -> http.server.ThreadingHTTPServer:
    """Create (without starting) a ``ThreadingHTTPServer`` serving ``/metrics``."""
    host, port = parse_listen_address(listen)
    cache = MetricsCache(collect, interval)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def setup(self) -> None:
            self.request.settimeout(_CLIENT_SOCKET_TIMEOUT_SECONDS)
            super().setup()

        def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                return

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._send_bytes(200, "text/plain; charset=utf-8", b"ok\n")
                return
            if path == "/metrics":
                try:
                    body = cache.get().encode("utf-8")
                except Exception as err:
                    print(
                        f"error: metrics collection failed: {err}",
                        file=sys.stderr,
                    )
                    self._send_bytes(
                        500,
                        "text/plain; charset=utf-8",
                        b"metrics collection failed\n",
                    )
                    return
                self._send_bytes(200, _PROMETHEUS_CONTENT_TYPE, body)
                return
            self._send_bytes(404, "text/plain; charset=utf-8", b"Not Found\n")

        def log_message(self, format: str, *args: object) -> None:
            return

    server_cls = _IPv6MetricsHTTPServer if ":" in host else _MetricsHTTPServer
    return server_cls((host, port), _Handler)


def serve_metrics(
    listen: str,
    collect: Callable[[], str],
    interval: float = 300.0,
) -> None:
    """Start the Prometheus HTTP exporter and block until SIGINT/SIGTERM."""
    server = create_metrics_server(listen, collect, interval=interval)
    host, port = server.server_address[:2]
    host_str = host.decode("ascii", "replace") if isinstance(host, bytes) else host
    display_host = f"[{host_str}]" if ":" in host_str else host_str
    print(
        f"certinspect metrics server listening on http://{display_host}:{port}/metrics "
        f"(refresh interval: {interval:g}s)",
        file=sys.stderr,
    )

    prev_sigterm = None
    if threading.current_thread() is threading.main_thread():

        def _handle_sigterm(_signum: int, _frame: object) -> None:
            raise _Shutdown

        prev_sigterm = signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        server.serve_forever()
    except (KeyboardInterrupt, _Shutdown):
        pass
    finally:
        if prev_sigterm is not None:
            signal.signal(signal.SIGTERM, prev_sigterm)
        server.server_close()
