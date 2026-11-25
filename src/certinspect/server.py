"""Standalone Prometheus HTTP metrics server for ``--serve-metrics``.

Exposes ``/metrics`` (Prometheus text format) and ``/healthz`` over a
threaded stdlib HTTP server with TTL caching so Prometheus scrapes never
trigger a storm of live TLS handshakes.
"""

import http.server
import sys
import threading
import time
from collections.abc import Callable

_PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def parse_listen_address(spec: str) -> tuple[str, int]:
    """Parse ``[host]:port``, ``host:port``, ``:port``, or ``port``.

    A bare port or ``:port`` binds ``127.0.0.1`` by default; pass
    ``0.0.0.0:9117`` explicitly to listen on all interfaces.
    Raises ``ValueError`` on malformed input or out-of-range ports.
    """
    raw = spec.strip()
    if not raw:
        raise ValueError("listen address must not be empty")
    if raw.startswith("["):
        host, sep, rest = raw[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ValueError(f"invalid IPv6 listen address: {spec!r}")
        port_str = rest[1:]
    elif ":" in raw:
        host, port_str = raw.rsplit(":", 1)
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
        now = time.monotonic()
        with self._lock:
            if self._payload is None or (now - self._updated_at) >= self._interval:
                self._payload = self._collect()
                self._updated_at = time.monotonic()
            return self._payload


def create_metrics_server(
    listen: str,
    collect: Callable[[], str],
    interval: float = 300.0,
) -> http.server.ThreadingHTTPServer:
    """Create (without starting) a ``ThreadingHTTPServer`` serving ``/metrics``."""
    host, port = parse_listen_address(listen)
    cache = MetricsCache(collect, interval)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                body = b"ok\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/metrics":
                body = cache.get().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", _PROMETHEUS_CONTENT_TYPE)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404, "Not Found")

        def log_message(self, format: str, *args: object) -> None:
            return

    return http.server.ThreadingHTTPServer((host, port), _Handler)


def serve_metrics(
    listen: str,
    collect: Callable[[], str],
    interval: float = 300.0,
) -> None:
    """Start the Prometheus HTTP exporter and block until interrupted."""
    server = create_metrics_server(listen, collect, interval=interval)
    host, port = server.server_address[:2]
    host_str = host.decode("ascii", "replace") if isinstance(host, bytes) else host
    print(
        f"certinspect metrics server listening on http://{host_str}:{port}/metrics "
        f"(refresh interval: {interval:g}s)",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
