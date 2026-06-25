"""
fetch.py — Retrieving the certificate from the TLS server.

Connect to a host:port over TLS and obtain the server certificate in DER
format (bytes), ready to be parsed in parser.py.

Hostname checking and verification are disabled on purpose: this tool must
be able to inspect expired or self-signed certificates without the
connection failing. Validity is computed later in parser.py.
"""

import socket
import ssl


def get_server_cert_der(host: str, port: int = 443, timeout: float = 5.0) -> bytes:
    """Return the server certificate in DER format (bytes)."""

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)
