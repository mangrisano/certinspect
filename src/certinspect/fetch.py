"""Retrieve the certificate from a TLS server.

Connect to a host:port over TLS and obtain the server certificate in DER
format (bytes) together with basic connection info (negotiated TLS version
and cipher).

Hostname checking and verification are disabled on purpose: this tool must
be able to inspect expired or self-signed certificates without the
connection failing. Validity is computed later in parser.py.
"""

import socket
import ssl


def get_server_cert(
    host: str, port: int = 443, timeout: float = 5.0
) -> tuple[bytes, dict]:
    """Return the server certificate (DER bytes) and connection info.

    The connection info is a dict with the negotiated ``tls_version`` and
    ``cipher`` suite name.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            conn = {
                "tls_version": ssock.version(),
                "cipher": cipher[0] if cipher else None,
            }
            return der, conn
