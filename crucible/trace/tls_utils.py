"""TLS utilities for the crucible trace proxy.

Two public functions:

* :func:`build_ssl_context` — load an existing cert/key pair into a server
  ``ssl.SSLContext``.
* :func:`generate_self_signed` — generate an RSA 2048 key + self-signed x509
  certificate using the ``cryptography`` package (already a transitive dep via
  ``google-auth``).  Returns paths to PEM files written into *tmpdir*.

The ``cryptography`` package is **not** listed in ``pyproject.toml``
dependencies because it is already pulled in transitively.  Both functions use
only stdlib ``ssl`` for the final ``SSLContext`` construction so that the
import of ``cryptography`` can be deferred to ``generate_self_signed`` only.
"""

from __future__ import annotations

import datetime
import ipaddress
import ssl
import tempfile
from pathlib import Path


def build_ssl_context(cert: Path, key: Path) -> ssl.SSLContext:
    """Create a server-side ``ssl.SSLContext`` from *cert* and *key* PEM files.

    Args:
        cert: Path to the PEM certificate file.
        key:  Path to the PEM private key file (may be the same file as *cert*
              if the cert file contains both).

    Returns:
        A configured :class:`ssl.SSLContext` ready to pass to
        ``anyio.streams.tls.TLSListener``.

    Raises:
        FileNotFoundError: if *cert* or *key* do not exist.
        ssl.SSLError: if the certificate or key is invalid / mismatched.
    """
    if not cert.exists():
        raise FileNotFoundError(f"TLS certificate not found: {cert}")
    if not key.exists():
        raise FileNotFoundError(f"TLS private key not found: {key}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


def generate_self_signed(tmpdir: Path | None = None) -> tuple[Path, Path]:
    """Generate a self-signed RSA 2048 certificate for development / testing.

    Uses the ``cryptography`` package which is already a transitive dependency
    of crucible (pulled in by ``google-auth``).

    Args:
        tmpdir: Directory to write the generated PEM files into.  If *None*, a
                fresh ``tempfile.mkdtemp()`` directory is used — the caller is
                responsible for cleanup.

    Returns:
        ``(cert_path, key_path)`` — both are PEM files inside *tmpdir*.

    Raises:
        ImportError: if ``cryptography`` is somehow not installed.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "The 'cryptography' package is required for --tls-self-signed. "
            "Install it with: pip install cryptography"
        ) from exc

    if tmpdir is None:
        tmpdir = Path(tempfile.mkdtemp(prefix="crucible_tls_"))
    tmpdir.mkdir(parents=True, exist_ok=True)

    # --- Generate RSA 2048 private key ---
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # --- Build x509 certificate ---
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "crucible-trace-proxy"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Crucible Security"),
        ]
    )

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # --- Write PEM files ---
    key_path = tmpdir / "crucible_tls.key"
    cert_path = tmpdir / "crucible_tls.crt"

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path
