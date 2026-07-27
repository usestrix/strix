"""Shared TLS context for stdlib ``urllib`` callers.

``ssl.create_default_context`` loads CA roots from OpenSSL's compiled-in
default paths. In frozen (PyInstaller) builds those paths point at the build
machine's Python installation, which does not exist on end-user machines, so
the default context verifies against an empty store and every HTTPS request
fails. ``certifi`` ships a CA bundle inside the binary; fall back to it
whenever the platform store yields no CA certificates.
"""

from __future__ import annotations

import ssl

import certifi


_context: ssl.SSLContext | None = None


def tls_context() -> ssl.SSLContext:
    """A default TLS context, backed by certifi when the OS store is empty."""
    global _context  # noqa: PLW0603
    if _context is None:
        context = ssl.create_default_context()
        if context.cert_store_stats().get("x509_ca", 0) == 0:
            context = ssl.create_default_context(cafile=certifi.where())
        _context = context
    return _context


__all__ = ["tls_context"]
