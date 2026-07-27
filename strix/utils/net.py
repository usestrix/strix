"""Shared TLS context for stdlib ``urllib`` callers.

``ssl.create_default_context`` loads CA roots from OpenSSL's compiled-in default
paths. In the frozen PyInstaller standalone build those paths point at the build
machine's Python installation, which doesn't exist on the end user's machine, so
the default context verifies against an *empty* trust store and every external
HTTPS request dies with ``CERTIFICATE_VERIFY_FAILED: unable to get local issuer
certificate``.

Prefer the platform trust store — it carries any corporate/MITM root CAs the
user has installed — and fall back to certifi's bundled CA store only when the
platform store is empty (i.e. the frozen-build case). Libraries like
``requests``/``httpx`` already trust certifi; this brings raw ``urllib`` in line.
"""

from __future__ import annotations

import ssl

import certifi


_context: ssl.SSLContext | None = None


def tls_context() -> ssl.SSLContext:
    """A default-verifying TLS context, backed by certifi when the OS store is empty.

    Built once and cached: the trust store doesn't change over a process's
    lifetime, and loading the CA bundle on every request would be wasteful.
    """
    global _context  # noqa: PLW0603
    if _context is None:
        context = ssl.create_default_context()
        if context.cert_store_stats().get("x509_ca", 0) == 0:
            context = ssl.create_default_context(cafile=certifi.where())
        _context = context
    return _context


__all__ = ["tls_context"]
