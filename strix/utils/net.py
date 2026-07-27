from __future__ import annotations

import ssl

import certifi


_context: ssl.SSLContext | None = None


def tls_context() -> ssl.SSLContext:
    global _context  # noqa: PLW0603
    if _context is None:
        context = ssl.create_default_context()
        if context.cert_store_stats().get("x509_ca", 0) == 0:
            context = ssl.create_default_context(cafile=certifi.where())
        _context = context
    return _context


__all__ = ["tls_context"]
