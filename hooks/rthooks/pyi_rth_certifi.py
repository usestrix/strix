"""PyInstaller runtime hook: point SSL env vars at the bundled certifi CA file.

Without ``collect_data_files('certifi')`` and this hook, a frozen binary can
resolve ``certifi.where()`` to a missing path and fail TLS verification with a
generic ``Connection error`` from httpx/litellm.
"""

from __future__ import annotations

import sys


if getattr(sys, "frozen", False):
    import os

    import certifi

    ca_bundle = certifi.where()
    os.environ.setdefault("SSL_CERT_FILE", ca_bundle)
    os.environ.setdefault("REQUESTS_CA_BUNDLE", ca_bundle)
