"""Main CLI Entry Point for Strix Hub."""

from __future__ import annotations

import argparse
import logging
import sys

from strix_hub.server import serve


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Strix Hub — Multi-Tenant Web Task & Model Control Platform")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", "-p", type=int, default=8888, help="Port to listen on (default: 8888)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    serve(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
