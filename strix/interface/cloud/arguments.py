"""Argument parsing that reports managed-cloud usage errors through one contract."""

from __future__ import annotations

import argparse
from typing import NoReturn

import strix.interface.cloud.http as http  # noqa: PLR0402


class CloudArgumentParser(argparse.ArgumentParser):
    """Raise a typed usage error instead of printing argparse prose and exiting."""

    def error(self, message: str) -> NoReturn:
        raise http.CloudError(
            f"invalid arguments for {self.prog}: {message}",
            exit_code=http.EXIT_USAGE,
        )
