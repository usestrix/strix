"""User interfaces for Strix.

Keep package import lightweight: the MCP service reuses target utilities and
must not initialize the legacy model stack during stdio startup.
"""


def main() -> None:
    """Load and run the CLI entry point lazily."""
    from .main import main as run

    run()


__all__ = ["main"]
