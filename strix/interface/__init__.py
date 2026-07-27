from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .main import main


__all__ = ["main"]


def __getattr__(name: str) -> object:
    if name == "main":
        from .main import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
