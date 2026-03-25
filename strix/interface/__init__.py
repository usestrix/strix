from typing import Any


def main(*args: Any, **kwargs: Any) -> Any:
    from .main import main as interface_main

    return interface_main(*args, **kwargs)


__all__ = ["main"]
