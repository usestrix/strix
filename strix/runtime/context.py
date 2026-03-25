from dataclasses import dataclass

_UNSET = object()


@dataclass
class RuntimeContext:
    sandbox_mode: bool = False
    caido_api_token: str | None = None


_runtime_context = RuntimeContext()


def configure_runtime_context(
    *,
    sandbox_mode: bool | None = None,
    caido_api_token: str | None | object = _UNSET,
) -> None:
    if sandbox_mode is not None:
        _runtime_context.sandbox_mode = sandbox_mode
    if caido_api_token is not _UNSET:
        _runtime_context.caido_api_token = caido_api_token


def is_sandbox_mode() -> bool:
    return _runtime_context.sandbox_mode


def get_caido_api_token() -> str | None:
    return _runtime_context.caido_api_token
