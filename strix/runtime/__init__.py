from strix.config import Config

from .runtime import AbstractRuntime


class SandboxInitializationError(Exception):
    """Raised when sandbox initialization fails (e.g., Docker issues)."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


_global_runtime: AbstractRuntime | None = None


def get_runtime() -> AbstractRuntime:
    global _global_runtime  # noqa: PLW0603

    runtime_backend = Config.get("strix_runtime_backend")

    if runtime_backend == "docker":
        from .docker_runtime import DockerRuntime

        if _global_runtime is None:
            _global_runtime = DockerRuntime()
        return _global_runtime

    raise ValueError(
        f"Unsupported runtime backend: {runtime_backend}. Only 'docker' is supported for now."
    )


def cleanup_runtime() -> None:
    global _global_runtime  # noqa: PLW0603

    if _global_runtime is not None:
        _global_runtime.cleanup()
        _global_runtime = None


__all__ = ["AbstractRuntime", "SandboxInitializationError", "cleanup_runtime", "get_runtime"]
