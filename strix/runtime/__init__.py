from strix.config import Config

from .runtime import AbstractRuntime


class SandboxInitializationError(Exception):
    """Raised when sandbox initialization fails (e.g., Docker issues)."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


def get_runtime() -> AbstractRuntime:
    runtime_backend = Config.get("strix_runtime_backend")

    if runtime_backend == "docker":
        from .docker_runtime import DockerRuntime

        return DockerRuntime()

    raise ValueError(
        f"Unsupported runtime backend: {runtime_backend}. Only 'docker' is supported for now."
    )


__all__ = ["AbstractRuntime", "SandboxInitializationError", "get_runtime"]
