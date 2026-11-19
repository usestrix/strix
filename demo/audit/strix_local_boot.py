"""Stand-in for the ``strix_local_boot`` module baked into the orchestrator image.

``k8s/kafka_orchestrator.py`` imports it before anything from Strix. In the image
it prepares the in-pod sandbox; on a dev machine Strix uses the Docker backend
(STRIX_RUNTIME_BACKEND=docker), which needs no preparation, so this is a no-op.
Put this directory on PYTHONPATH (demo/run-audit-local.sh does).
"""


def initialize_local_environment() -> None:
    return None
