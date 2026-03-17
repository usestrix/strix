from typing import Any


_agent_instances: dict[str, Any] = {}


def register_agent_instance(agent_id: str, agent: Any) -> None:
    if not agent_id:
        return
    _agent_instances[agent_id] = agent


def unregister_agent_instance(agent_id: str) -> None:
    if not agent_id:
        return
    _agent_instances.pop(agent_id, None)


def get_agent_instance(agent_id: str) -> Any | None:
    if not agent_id:
        return None
    return _agent_instances.get(agent_id)
