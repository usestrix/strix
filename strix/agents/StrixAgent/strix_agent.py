from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig


class StrixAgent(BaseAgent):
    max_iterations = 200

    def __init__(self, config: dict[str, Any]):
        default_modules = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_modules = ["root_agent"]

        self.default_llm_config = LLMConfig(prompt_modules=default_modules)

        super().__init__(config)

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:
        scan_type = scan_config.get("scan_type", "general")
        target = scan_config.get("target", {})
        user_instructions = scan_config.get("user_instructions", "")

        task_parts = []

        if scan_type == "repository":
            repo_url = target["target_repo"]
            cloned_path = target.get("cloned_repo_path")

            if cloned_path:
                workspace_path = "/workspace"
                task_parts.append(
                    f"Perform a security assessment of the Git repository: {repo_url}. "
                    f"The repository has been cloned from '{repo_url}' to '{cloned_path}' "
                    f"(host path) and then copied to '{workspace_path}' in your environment."
                    f"Analyze the codebase at: {workspace_path}"
                )
            else:
                task_parts.append(
                    f"Perform a security assessment of the Git repository: {repo_url}"
                )

        elif scan_type == "web_application":
            task_parts.append(
                f"Perform a security assessment of the web application: {target['target_url']}"
            )

        elif scan_type == "local_code":
            original_path = target.get("target_path", "unknown")
            workspace_path = "/workspace"
            task_parts.append(
                f"Perform a security assessment of the local codebase. "
                f"The code from '{original_path}' (user host path) has been copied to "
                f"'{workspace_path}' in your environment. "
                f"Analyze the codebase at: {workspace_path}"
            )

        else:
            task_parts.append(
                f"Perform a general security assessment of: {next(iter(target.values()))}"
            )

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += (
                f"\n\nSpecial instructions from the user that must be followed: {user_instructions}"
            )

        return await self.agent_loop(task=task_description)
