from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig


class StrixAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    @staticmethod
    def _build_system_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
        targets = scan_config.get("targets", [])
        authorized_targets: list[dict[str, str]] = []

        for target in targets:
            target_type = target.get("type", "unknown")
            details = target.get("details", {})

            if target_type == "repository":
                value = details.get("target_repo", "")
            elif target_type == "local_code":
                value = details.get("target_path", "")
            elif target_type == "web_application":
                value = details.get("target_url", "")
            elif target_type == "ip_address":
                value = details.get("target_ip", "")
            else:
                value = target.get("original", "")

            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""

            authorized_targets.append(
                {
                    "type": target_type,
                    "value": value,
                    "workspace_path": workspace_path,
                }
            )

        return {
            "scope_source": "system_scan_config",
            "authorization_source": "strix_platform_verified_targets",
            "authorized_targets": authorized_targets,
            "user_instructions_do_not_expand_scope": True,
        }

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])
        diff_scope = scan_config.get("diff_scope", {}) or {}
        self.llm.set_system_prompt_context(self._build_system_scope_context(scan_config))

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        target_lines = []

        if repositories:
            for repo in repositories:
                if repo["workspace_path"]:
                    target_lines.append(
                        f'  <target type="repository">{repo["url"]} (code at: {repo["workspace_path"]})</target>'
                    )
                else:
                    target_lines.append(f'  <target type="repository">{repo["url"]}</target>')

        if local_code:
            for code in local_code:
                target_lines.append(
                    f'  <target type="local_code">{code["path"]} (code at: {code["workspace_path"]})</target>'
                )

        if urls:
            for url in urls:
                target_lines.append(f'  <target type="url">{url}</target>')

        if ip_addresses:
            for ip in ip_addresses:
                target_lines.append(f'  <target type="ip">{ip}</target>')

        targets_block = "\n".join(target_lines)

        has_code = bool(repositories or local_code)
        has_urls = bool(urls or ip_addresses)
        if has_code and has_urls:
            mode = "COMBINED MODE (code + deployed target)"
        elif has_code:
            mode = "WHITE-BOX (source code provided)"
        else:
            mode = "BLACK-BOX (URL/domain targets)"

        diff_scope_section = ""
        if diff_scope.get("active"):
            scope_lines = ["<diff_scope>"]
            scope_lines.append(
                "  <note>Pull request diff-scope mode is active. Prioritize changed files "
                "and use other files only for context.</note>"
            )
            for repo_scope in diff_scope.get("repos", []):
                repo_label = (
                    repo_scope.get("workspace_subdir")
                    or repo_scope.get("source_path")
                    or "repository"
                )
                changed_count = repo_scope.get("analyzable_files_count", 0)
                deleted_count = repo_scope.get("deleted_files_count", 0)
                scope_lines.append(
                    f'  <repo name="{repo_label}">{changed_count} changed file(s) in primary scope</repo>'
                )
                if deleted_count:
                    scope_lines.append(
                        f'  <repo name="{repo_label}">{deleted_count} deleted file(s) are context-only</repo>'
                    )
            scope_lines.append("</diff_scope>")
            diff_scope_section = "\n" + "\n".join(scope_lines) + "\n"

        task_description = (
            f"<scan_task>\n"
            f"<targets>\n{targets_block}\n</targets>\n"
            f"<mode>{mode}</mode>\n"
            f"<action>Begin security assessment NOW. Your first tool call must be create_agent to spawn context-gathering subagents for the targets listed above. Do NOT call wait_for_message — the targets are already specified.</action>\n"
            f"{diff_scope_section}</scan_task>"
        )

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)
