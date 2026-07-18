"""Tool cost estimation and tracking for Strix."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents.tool import (
    ApplyPatchTool,
    ComputerTool,
    CustomTool,
    FileSearchTool,
    FunctionTool,
    HostedMCPTool,
    ImageGenerationTool,
    ShellTool,
    ToolSearchTool,
    WebSearchTool,
)


logger = logging.getLogger(__name__)


@dataclass
class ToolCostEstimate:
    """Estimated cost for a tool execution."""

    tool_name: str
    estimated_cost_usd: float
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


# Default cost estimates per tool type (in USD)
# These are rough estimates based on typical LLM token consumption
# Base costs will be multiplied by scan mode multipliers
TOOL_COST_ESTIMATES: dict[str, float] = {
    # Low-cost tools (simple operations, minimal tokens)
    "think": 0.0001,  # Simple thought recording
    "todo_create": 0.0002,
    "todo_update": 0.0002,
    "todo_mark_complete": 0.0002,
    "note_create": 0.0002,
    "note_update": 0.0002,
    "note_read": 0.0001,
    "agent_pause": 0.0001,
    "agent_resume": 0.0001,
    "send_message_to_agent": 0.0003,
    "wait_for_message": 0.0002,
    "stop_agent": 0.0002,
    "view_agent_graph": 0.0002,
    
    # Medium-cost tools (moderate token usage)
    "shell_execute": 0.001,  # Shell command execution
    "apply_patch": 0.0015,  # Code patching
    "file_search": 0.001,  # File system search
    "code_interpreter": 0.002,  # Code execution
    "image_generation": 0.004,  # Image generation (more expensive)
    "web_search": 0.002,  # Web search via Perplexity
    
    # Higher-cost tools (complex operations)
    "computer_use": 0.003,  # Computer interaction
    "mcp_tool": 0.002,  # MCP tool calls
    "custom_tool": 0.0015,  # Custom tools
    
    # Lifecycle tools
    "finish_scan": 0.0005,
    "agent_finish": 0.0003,
    "create_vulnerability_report": 0.0005,
    "update_vulnerability_report": 0.0003,
}

# Scan mode cost multipliers
# quick: faster, less thorough, lower token usage
# standard: balanced approach
# deep: comprehensive analysis, higher token usage
SCAN_MODE_MULTIPLIERS: dict[str, float] = {
    "quick": 0.5,      # 50% of base cost
    "standard": 1.0,   # Base cost
    "deep": 1.5,       # 150% of base cost
}

# Fallback default cost for unknown tools
DEFAULT_TOOL_COST = 0.0005


class ToolCostTracker:
    """Track tool usage and estimate costs."""

    def __init__(self, run_dir: Path | None = None, scan_mode: str = "deep") -> None:
        self._tool_costs: list[ToolCostEstimate] = []
        self._total_estimated_cost = 0.0
        self._run_dir = run_dir
        self._log_file: Path | None = None
        self._scan_mode = scan_mode
        self._cost_multiplier = SCAN_MODE_MULTIPLIERS.get(scan_mode, 1.0)
        
    def set_run_dir(self, run_dir: Path) -> None:
        """Set the run directory for logging."""
        self._run_dir = run_dir
        self._log_file = run_dir / "tool_costs.jsonl"
        
    def set_scan_mode(self, scan_mode: str) -> None:
        """Set the scan mode to adjust cost estimates."""
        self._scan_mode = scan_mode
        self._cost_multiplier = SCAN_MODE_MULTIPLIERS.get(scan_mode, 1.0)
        logger.info("Tool cost tracker scan mode set to %s (multiplier: %.2f)", 
                   scan_mode, self._cost_multiplier)
        
    def set_run_dir(self, run_dir: Path) -> None:
        """Set the run directory for logging."""
        self._run_dir = run_dir
        self._log_file = run_dir / "tool_costs.jsonl"
        
    def record_tool_usage(
        self,
        tool_name: str,
        agent_id: str | None = None,
        agent_name: str | None = None,
        custom_cost: float | None = None,
    ) -> ToolCostEstimate:
        """Record a tool usage event with cost estimation."""
        # Get cost estimate
        if custom_cost is not None:
            cost = custom_cost
        else:
            base_cost = TOOL_COST_ESTIMATES.get(tool_name, DEFAULT_TOOL_COST)
            cost = base_cost * self._cost_multiplier
        
        # Create estimate record
        estimate = ToolCostEstimate(
            tool_name=tool_name,
            estimated_cost_usd=cost,
            description=f"Tool execution by {agent_name or agent_id or 'unknown'} (mode={self._scan_mode})",
        )
        
        self._tool_costs.append(estimate)
        self._total_estimated_cost += cost
        
        # Log to file if run_dir is set
        if self._log_file is not None:
            self._write_log_entry(estimate, agent_id, agent_name)
        
        logger.debug(
            "Tool %s used (agent=%s, cost=$%.6f, mode=%s)",
            tool_name,
            agent_name or agent_id,
            cost,
            self._scan_mode,
        )
        
        return estimate
    
    def _write_log_entry(
        self,
        estimate: ToolCostEstimate,
        agent_id: str | None = None,
        agent_name: str | None = None,
    ) -> None:
        """Write a tool cost entry to the log file."""
        try:
            entry = {
                "timestamp": estimate.timestamp,
                "tool_name": estimate.tool_name,
                "estimated_cost_usd": estimate.estimated_cost_usd,
                "agent_id": agent_id,
                "agent_name": agent_name,
                "scan_mode": self._scan_mode,
                "cost_multiplier": self._cost_multiplier,
            }
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except (OSError, IOError) as e:
            logger.warning("Failed to write tool cost log: %s", e)
    
    def get_total_estimated_cost(self) -> float:
        """Get the total estimated cost for all tool executions."""
        return round(self._total_estimated_cost, 10)
    
    def get_tool_usage_summary(self) -> dict[str, Any]:
        """Get a summary of tool usage."""
        from collections import Counter
        
        tool_counts = Counter(t.tool_name for t in self._tool_costs)
        tool_costs = {}
        for tool_name in tool_counts:
            matching = [t for t in self._tool_costs if t.tool_name == tool_name]
            tool_costs[tool_name] = {
                "count": len(matching),
                "total_cost": round(sum(t.estimated_cost_usd for t in matching), 10),
            }
        
        return {
            "total_executions": len(self._tool_costs),
            "total_estimated_cost": self.get_total_estimated_cost(),
            "scan_mode": self._scan_mode,
            "cost_multiplier": self._cost_multiplier,
            "by_tool": tool_costs,
            "by_agent": self._get_cost_by_agent(),
        }
    
    def _get_cost_by_agent(self) -> dict[str, Any]:
        """Get cost breakdown by agent."""
        from collections import defaultdict
        
        agent_costs: dict[str, list[float]] = defaultdict(list)
        for t in self._tool_costs:
            # Extract agent from description or use unknown
            agent_key = "unknown"
            if " by " in t.description:
                agent_part = t.description.split(" by ")[1].split(" ")[0]
                agent_key = agent_part
            
            agent_costs[agent_key].append(t.estimated_cost_usd)
        
        result = {}
        for agent, costs in agent_costs.items():
            result[agent] = {
                "count": len(costs),
                "total_cost": round(sum(costs), 10),
            }
        
        return result
    
    def to_record(self) -> dict[str, Any]:
        """Convert tracker state to a record for persistence."""
        return {
            "total_estimated_cost": self.get_total_estimated_cost(),
            "total_executions": len(self._tool_costs),
            "scan_mode": self._scan_mode,
            "cost_multiplier": self._cost_multiplier,
            "tool_usage": [
                {
                    "tool_name": t.tool_name,
                    "estimated_cost_usd": t.estimated_cost_usd,
                    "timestamp": t.timestamp,
                    "scan_mode": self._scan_mode,
                }
                for t in self._tool_costs
            ],
            "summary": self.get_tool_usage_summary(),
        }


def get_tool_name_from_tool(tool: Any) -> str:
    """Extract tool name from various tool types."""
    if isinstance(tool, FunctionTool):
        return tool.name
    elif isinstance(tool, ShellTool):
        return "shell_execute"
    elif isinstance(tool, ApplyPatchTool):
        return "apply_patch"
    elif isinstance(tool, WebSearchTool):
        return "web_search"
    elif isinstance(tool, FileSearchTool):
        return "file_search"
    elif isinstance(tool, ImageGenerationTool):
        return "image_generation"
    elif isinstance(tool, ComputerTool):
        return "computer_use"
    elif isinstance(tool, HostedMCPTool):
        return "mcp_tool"
    elif isinstance(tool, CustomTool):
        return "custom_tool"
    elif isinstance(tool, ToolSearchTool):
        return "tool_search"
    elif hasattr(tool, "name"):
        return str(tool.name)
    else:
        return "unknown_tool"


# Global tracker instance
_global_tool_tracker: ToolCostTracker | None = None


def get_global_tool_tracker() -> ToolCostTracker | None:
    """Get the global tool cost tracker."""
    return _global_tool_tracker


def set_global_tool_tracker(tracker: ToolCostTracker) -> None:
    """Set the global tool cost tracker."""
    global _global_tool_tracker
    _global_tool_tracker = tracker


def init_tool_tracker(run_dir: Path, scan_mode: str = "deep") -> ToolCostTracker:
    """Initialize and set the global tool tracker."""
    tracker = ToolCostTracker(run_dir=run_dir, scan_mode=scan_mode)
    set_global_tool_tracker(tracker)
    return tracker
