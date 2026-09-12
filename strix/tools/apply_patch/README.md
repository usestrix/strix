# apply_patch

SDK-provided file patching tool — the agent's only first-class way to edit
files in the sandbox. Surfaced to the model as `patch` (renamed via
`_TOOL_NAME_OVERRIDES` in `strix/agents/factory.py`).

- **Implementation:** `agents.sandbox.capabilities.tools.apply_patch_tool.ApplyPatchTool`
  (upstream `agents` SDK)
- **Wired in:** `strix/agents/factory.py` — added per-run via the SDK
  `Filesystem` capability.
