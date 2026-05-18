# Strix Source Instructions for Hoplite

This checkout is the runtime source used by `../hoplite-agent`. Hoplite is a wrapper; runtime behavior must be implemented here.

## Hoplite-Specific Runtime Areas

- `strix/runtime/docker_runtime.py`: passes proxy and timeout configuration into sandbox containers.
- `containers/docker-entrypoint.sh`: configures proxy environment and strict egress enforcement.
- `containers/Dockerfile`: builds the local `hoplite-sandbox:local` image used by Hoplite.
- `strix/agents/StrixAgent/system_prompt.jinja`: agent operating rules, cleanup expectations, proxy-bypass prohibition.
- `strix/tools/finish/finish_actions.py`: final scan completion contract.
- `strix/telemetry/tracer.py`: final report persistence.

## Hoplite Requirements

- Keep Hoplite naming as `hoplite`; do not rename it to hoplight.
- Tor/proxy mode must fail closed. Do not add direct fallback behavior unless explicitly requested.
- Agents must not be encouraged to unset proxy variables, use `--noproxy '*'`, or bypass proxy controls.
- Sandbox network enforcement should block direct egress when `STRIX_ENFORCE_TOOL_PROXY=true`.
- Agents must track temporary artifacts and clean them up before calling `finish_scan`.
- `finish_scan` must include cleanup status.
- Headless/non-interactive mode is the Hoplite default.

## Validation

Use `uv` when available:

```bash
uv run ruff check .
uv run pytest
```

For targeted runtime work, at minimum run the relevant tests under `tests/runtime`, `tests/tools`, and `tests/interface`.
