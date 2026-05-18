# Strix Notes for Hoplite

This Strix source tree backs the Hoplite launcher at `../hoplite-agent`.

## Do Not Miss

- Runtime changes belong here, not only in the Hoplite shell wrapper.
- Hoplite builds `hoplite-sandbox:local` from this tree.
- Strict proxy enforcement is controlled by `STRIX_ENFORCE_TOOL_PROXY` on the host and `STRIX_ENFORCE_PROXY` in the container.
- The sandbox entrypoint should prevent direct outbound target traffic when strict proxy mode is enabled.
- The agent prompt must tell agents to preserve proxy routing and clean up temporary accounts/files/state.
- The final report includes a cleanup summary.

## Useful Checks

```bash
uv run ruff check strix tests
uv run pytest tests/runtime tests/tools tests/interface
```
