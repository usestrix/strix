### Overview

To help make Strix better for everyone, we collect anonymized data that helps us understand how to better improve our AI security agent for our users, guide the addition of new features, and fix common errors and bugs. This feedback loop is crucial for improving Strix's capabilities and user experience.

Strix has two telemetry channels:

1. **Anonymous product telemetry** via [PostHog](https://posthog.com) for high-level usage and reliability metrics.
2. **Run observability traces** via OpenTelemetry/OpenLLMetry, written locally to `strix_runs/<run_name>/events.jsonl` by default.

Remote OpenTelemetry export is optional and only enabled when `TRACELOOP_BASE_URL` and `TRACELOOP_API_KEY` are set.
Local telemetry logs are retained for 30 days by default (`STRIX_EVENTS_RETENTION_DAYS=30`). Set `STRIX_EVENTS_RETENTION_DAYS=0` to disable automatic pruning.

### Telemetry Policy

Privacy is our priority.

- PostHog telemetry is anonymized by default and does **not** include prompts, payloads, or findings content. Each session gets a random UUID that is not persisted or tied to you. Your code, scan targets, vulnerability details, and findings always remain private and are never collected.
- OpenTelemetry run traces are stored locally in your run directory. If you configure a remote OTEL endpoint, those traces are exported to your configured destination.

### What We Track

We collect only very **basic** usage data including:

**Session Errors:** Duration and error types (not messages or stack traces)\
**System Context:** OS type, architecture, Strix version\
**Scan Context:** Scan mode (quick/standard/deep), scan type (whitebox/blackbox)\
**Model Usage:** Which LLM model is being used (not prompts or responses)\
**Aggregate Metrics:** Vulnerability counts by severity, agent/tool counts, token usage and cost estimates

For complete transparency, you can inspect our [telemetry implementation](https://github.com/usestrix/strix/blob/main/strix/telemetry/posthog.py) to see the exact events we track.

### What We **Never** Collect

- IP addresses, usernames, or any identifying information
- Scan targets, file paths, target URLs, or domains
- Vulnerability details, descriptions, or code
- LLM requests and responses

### How to Opt Out

Telemetry in Strix is entirely **optional**:

```bash
export STRIX_TELEMETRY=0
```

`STRIX_TELEMETRY` acts as the global default for both channels.

You can also control channels independently:

```bash
# Disable only OpenTelemetry run traces
export STRIX_OTEL_TELEMETRY=0

# Disable only PostHog product telemetry
export STRIX_POSTHOG_TELEMETRY=0
```
