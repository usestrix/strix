# `scope.yaml` — Authorized Scope Schema (Phase 0)

The authorization contract for a Strix 2 run. Declares exactly what the engagement may touch, per domain,
plus the intrusive-action gate. Loaded by `strix.scope.load_scope_policy`; evaluated by
`ScopePolicy.evaluate(target, *, intrusive=False)`. **Fail-closed:** anything not matched is denied.

Status: **schema + loader + evaluator implemented and tested; boundary enforcement wired in Phase 1.**

## Resolution order
1. Explicit path argument.
2. `$STRIX_SCOPE_CONFIG`.
3. First of `scope.yaml`, `scope.yml`, `.strix/scope.yaml` from the search dir (default: cwd).
4. None found → loader returns `None` (caller decides the safe default; Phase 1 treats `None` as
   "no authorization on record" for the new intrusive domains).

A file that **exists but is malformed / invalid / not a mapping** raises `ScopeConfigError` — a
present-but-wrong authorization document is never treated as "no restrictions".

## Fields

```yaml
name:            str?          # engagement label (report header)
authorized_by:   str?          # who/what authorized this test
notes:           str?          # rules of engagement, ticket link, etc.
allow_intrusive: bool = false  # gate for state-changing actions (mirrors --allow-intrusive)

web:
  domains: [str]               # "example.com" or "*.example.com" (wildcard covers apex + subdomains)
api:
  base_urls: [str]             # request URL is in scope if it starts with one of these
network:
  hosts: [str]                 # hostnames or single IPs
  cidrs: [str]                 # validated CIDR ranges
  ports: [int] | null          # port allowlist; null = all ports, [] = none
cloud:
  aws_account_ids: [str]       # exactly 12 digits (validated)
  azure_subscription_ids: [str]
  gcp_project_ids: [str]
  regions: [str] | null        # region allowlist; null = all (reserved for Phase 1 region checks)
```

Unknown keys are rejected (`extra="forbid"`) at every level, so a typo can't silently widen scope.

## Target classification (in `evaluate`)
| Target form | Kind | Checked against |
|---|---|---|
| `aws:…`, `azure:…`, `gcp:…`, `arn:aws:…`, bare 12-digit | cloud | `cloud.*` (ARN account id read from field 5) |
| `scheme://host[:port]/…` | web/api | `api.base_urls` (prefix), then `web.domains`, then `network.*` |
| IP / CIDR / hostname | network | `network.cidrs`, `network.hosts`, then `web.domains` |

`evaluate` returns a `ScopeDecision(allowed, reason, kind, category, matched)` — truthy iff allowed. An
`intrusive=True` call is denied unless `allow_intrusive` is set, even for an in-scope target, so the
intrusive gate can't be bypassed by a target that is otherwise authorized.

## Phase 1 wiring (planned)
- Enforce at the MCP wrapper boundary (`call_mcp`) and inside each domain wrapper: resolve the target
  argument, call `evaluate`, refuse out-of-scope with the decision's `reason`.
- `--allow-intrusive` CLI flag → `allow_intrusive` override; intrusive tool calls logged.
- Region enforcement for cloud once cloud tools land.
