---
name: safe-mode-crawling
description: Systematic guard against destructive side effects when crawling and testing — recognize irreversible operations before invoking them, prefer read-only reconnaissance, and surface high-risk actions to the operator
---

# Safe-Mode Crawling Guard

Autonomous agents that drive browsers, submit forms, and fire HTTP requests can cause real damage to target environments — deleting data, triggering payments, sending emails, or mutating production state. This skill teaches agents to recognize destructive operations **before** executing them, prefer read-only reconnaissance, and escalate to the operator when an action's side effects are uncertain.

## Why This Matters

An agent pointed at a staging or production application with admin credentials can:
- `DELETE` database records, user accounts, or storage objects
- Trigger email/SMS notifications to real users
- Process payments or refunds through payment gateways
- Reset passwords, revoke API keys, or invalidate sessions
- Execute bulk operations (purge caches, drop tables, wipe logs)
- Submit forms that create real orders, tickets, or support requests

These are not hypothetical — they are the natural consequence of an autonomous agent exploring admin panels and API endpoints without constraint.

## Recognizing Destructive Operations

### HTTP Method Heuristics

| Method | Default Risk | Notes |
|--------|-------------|-------|
| `GET`, `HEAD`, `OPTIONS` | 🟢 Usually Safe | Read-only by specification, but **not guaranteed** — some apps use GET for state changes |
| `POST` | 🟡 Caution | Creates resources; may trigger side effects |
| `PUT`, `PATCH` | 🟡 Caution | Modifies existing resources |
| `DELETE` | 🔴 High Risk | Removes resources; often irreversible |

**Critical:** HTTP method alone is NOT sufficient to determine safety. Some applications expose state-changing operations through `GET` (e.g., `GET /api/users/delete?id=5`, `GET /admin/reset-password?user=admin`, `GET /logout`, `GET /unsubscribe`). Similarly, `POST` is used for destructive operations (e.g., `POST /api/users/delete`, `POST /admin/purge-cache`). **Always check endpoint semantics — URL path, query parameters, and context — regardless of HTTP method.**

### High-Risk Endpoint Patterns

Watch for these patterns in URLs, form actions, and API routes:

**Deletion / Removal**
- `/delete`, `/remove`, `/destroy`, `/purge`, `/wipe`, `/drop`
- `/api/*/delete`, `/admin/*/remove`
- Bulk variants: `/bulk-delete`, `/delete-all`, `/clear-all`

**State Mutation**
- `/reset`, `/revoke`, `/invalidate`, `/deactivate`, `/disable`
- `/password/reset`, `/api-keys/revoke`, `/sessions/invalidate`

**Financial / Transactional**
- `/payment`, `/charge`, `/refund`, `/purchase`, `/checkout`
- `/subscribe`, `/cancel-subscription`, `/billing`

**Communication Triggers**
- `/send`, `/notify`, `/email`, `/sms`, `/webhook/trigger`
- `/invite`, `/broadcast`, `/publish`

**Admin / System**
- `/admin/*/execute`, `/admin/*/run`
- `/migrate`, `/seed`, `/truncate`, `/backup/delete`

### Form Analysis

Before submitting any form, check:
1. **Action URL** — does it match a high-risk pattern above?
2. **Submit button text** — "Delete", "Remove", "Reset", "Send", "Pay", "Confirm"
3. **Confirmation dialogs** — JavaScript confirms are a signal the app considers the action risky
4. **Hidden fields** — `_method=DELETE`, `action=destroy`, `confirm=true`
5. **CSRF tokens** — presence indicates state-changing operation

## Decision Framework

```
1. Does the endpoint match a high-risk pattern (e.g., /delete, /payment, /reset)?
   ├── YES → STOP. Log the finding. Do NOT execute.
   │         Surface to operator with: URL, method, parameters, and risk assessment.
   └── NO → Continue to step 2.

2. Does the endpoint semantics suggest state change? (Check URL path, query params,
   button text, form action, API docs — even for GET/HEAD/OPTIONS.)
   ├── YES or UNCERTAIN → Treat as mutating. Go to step 3.
   └── NO, confirmed read-only → Proceed.

3. Can this action be reversed?
   ├── YES (e.g., create a test user that can be deleted) → Proceed with caution.
   └── NO or UNCERTAIN → STOP. Surface to operator.
```

> **Why GET/HEAD/OPTIONS are not auto-approved:** The HTTP spec says these methods _should_ be safe, but real-world applications violate this. A `GET /admin/deleteUser?id=5` is just as destructive as `DELETE /api/users/5`. The decision tree checks endpoint semantics for **every** request, regardless of method.

## Operational Rules

### Before Any Mutating Request

1. **Identify the operation** — What does this endpoint actually do? Read the endpoint name, form labels, button text, and API documentation if available.
2. **Assess reversibility** — Can the action be undone? Creating a test record is usually reversible; deleting a production record is not.
3. **Check scope** — Is this a single-resource operation or a bulk operation? Bulk operations are categorically higher risk.
4. **Prefer read-only alternatives** — Can the same vulnerability be demonstrated with a GET-based information disclosure instead of a destructive POST?

### Idempotency Checks

Before repeating any mutating request:
- Has this exact request already been sent in this session?
- Did the first attempt succeed? If so, do not retry — the side effect has already occurred.
- For test data creation: use unique, identifiable values (e.g., `strix_test_<timestamp>`) so cleanup is possible.

### When to Stop and Surface

**Always stop and report to the operator when:**
- The action would delete or modify real user data
- The action would trigger external communication (email, SMS, webhook)
- The action involves payment processing or financial transactions
- The action would modify authentication state (password reset, key revocation)
- The action is a bulk/batch operation affecting multiple resources
- You are uncertain about the side effects

**Format for surfacing:**
```
⚠️ HIGH-RISK ACTION DETECTED
Endpoint: DELETE /api/v1/users/42
Method: DELETE
Risk: Irreversible deletion of user account
Context: Found during IDOR testing on user management panel
Recommendation: Test with a disposable test account instead, or confirm with operator
```

## Validation

1. Demonstrate that the safe-mode guard prevents execution of destructive operations by showing the agent correctly identifies and skips high-risk endpoints
2. Confirm that read-only testing paths still discover the vulnerability (e.g., proving IDOR via GET before attempting DELETE)
3. Document any high-risk operations that were surfaced to the operator instead of executed
4. Verify that test data created during scanning uses identifiable prefixes for cleanup

## Integration with Other Skills

- **IDOR testing** — Prove authorization bypass with GET requests first; only attempt state-changing operations with disposable test data
- **CSRF testing** — Demonstrate the vulnerability exists without actually triggering the destructive action on real data
- **Business logic** — Map the workflow read-only before attempting to exploit state transitions
- **Authentication/JWT** — Test token manipulation without invalidating real sessions

## Pro Tips

1. Start every engagement by mapping the application **read-only** — enumerate endpoints, understand data model, identify admin functions — before attempting any writes
2. If the target has a test/sandbox mode, prefer it over production endpoints
3. When testing APIs, use obviously fake data (`test@strix-pentest.example`, `strix_test_*`) so the operator can identify and clean up agent-created records
4. Document every mutating request you *choose not to send* — this is valuable information for the operator and demonstrates responsible testing methodology
5. A vulnerability that could cause damage is still a valid finding even if you don't trigger the damage — describe the attack path, show the preconditions are met, and let the operator decide on full exploitation
