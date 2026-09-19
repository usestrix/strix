---
name: second-opinion
description: Deliberately re-review already-covered surfaces with a differently-configured model
---

# Second Opinion

Every agent in a scan runs on the same model by default. That is the right default — it is predictable and it is what the operator configured — but different model families notice different things on the same input. A pass that already happened is not necessarily a pass that was thorough; a second, independent look from a different model can surface what the first one missed. This is a deliberate, operator-triggered capability, not something that fires on its own — nothing in Strix spawns a second-opinion agent automatically, and this skill does not ask you to either.

## When to use this

Reach for a second opinion when coverage on a scan that matters is thin or uncertain and there is still budget to spend on it:

- `list_coverage(outcome="needs_follow_up")` is non-empty and piling up faster than it is being resolved — entries sitting open across multiple agents rather than one agent's temporary backlog.
- A target is large or high-value relative to how much of it has actually been exercised — e.g. a handful of endpoints marked `covered` on an API surface with dozens of routes.
- The scan is close to wrapping up and you (the root agent) judge that a fresh pass over what has already been reviewed is worth more than starting a new area from scratch.

Do not reach for this to cover new ground — that is what an ordinary specialist agent is for. This is specifically for **re-examining surfaces someone already looked at**, with a model that might notice something the first pass didn't.

Do not reach for this reflexively on every scan — it is another full agent's worth of tokens and time on top of the primary pass, and it needs a real driver (thin coverage on something that matters, not curiosity).

## How to use this

1. Call `list_coverage(outcome="needs_follow_up")` (and, if useful, look at what is marked `covered` on the target you're worried about) to build a concrete list of surfaces to re-check. A second opinion is only as good as the list of what it's being asked to re-examine — don't hand it a vague "look at the app again."
2. Call `create_agent` with `model` set to a different model string than the one this scan is running on, and a `task` that says explicitly this is a re-review, not fresh recon:

   ```
   create_agent(
       name="Second Opinion: Auth Surface",
       task=(
           "Re-review these already-covered surfaces with fresh eyes: "
           "<list the specific endpoints/flows/coverage entries from step 1>. "
           "The first pass marked these as needs_follow_up / covered but "
           "coverage here is thin relative to the surface's size. Look for "
           "anything the first pass could have missed, not new areas."
       ),
       model="anthropic/claude-opus-4-7",
       skills=["auth"],
   )
   ```

3. Treat its findings like any other subagent's: filed vulnerability reports and `update_coverage` calls on the entries it resolved. It reports back through the same `agent_finish` / completion-report flow as every other child.

`model` accepts the same `<provider>/<model>` strings as `STRIX_LLM` (e.g. `anthropic/claude-opus-4-7`, `openai/gpt-5.6`, `zai/glm-5.3`). Pick something meaningfully different from the scan's configured model — a second pass on the same model tends to repeat the same blind spots.
