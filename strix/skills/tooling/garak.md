---
name: garak
description: garak automated LLM vulnerability probe-scanner syntax, probe selection, and how to feed its findings into the llm_applications skill
---

# garak CLI Playbook

Official docs:
- https://github.com/NVIDIA/garak
- https://docs.garak.ai

garak is NVIDIA's automated LLM red-teaming scanner: 100+ pre-built **probes** (jailbreak, prompt-leak, encoding-bypass, toxicity, malware-generation, package hallucination, DAN-family, etc.) fired against a target model, each scored by a matching **detector**. Use it to get broad, reproducible coverage fast before hand-crafting targeted prompt-injection payloads from `llm_applications`/`llm_prompt_injection` — garak finds the low-hanging fruit systematically; the manual skills go deeper on what it flags.

Install (not preinstalled in the sandbox):
```
pipx install garak
```

Canonical syntax:
`garak --model_type <type> --model_name <name> [--probes <probe_spec>] [flags]`

High-signal flags:
- `--model_type <type>` target harness: `openai`, `huggingface`, `rest` (generic HTTP endpoint — use this for a custom/target LLM API), `ggml`, `litellm`
- `--model_name <name>` model identifier for the chosen harness
- `--probes <spec>` probe module(s) or `all`; comma-separated, supports `modulename.ProbeName` for a single probe
- `--generations <n>` responses per prompt (more = better signal, more cost)
- `--report_prefix <path>` output file prefix (JSONL report + HTML summary)
- `--config <file>` YAML config for complex REST-target setups (headers, auth, request/response JSON paths)

**REST target setup** (the common case — testing a target's own LLM-backed feature, not a public model API): garak needs a config describing how to call the endpoint and where to find the completion in the response:
```yaml
# garak_rest.yaml
rest:
  RestGenerator:
    name: target
    uri: "https://target.tld/api/chat"
    method: "post"
    headers:
      Authorization: "Bearer $KEY"
      Content-Type: "application/json"
    req_template_json_object:
      message: "$INPUT"
    response_json: true
    response_json_field: "$.reply"
```
```
garak --model_type rest --generator_option_file garak_rest.yaml --probes promptinject,dan,encoding --report_prefix target_scan
```

Agent-safe baseline for automation:
`garak --model_type rest --generator_option_file garak_rest.yaml --probes promptinject,dan,leakreplay,encoding,malwaregen --generations 3 --report_prefix scan_$(date +%s)`

High-value probe modules for a bug-bounty/pentest context (not a full `--probes all` run, which is slow and mostly noise for adversarial testing):
- `promptinject` — direct/indirect prompt-injection payload library
- `dan` — jailbreak-persona family (DAN and variants) for system-prompt override testing
- `leakreplay` — system-prompt/training-data extraction attempts
- `encoding` — base64/rot13/unicode-smuggled payloads that bypass naive input filters
- `xss` — checks if the model echoes attacker input unescaped (relevant when the LLM output renders in a web UI — feeds directly into `xss`/`llm_applications` findings)
- `malwaregen` — tests whether the target will produce functional malicious code on request (impact-severity signal, not exploitation)

Usage rules:
- Always start with a small `--probes` subset and low `--generations` to confirm the REST harness is correctly parsing responses before a full run — a misconfigured `response_json_field` silently produces all-false-negative results, not an error.
- Feed garak's JSONL report findings (specific prompts that scored positive) into the `llm_applications`/`llm_prompt_injection` skills for manual deepening and impact writeup — garak's own report is a signal source, not a submittable finding by itself.
- `--generations` above 1 multiplies cost/time linearly; use 3-5 only for probes with nondeterministic bypass rates (jailbreak-family), 1 is enough for deterministic encoding/leak checks.

Failure recovery:
- Empty/all-clean report on a target known to be weak → check `response_json_field` against a raw `curl` of the endpoint first; the JSONPath is the most common misconfiguration.
- Rate-limited/blocked by target WAF mid-scan → lower `--generations`, add request delay via `--config`, or narrow `--probes` and run sequentially instead of the full battery.

If uncertain, query web_search with:
`site:github.com/NVIDIA/garak probes <probe_name>`
