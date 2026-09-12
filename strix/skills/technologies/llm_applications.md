---
name: llm-applications
description: "End-to-end security testing for LLM, RAG, embedding, agent, and model-serving applications. Covers the OWASP Top 10 for LLM Applications 2026 (LLM01-LLM10): prompt injection, sensitive disclosure, excessive agency, supply chain, data/model poisoning, unbounded consumption, misinformation, hidden context exposure, vector weaknesses, and improper output handling. Use for architecture mapping, source review, black-box testing, and complete LLM application assessments."
---

# LLM Application Security

Use this as the umbrella workflow for the [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/). Load `llm_prompt_injection` for deeper LLM01 testing and the relevant conventional vulnerability skill when an LLM-controlled value reaches a browser, query, command, URL, file, or authorization sink.

Treat the identifiers as a coverage taxonomy, not as report titles. Classify a finding by its technical root cause and affected trust boundary. One exploit chain may contain several OWASP categories, while one root cause should not become ten duplicate reports.

The LLM list covers the model as a component of an application. When a model acts through tools, persistent memory, peer agents, or autonomous workflows, apply this list and pair the assessment with the OWASP Top 10 for Agentic Applications 2026; do not force every agentic failure into an LLM category.

## Architecture and Evidence Map

Map the complete system before testing prompts:

```text
users / tenants / external content
  -> API, UI, file and multimodal ingestion
  -> prompt builder, policy and orchestration
  -> model/provider and context window
  -> memory, cache, RAG retrieval and vector index
  -> tools, MCP servers, plugins and peer agents
  -> output parsers, renderers and downstream systems
  -> logs, traces, feedback, evaluation and training pipelines
```

For every edge, record:

- **Data authority:** who creates, reads, updates, deletes, approves, and owns the data; tenant and sensitivity; retention and training use.
- **Action authority:** caller identity, downstream identity, permissions, authorization checks, confirmation, transaction boundaries, and audit evidence.
- **Transformation:** serialization, chunking, embedding, retrieval, reranking, prompt placement, output parsing, and cache keys.
- **Runtime identity:** application build, provider, model and revision, prompt revision, tool set, feature flags, corpus/index snapshot, temperature/seed where available, and quota policy.

Do not treat the model as an authorization principal or a trusted parser. Put deterministic authentication, authorization, validation, and policy enforcement outside the model.

## 2026 Coverage Matrix

| OWASP 2026 risk | Security invariant to test | Primary route |
|---|---|---|
| LLM01:2026 Prompt Injection | Untrusted instructions cannot cross a meaningful policy or authority boundary | `llm_prompt_injection` |
| LLM02:2026 Sensitive Information Disclosure | A response, context, cache, trace, training path, or retrieval result reveals only data authorized for the caller | This skill + `information_disclosure` |
| LLM03:2026 Excessive Agency | Tools expose only required functionality, permissions, and autonomy, with complete mediation at the action | This skill + `broken_function_level_authorization` / `business_logic` |
| LLM04:2026 Supply Chain | Every model, adapter, dataset, tokenizer, prompt, plugin, package, image, and hosted API has verified provenance and an immutable deployment identity | This skill + `dependency_cve_scanning` / `source_aware_sast` |
| LLM05:2026 Data and Model Poisoning | Attacker-influenced training, tuning, feedback, memory, or embedding data cannot persistently alter protected behavior unnoticed | This skill |
| LLM06:2026 Unbounded Consumption | Every request, recursive action, queue, and billable operation has enforceable cumulative resource and cost bounds | This skill + `business_logic` / `race_conditions` |
| LLM07:2026 Misinformation | Unsupported output cannot silently drive a security-sensitive or high-impact decision | This skill + `business_logic` |
| LLM08:2026 Hidden Context Exposure | Hidden instructions and operational context contain no secrets and reveal no security-relevant logic or capability that materially increases attacker power | This skill + `llm_prompt_injection` / `information_disclosure` |
| LLM09:2026 Vector and Embedding Weaknesses | Ingestion and retrieval preserve tenant, source, document authorization, and embedding confidentiality across the index lifecycle | This skill + `idor` / `information_disclosure` |
| LLM10:2026 Improper Output Handling | Model output remains untrusted until the actual downstream grammar and sink validate it | This skill + the sink-specific vulnerability skill |

## Assessment Workflow

1. Inventory every LLM-backed feature, model endpoint, ingestion route, retrieval source, tool, output consumer, and feedback/training path.
2. Build the data-and-authority map above for each user role and tenant.
3. Create a test matrix across application build, model/revision, prompt revision, tool configuration, identity, corpus snapshot, and quota tier.
4. Use controlled records with distinct per-user and per-tenant markers to distinguish context, retrieval, cache, memory, and training leakage.
5. Establish a normal baseline and matched negative control before adversarial variants. Run repeated trials and report success counts because model behavior is stochastic.
6. Validate the application-side effect, retrieved record, rendered sink, downstream authorization result, resource meter, or persistent model change. Model narration alone is not evidence of that effect.
7. Label each claim **architecture-confirmed**, **dynamically verified**, **candidate**, or **disproven**. Do not turn an unsafe architecture property into a claimed exploit, or ignore a confirmed control defect merely because downstream impact has not yet been exercised.
8. Report the smallest technical root cause that explains the demonstrated impact, then document related OWASP categories as chain context.

## Source Review

Trace source to sink around:

- provider SDK calls, local inference servers, model gateways, and fallback providers
- system/developer prompts, templates, message-role conversion, context truncation, reasoning channels, and prompt caches
- file, URL, email, image/audio/video, connector, tool-result, peer-agent, and memory ingestion
- embedding generation, collection/namespace selection, metadata filters, reranking, hybrid search, and retrieval caches
- function/tool definitions, MCP clients/servers, generic HTTP/shell/SQL tools, peer-agent delegation, and approval handlers
- model output parsers, HTML/Markdown renderers, terminals/IDEs/logs, code execution, query builders, URLs, file paths, templates, and policy decisions
- training/fine-tuning jobs, adapters, datasets, feedback stores, evaluation corpora, model registries, and runtime downloads
- token accounting, request limits, concurrency, retries, agent-loop depth, fan-out, async queues, streaming cancellation, and provider billing

Record both forward and reverse reachability: attacker-controlled input to privileged consumer, and privileged consumer back to every input or model output that can influence it.

## Optional Tool Routing

Use tools only when they match the deployed surface. Treat generated cases and scanner labels as leads until the application-side boundary is validated.

- **[Promptfoo](https://github.com/promptfoo/promptfoo)** — use for repeatable model/application trials, custom adversarial cases, graders, provider comparisons, and success-rate regression. Install the reviewed version locally with `npm install --save-dev --save-exact promptfoo@0.122.0`, then invoke `./node_modules/.bin/promptfoo redteam run`. Define explicit plugins, assertions, `numTests`, `maxConcurrency`, and `delay`; provider calls may transmit test data and incur cost. Its `owasp:llm` preset still uses the 2025 category mapping in version 0.122.0, so build or select tests from the 2026 matrix above and do not present the preset report as complete 2026 coverage.
- **[MCP Inspector](https://github.com/modelcontextprotocol/inspector)** — use for LLM01/LLM03 surface mapping when MCP servers are present. Install the reviewed version with `npm install --save-dev --save-exact @modelcontextprotocol/inspector@2.2.0`, then use `./node_modules/.bin/mcp-inspector --cli --config <reviewed-config> --server <name> --method tools/list` and the equivalent `resources/list` / `prompts/list` operations. Starting a stdio server executes that configured process, initialization/list handlers may have side effects, and `tools/call` can perform the real action; inspect the target and credentials before invoking it.
- **[ModelScan](https://github.com/protectai/modelscan)** — use for LLM04 static triage of supported H5, Pickle, and SavedModel artifacts before loading them, for example `uvx modelscan==0.8.8 -p <artifact>`. Run it as an untrusted-file parser in an isolated analysis environment. A clean result covers only the scanner's supported formats and signatures; it does not establish artifact provenance, integrity, or absence of behavioral backdoors.

## LLM01:2026 Prompt Injection

Load `llm_prompt_injection` and test direct, indirect, stored, cross-modal, tool-result, memory, intermediate-reasoning, and multi-turn instruction paths. Include content from web pages, documents, messages, metadata, OCR, images/audio/video, retrieved chunks, tools, MCP servers, and peer agents.

For each delivery path, record provenance as untrusted, semi-trusted, or trusted-by-the-operator but attacker-writable through another workflow. Test plain, split, multilingual, encoded, invisible-Unicode, and multimodal representations where the deployed preprocessing makes them relevant.

Define the violated invariant before testing: unauthorized data access, an unauthorized action, corruption of a protected decision, persistent behavior change, or unsafe downstream output. A jailbreak or changed tone without a security-relevant boundary is not automatically an application vulnerability.

Distinguish:

- **Prompt injection:** input changes model behavior contrary to application policy.
- **Jailbreak:** model safety behavior is bypassed; application impact depends on the product's requirements and connected capabilities.
- **Poisoning:** attacker influence persists in training, feedback, memory, or an indexed corpus and affects later users or decisions.

## LLM02:2026 Sensitive Information Disclosure

Inventory sensitive data in prompts, reasoning or scratchpad traces, retrieved chunks, tool results, memory, caches, logs, training/feedback stores, model outputs, and provider retention paths.

Test separately for:

- cross-user and cross-tenant context, memory, cache, and retrieval leakage
- secrets or private records inserted into prompts, tool schemas/results, errors, traces, or telemetry
- retained user content later used for training, evaluation, or another user's response
- training-data membership or memorization when the tested model and data provenance make that claim meaningful
- model/provider options that expose logits, log probabilities, hidden metadata, raw context, or internal reasoning

Use distinct markers for each principal and storage stage. A fabricated secret or hallucinated record is not disclosure; correlate the output to a real record and its unauthorized source.

## LLM03:2026 Excessive Agency

Create a capability ledger for every tool and peer agent:

```text
tool -> exposed operations -> downstream identity -> permissions
     -> caller/user binding -> argument validation -> authorization
     -> side effects -> retry/idempotency -> audit evidence
```

Test the three independent causes:

- **Excessive functionality:** unused, generic, administrative, shell, arbitrary-URL, or broad CRUD tools remain callable.
- **Excessive permissions:** tools use a shared/service identity or scopes broader than the initiating user and requested operation.
- **Excessive autonomy:** consequential actions execute without human or deterministic authorization appropriate to the exact action, object, arguments, identity, and current state.

Tool descriptions, model instructions, hidden channel names, and confirmation prose are not authorization controls. Enforce authorization again at the tool/downstream system. Test delegation, recursive plans, retries, race/state changes between approval and execution, and whether untrusted tool results become new instructions.

Prove the accepted tool call and downstream result. A model saying it invoked a tool is not evidence that the action occurred.

## LLM04:2026 Supply Chain

Build an inventory beyond ordinary packages:

- base models, weights, tokenizers, configuration, adapters/LoRA, quantizations, and model-conversion outputs
- training, tuning, evaluation, and embedding datasets
- prompt/template repositories, skills, plugins, MCP servers, hosted model APIs, and model gateways
- Python/JavaScript/native dependencies, containers, drivers, accelerators, and serving infrastructure

For each component, record origin, owner, license/terms, exact revision or digest, hash/signature/attestation, review status, update channel, runtime downloads, and effective permissions. Resolve every model alias, branch, mutable tag, adapter, and custom-code dependency to the artifact actually loaded. Identify who can mutate the source, promotion record, cache, or registry and whether the promoted artifact matches its claimed identity.

Inspect model loading as code loading. Pickle-compatible weights, custom model/tokenizer code, conversion hooks, package installation, and remote-code trust options can execute during acquisition or load. Trace the selected loader, artifact format, revision, initialization hooks, and resulting process or file activity.

Trace model-generated dependency names through every package runner, installer, build file, and registry lookup. A fabricated package recommendation is LLM07 misinformation; accepting or auto-installing an unverified name, namespace, or registry artifact is the LLM04 supply-chain boundary. Verify ownership and provenance rather than treating a registry response alone as proof of safety.

Use `dependency_cve_scanning` for verified known-CVE software versions. A malicious or tampered model, dataset, adapter, prompt, or plugin is a different supply-chain finding and requires provenance plus behavioral or loader evidence.

## LLM05:2026 Data and Model Poisoning

Map who can contribute to every pre-training, fine-tuning, preference, feedback, evaluation, memory, and embedding dataset. Record moderation, approval, deduplication, weighting, precedence, versioning, rollback, and the delay before data affects production.

Test:

- targeted trigger/backdoor behavior versus broad quality degradation
- poisoned examples that survive normalization, deduplication, chunking, or retraining
- feedback loops where model output or user ratings become future training data
- shared memory or indexed content that persists across users, sessions, or releases
- compromised adapters, merged models, or fine-tuning jobs that alter only a narrow topic, identity, or trigger

Compare clean and candidate snapshots with a fixed evaluation corpus and repeated trials. Trace a candidate record into the exact training/index snapshot and demonstrate persistence plus a protected behavior change. One retrieved malicious instruction may be LLM01 rather than proof that the model or dataset was poisoned.

Classify provenance/distribution compromise under LLM04 and durable corruption of data, weights, adapters, templates, or model behavior under LLM05. Record both when one chain crosses both boundaries, but do not duplicate the same root cause.

## LLM06:2026 Unbounded Consumption

Inventory every resource multiplier:

- input and output tokens, context windows, image/audio/video/document processing, embeddings, reranking, and model tier
- requests per user/key/IP/tenant, concurrency, batch size, and organization-wide budget
- agent iterations, tool calls, peer-agent fan-out, retries, provider failover, and recursive workflows
- upload count/size, chunk count, index growth, queued/background jobs, and retained outputs
- streaming connections, disconnect cancellation, timeouts, cache behavior, and partial failures
- logprobs or repeated-query surfaces that increase extraction or model-replication risk

Model cumulative work, not isolated limits: depth × fan-out × retries × failovers × model/tool cost. Test limits at request, identity, tenant, and global layers. Confirm that alternate keys, endpoints, models, encodings, streaming, retries, and concurrent requests cannot bypass accounting. Verify cancellation stops upstream inference and tool work, and that failed/retried operations do not bill or enqueue without bounds.

Record measured requests, tokens, tool calls, queue growth, latency, and provider-side cost/usage. Increase load in controlled steps; do not infer denial of service, model extraction, or financial impact from the mere absence of a UI counter.

## LLM07:2026 Misinformation

Define a trusted answer set and the downstream decision before testing. Separate ordinary model fallibility from a security or business-logic flaw.

Exercise:

- absent, ambiguous, stale, and mutually contradictory sources
- fabricated, mismatched, or forged citations, quotations, evidence, and task-completion claims
- adversarial sources that rank above authoritative material
- confidence language and UI cues that overstate certainty
- generated code, policy, medical/legal/financial guidance, identity matching, fraud/risk decisions, and other outputs consumed without verification
- automated actions triggered by unsupported claims

Measure claim support, citation coverage and entailment, source authority, abstention, and decision error across a repeatable corpus rather than reporting one hallucinated answer. Report when unsupported output crosses a defined trust boundary or drives a protected decision without required verification; otherwise record it as a quality/reliability issue.

## LLM08:2026 Hidden Context Exposure

Inventory non-user-facing content available to the model: system and developer instructions, retrieved policy text, user-profile context, tool/function schemas, workflow criteria, internal roles, reasoning scaffolds, and operational configuration.

Test extraction, inference, and reconstruction separately. Compare purported hidden context with the deployed revision, a unique marker, or observed capability because models can fabricate plausible prompts and tool lists.

Classify the result by what it exposes:

- embedded credentials, tokens, private records, or connection material -> LLM02 disclosure, with LLM08 as the exposure path
- hidden rules, trust boundaries, tool schemas, or workflow logic that materially improve an attack -> LLM08
- authorization, filtering, or privilege controls that depend on hidden-context secrecy or model obedience -> the underlying deterministic-control failure
- generic instructions with no sensitive content, security reliance, or material attacker advantage -> no standalone vulnerability

Assume hidden context is discoverable. Keep secrets and security-critical decisions outside it, and test the underlying control even when exact prompt wording cannot be recovered.

## LLM09:2026 Vector and Embedding Weaknesses

Map ingestion authorization separately from retrieval authorization. Preserve source identity, tenant, document ACL, classification, retention, and deletion state through chunking, embedding, indexing, replication, reranking, and caching.

Test:

- authorization inside vector search, filtering after top-k but before context construction, and filtering only after the model sees candidates
- shared collections/namespaces and missing, inconsistent, or fail-open tenant filters
- metadata-filter injection, type confusion, duplicate keys, or precedence differences
- oversampling/reranking/hybrid-search stages that drop earlier authorization constraints
- stale embeddings after source ACL changes, deletion, tenant moves, or index rebuilds
- retrieval and answer caches keyed without user, tenant, role, corpus version, or filter state
- cross-tenant existence inference through IDs, scores, timing, citations, or chunk metadata even when final text is refused
- adversarial or duplicate content that dominates nearest-neighbor retrieval
- embedding export, inversion, reconstruction, or linkage when vectors are returned or broadly readable

Use at least two principals and distinct documents. Inspect raw candidate IDs, context-bound chunks, and the final answer. Post-search filtering may cause ranking interference or expose candidates to an intermediate service without proving that the model or user received another tenant's content; state the exact boundary crossed.

Do not apply LLM09 merely because an application retrieves documents. Require an embedding or vector-similarity property; route authorization flaws in vectorless retrieval to the conventional access-control or information-disclosure skill.

## LLM10:2026 Improper Output Handling

Treat every model-generated string, object, URL, code block, tool argument, control sequence, and structured-output field as attacker-influenceable.

Trace output into its actual consumer:

- HTML, Markdown, email, office-document, terminal, IDE, log, and rich-text renderers
- shell/process APIs, SQL/NoSQL queries, templates, expressions, interpreters, and generated code accepted into builds
- URLs, webhooks, redirects, image fetches, browser navigation, and server-side requests
- file paths, archive entries, object keys, configuration, logs, and serialized objects
- authorization, moderation, routing, pricing, eligibility, or workflow decisions

Validate with the sink-specific skill (`xss`, `sql_injection`, `nosql_injection`, `rce`, `ssrf`, `path_traversal_lfi_rfi`, `ssti`, or `insecure_deserialization`). JSON/schema conformance does not establish authorization or semantic safety; validate types, ranges, identities, destinations, and business rules after parsing.

## Reproducibility and Reporting

- Preserve application/model/prompt/tool/corpus versions and all generation parameters available to the application.
- Compare baseline and adversarial trials, record attempt and success counts, and distinguish deterministic application behavior from stochastic model behavior.
- Validate authorization, data origin, downstream effects, persistence, or measured consumption outside the model transcript.
- Split reports when weaknesses have independent reproductions, trust boundaries, owners, or remediations. Otherwise report one technical root cause and mention additional OWASP mappings as chain context.
- Use `create_dependency_report` only for verified advisory-matched dependency CVEs. Use `create_vulnerability_report` for dynamically verified application, model, RAG, agent, or supply-chain findings.

## Summary

Test the LLM application as a data-and-authority system, not as a chatbot prompt. Complete 2026 coverage requires model behavior, application code, retrieval, tools, supply chain, downstream sinks, and resource controls to be evaluated together while keeping their root causes distinct.
