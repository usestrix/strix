---
name: rag-vector-db-security
description: RAG pipeline and vector-database-specific security testing for cross-tenant isolation, embedding leakage, and retrieval-based indirect prompt injection
---

# RAG & Vector Database Security

`llm_applications` covers OWASP LLM Top 10 end to end. This skill goes deeper on the retrieval layer specifically — the vector database and the retrieval-augmented-generation pipeline built on top of it — where multi-tenant isolation failures and retrieval-specific injection techniques live outside the model itself.

## Attack Surface

- Vector database instances (Pinecone, Weaviate, Qdrant, Milvus, pgvector, Chroma) storing embeddings for one or more tenants/users
- The retrieval step of any RAG pipeline: query embedding → similarity search → document/chunk retrieval → context injection into the LLM prompt
- Document ingestion pipelines that embed and index user- or externally-supplied content
- Vector-DB admin/management APIs, frequently exposed separately from the application's own auth layer

## Key Vulnerabilities

### Cross-Tenant Vector-Index Isolation Failures

Multi-tenant RAG deployments typically isolate tenants via a metadata filter (`tenant_id: "acme"`) applied at query time, rather than physically separate indexes — this is a runtime authorization check, and it fails the same way any filter-based authorization does:
- Test whether the metadata filter is enforced server-side by the RAG application, or whether the vector-DB query itself is constructed with a client-influenceable filter parameter (an API that accepts a raw filter/query object from the client rather than injecting the tenant scope itself)
- Test with a crafted query that omits the tenant filter, uses a filter-bypass value (`tenant_id: {"$ne": "attacker_tenant"}` on DBs supporting operator-based filters), or exploits filter-vs-similarity-threshold interaction (a low similarity-score threshold combined with a broad/missing filter can surface cross-tenant chunks even when a filter is nominally present, if the DB applies the filter as a post-filter on top-K results rather than pre-filtering the search space)
- Confirm impact by retrieving and surfacing another tenant's actual document content through the RAG output, not just observing an internal metadata leak

### Embedding Inversion / Data Leakage

- Embeddings are not inherently anonymous — with access to the embedding vectors themselves (via an exposed vector-DB query API, or a debug endpoint returning raw vectors alongside retrieved text), embedding-inversion techniques can reconstruct approximate source text, especially for short, low-entropy inputs (PII fields, form data) embedded individually rather than as part of longer documents
- Test whether any application endpoint returns raw embedding vectors (not just retrieved text) — this is a data-exposure finding independent of any inversion attack, since a returned vector for a short, sensitive input is itself often near-reversible with public embedding-inversion tooling for common embedding models (OpenAI `text-embedding-*`, common open-source sentence-transformer models)

### Retrieval-Augmented Indirect Prompt Injection

The RAG-specific variant of indirect prompt injection (see `llm_prompt_injection` for the general technique): the attacker doesn't need any access to the LLM's input directly — they only need their content to end up in the knowledge base the retriever pulls from.
- If the target ingests externally-supplied content into its RAG index (support tickets, uploaded documents, scraped web pages, user-submitted reviews/comments), craft content containing an instruction payload designed to survive chunking and be retrieved for a plausible future query
- Payload design should account for the retrieval step being similarity-based, not exact-match: embed the instruction payload alongside content that's semantically close to *likely future queries* about the topic you want to hijack, so the poisoned chunk actually gets retrieved and placed in context
- Test both "torn" instructions split across chunk boundaries (see next section) and complete instructions within a single chunk, since chunking strategy varies by target

### Chunk-Boundary Manipulation

- If chunk size/overlap can be inferred (via response timing, error messages, or documented defaults for the RAG framework in use), craft a payload that straddles a chunk boundary such that no single chunk's similarity score to a "relevance check" step is high enough to be filtered as suspicious by a naive per-chunk moderation pass, but the reassembled context (multiple retrieved chunks concatenated into the prompt) still contains the full coherent instruction
- Test relevance-threshold evasion: a retriever configured to only inject chunks above a similarity threshold can sometimes be gamed by padding the malicious chunk with content closely matching common query phrasing, inflating its similarity score independent of the instruction payload's semantic content

### Vector-DB Admin-API Exposure

- Many vector-DB deployments run with the database's native admin/management API reachable directly (not proxied through the application's own auth), particularly in early-stage or internally-deployed setups — check for the DB's default port/API path directly reachable from outside the expected network boundary:
```
# Common default ports/paths worth checking during recon
Weaviate: :8080/v1/schema, /v1/objects
Qdrant: :6333/collections
Milvus: :19530 (gRPC), :9091 (metrics/admin)
Chroma: :8000/api/v1/collections
pgvector: reachable Postgres port with the target DB's own separate risk surface
```
- An exposed admin API typically allows full read (dump all embeddings/documents across all tenants), write (poison the index directly, bypassing any application-layer ingestion validation), and sometimes delete/reindex operations with no authentication at all in default/dev configurations left running in production

## Chaining Attacks

- Cross-tenant isolation failure + embedding inversion: extract another tenant's sensitive document content even when only vectors (not source text) are directly exposed
- Retrieval poisoning + indirect prompt injection: full RAG-pipeline compromise leading to data exfiltration or unauthorized tool invocation by the downstream LLM agent (see `agentic_system_security` for the tool-invocation half)
- Exposed admin API + retrieval poisoning: bypass all application-layer ingestion validation entirely by writing directly to the index

## Testing Methodology

1. Map the full RAG pipeline: ingestion source(s), embedding model, vector-DB, retrieval-query construction, context-injection point
2. Test tenant-isolation enforcement at the actual vector-DB query layer, not just the application's UI-level access control
3. Check for any endpoint returning raw embedding vectors; assess inversion feasibility for the embedding model in use
4. If content ingestion is externally reachable, test retrieval-poisoning payloads designed around the target's chunking/relevance-filtering behavior
5. Directly probe for an exposed vector-DB admin API on the target's infrastructure

## Validation

1. Cross-tenant leakage: demonstrate retrieval of another tenant's actual content through the RAG output as tenant A's authenticated user
2. Retrieval poisoning: demonstrate the injected instruction actually gets retrieved and influences the LLM's downstream behavior/output on a plausible real query
3. Admin-API exposure: demonstrate unauthenticated read (and, if in scope, write) against the vector-DB directly

## False Positives

- Metadata filter enforced correctly at the query layer with no client-influenceable bypass
- Raw vectors never exposed to any client-reachable endpoint
- Ingestion pipeline includes content moderation/sanitization that strips instruction-like content before indexing

## Impact

- Cross-tenant data exposure at the document/knowledge-base level, often more sensitive than typical API-level IDOR since RAG knowledge bases frequently contain aggregated internal documents
- Full RAG-pipeline hijacking via indirect prompt injection, potentially cascading into agentic tool misuse
- Complete index compromise via an exposed admin API, undermining every downstream RAG consumer at once

## Pro Tips

1. Test isolation at the vector-DB query layer directly when possible — application-layer testing alone can miss a filter that's bypassable at the raw query level
2. Always check for a directly-reachable vector-DB admin port as a first step — it's a common, high-impact, low-effort finding in early-stage RAG deployments
3. Design injection payloads around the retriever's actual similarity/relevance behavior, not just prompt-injection phrasing that works against direct LLM input
4. Cross-reference `llm_applications` and `agentic_system_security` — a RAG-layer finding is often the entry point into a broader LLM-application or agentic-tool compromise chain

## Summary

RAG pipelines add a whole new authorization and injection surface beneath the LLM itself — the vector database's isolation model and the retrieval step's trust in ingested content are both testable independent of the model's own prompt-injection resistance.
