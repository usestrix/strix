---
name: query-language-injection
description: Query-language injection testing for scalar search, filter, selector, and authorization inputs compiled into JSONPath, JMESPath, OData, Lucene, LDAP, Cypher, XPath, or similar expressions. Requires a per-sink four-cell balanced true/false matrix before generic spraying or no-issue closure
---

# Query-Language Injection

An HTTP scalar becomes an injection sink when an application inserts it into a query, selector, policy, or expression string. The input may look like an exact-match value at the API boundary while becoming executable syntax in a downstream parser. Treat each accepted search, filter, selector, and authorization field as an independent sink.

## Non-Skippable First Pass

Make this the first test after baselines. Do not begin generic SQL, NoSQL, wildcard, metacharacter, or product-specific spraying until every candidate scalar has a completed row in the execution ledger.

For each scalar search, filter, selector, and authorization input:

1. Record its transport path, a full known-match value `V`, a known-no-match value, and the corresponding record property.
2. Map transport structure to record structure. For a nested request path such as `filters.status`, start with the leaf property `@.status`, not `@.filters.status`, unless responses or documentation show that the record itself is nested. For a free-text input, test each record property it searches.
3. Keep authentication, sibling fields, method, pagination, and ordering fixed.
4. Put each of these four values in the selected input itself:
   - `V' || @.<property> == @.<property> || 'V`
   - `V' && @.<property> != @.<property> && 'V`
   - `V" || @.<property> == @.<property> || "V`
   - `V" && @.<property> != @.<property> && "V`
5. Compare returned object identities. A structural injection normally makes the `OR/true` cells broaden and the `AND/false` cells narrow.
6. Record the transport path, record property, known value, all four exact transmitted values, status, result count, and returned identities.

Substitute every placeholder before transmission. For the neutral example `filters.status=active`, the record property is `status`, so send exactly:

- `active' || @.status == @.status || 'active`
- `active' && @.status != @.status && 'active`
- `active" || @.status == @.status || "active`
- `active" && @.status != @.status && "active`

Use the selected input's own accepted value at both ends. Do not send literal `V`, `@.<property>`, a bare closure fragment, or a payload in a free-text sibling. Repeat the matrix independently for every scalar, even when another field is literal or inert.

A ledger row missing any cell is incomplete. Do not substitute standalone quotes, SQL tautologies, object operators, wildcards, or generic search tokens. Do not close the input as exact-match, safe, or `no issue` unless the row is complete or a specific control proves its value cannot reach expression construction. Otherwise retain an open proof gap.

## Attack Surface

Prioritize inputs that influence:

- search, filtering, sorting, faceting, lookup, and autocomplete
- tenant, owner, role, classification, visibility, or policy selectors
- exports, reports, saved searches, dashboards, and background jobs
- document, graph, directory, or inventory queries
- path-like selectors, projections, field expressions, and rule conditions

Test query parameters, JSON and form fields, headers, cookies, GraphQL arguments, WebSocket messages, and values copied into asynchronous work. A client-side dropdown or fixed option list is not a server-side control.

Common sinks include JSONPath, JMESPath, XPath, LDAP filters, OData, Lucene-style search, Cypher, expression engines, and application-specific filter DSLs. Do not assume the grammar from the endpoint name alone. Infer it from errors, response behavior, client code, documentation, or source when available.

## Core Model

Map the complete path before selecting payloads:

```text
attacker-controlled scalar
  -> decoding or normalization
  -> string interpolation or expression construction
  -> query-language parser
  -> evaluator
  -> authorization or result handling
```

The key question is whether the value stays data or changes the structure of the final expression. A protected query is vulnerable when attacker input can close its original value context, introduce an operator or expression, and rebalance the remaining suffix.

## Reconnaissance

For every candidate field:

1. Record a known-match value and a known-no-match value.
2. Keep method, authentication, sibling fields, pagination, and ordering fixed.
3. Compare returned object identities and authorization boundaries, not only status or response length.
4. Repeat requests when data, timing, or ordering can vary.
5. Preserve the raw request. High-level serializers may quote, normalize, or collapse the representation being tested.

Test the field itself. A payload in a sibling field does not clear the original sink. Standalone quotes or metacharacters are discovery signals, not sufficient negative tests.

## Grammar Adaptation

After completing the first pass, use observed behavior to translate the same broadening and narrowing pair rather than spraying unrelated payloads. Balance the expected suffix instead of relying only on comments. Constant-only expressions may be rejected while field comparisons remain valid.

| Language family | Useful structural clues | Paired strategy |
|---|---|---|
| JSONPath | `$`, `@`, filters, brackets, quote-delimited comparisons | close the comparison, add true and false predicates, then rebalance |
| JMESPath | filters, projections, backtick literals, pipe expressions | alter a filter or projection and compare broadened with empty results |
| XPath | path steps, predicates, `and`, `or`, quote-delimited values | close the literal and compare true with false node-set predicates |
| LDAP | parenthesized filters, `&`, `|`, `!`, wildcards | inject balanced filter groups and compare match-all with match-none controls |
| OData | `$filter`, `eq`, `ne`, `and`, `or`, single-quoted strings | close the literal and compare true with false clauses using valid escaping |
| Lucene-like DSLs | field clauses, quotes, grouping, boolean operators | escape the term context and compare broad with contradictory clauses |
| Cypher-like expressions | quoted values, `WHERE`, boolean operators, comments | close the value and compare tautological with contradictory predicates |

Also test plausible value contexts such as strings, numbers, lists, paths, function arguments, and nested predicates. Change one structural assumption at a time. Use encoded forms only after a raw structural probe establishes a likely grammar or intermediary filter.

## Differential Oracles

High-signal evidence includes:

- the broadening probe returns objects absent from the known-match baseline
- the narrowing control returns no objects or a strict subset
- protected, cross-tenant, privileged, or hidden records appear
- error shape changes reveal the downstream parser or expression context
- the same predicate controls an existence, count, timing, or authorization oracle

An empty result can mean either a false predicate or a swallowed parser exception. Distinguish them with a syntactically valid false control, repeated requests, and a second predicate pair. A parser error alone proves input reached a grammar, not that the query can be controlled.

## Authorization Filters

Treat query injection as an authorization issue when the vulnerable predicate enforces tenant, owner, role, classification, or visibility boundaries. Prove that the injected request returns an object the same principal cannot obtain through the normal selector. Record the object identity and protected property so intended broad search behavior is not mistaken for a bypass.

Do not stop after showing that the result count changed. Determine whether the injected expression can read protected data, influence an export, modify a selected object, or reach a more privileged downstream operation.

## Validation

A confirmed finding should include:

1. A normal known-match baseline.
2. A normal known-no-match baseline.
3. A broadening expression with a stable unauthorized result.
4. A paired narrowing or contradictory expression.
5. Repetition showing the differential is deterministic.
6. Evidence of the affected objects, boundary, and business impact.

Keep sibling fields and credentials constant across the evidence pair. Prefer object identifiers or normalized response digests over raw body length. If only an error or response-shape anomaly is available, retain it as a proof gap rather than reporting data access that was not demonstrated.

## False Positives

- intended wildcard, fuzzy search, or documented advanced-query syntax
- changing datasets, pagination, ranking, caching, or unstable ordering
- generic validation errors that occur before the expression parser
- a quote accepted as literal data without control over query structure
- a broad result caused by an omitted filter rather than injected syntax
- an empty response caused by a swallowed exception without a valid predicate oracle

## Remediation

- Avoid building expressions through string concatenation.
- Use typed parameters, variables, or a safe AST/query-builder API when supported.
- Map user-facing options to server-owned predicates instead of accepting expression fragments.
- Apply strict allowlists for field names, operators, functions, and value types when dynamic queries are required.
- Enforce authorization outside attacker-controlled search expressions and re-check every resolved object before returning or acting on it.
- Preserve one canonical parse and representation across gateways, workers, and backend services.
- Add regression tests using paired true and false predicates for every previously vulnerable field.

Do not conclude `exact match`, `safe`, or `ruled out` until the paired matrix ran on every candidate scalar sink, or a specific non-concatenating control was identified.
