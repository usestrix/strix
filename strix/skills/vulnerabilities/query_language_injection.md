---
name: query-language-injection
description: Scalar injection into embedded query languages, especially apparent exact-match authorization filters compiled as JSONPath, JMESPath, OData, Lucene, LDAP, Cypher, or XPath
---

# Query-Language Injection

An HTTP string can become syntax when a downstream component builds a query or policy expression. Treat every accepted search, filter, selector, and authorization scalar as an independent sink.

## Mandatory Matrix

For each named scalar field:

1. Establish known-match and known-no-match controls while all sibling fields stay fixed.
2. With known match `V`, execute these four JSONPath-style closure cells on the field itself: `V' || @.<field> == @.<field> || 'V`, `V' && @.<field> != @.<field> && 'V`, `V" || @.<field> == @.<field> || "V`, and `V" && @.<field> != @.<field> && "V`. Balance the expected suffix and adapt field and operator syntax for other grammars. Constant-only expressions may be rejected.
3. Do not substitute standalone metacharacters, generic SQL probes, object payloads, or tests of a sibling field for any cell.
4. Repeat across plausible grammars inferred from behavior or errors. An empty result may represent a swallowed parser exception.
5. Confirm impact through broadened, cross-tenant, privileged, or otherwise forbidden results—not a parser error alone.

Do not conclude `exact match`, `safe`, or `ruled out` until this matrix ran on every scalar sink, or a specific non-concatenating control was identified.
