---
name: oracle_database
description: Oracle Database-specific testing covering TNS listener enumeration, default accounts, PL/SQL injection, and listener/Data Guard misconfiguration
---

# Oracle Database

Oracle's attack surface diverges sharply from MySQL/Postgres: the TNS listener is a distinct pre-auth service with its own protocol, PL/SQL injection has package/procedure execution context that generic SQLi payloads don't cover, and the default-account list is large and well-documented from decades of enterprise deployments. Treat the TNS listener as attack surface in its own right, separate from whatever sits behind it.

## Attack Surface

- **TNS Listener** (port 1521 default, sometimes 1526/1522) — the pre-auth entry point; accepts connect-string-driven service registration and routing before any database credential is involved
- **PL/SQL packages** — stored procedures with elevated execution context (`DBMS_*`, `UTL_*`, custom app packages) reachable via any SQL injection point that lands in a PL/SQL block, not just `SELECT`
- **Enterprise Manager (EM Express / OEM)** — web console, often on port 5500/1158
- **Data Guard / listener failover config** — standby listener endpoints, broker configuration exposure
- **APEX** (Application Express) if deployed — its own large surface, treat as a separate web app with Oracle-specific auth backing it

## Reconnaissance

**TNS listener version fingerprint**
```
# tnscmd10g (part of the oracle-tools family) — no valid SID needed
tnscmd10g version -h <target> -p 1521
tnscmd10g status -h <target> -p 1521

# Raw socket probe if tnscmd10g isn't available
python3 -c "
import socket
s = socket.create_connection(('<target>', 1521), timeout=5)
s.send(b'\\x00\\x1e\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x36\\x01\\x2c\\x00\\x00\\x08\\x00\\x7f\\xff\\x7f\\x08\\x00\\x00\\x00\\x01\\x00\\x00\\x1d\\x00\\x3a\\x00\\x00\\x00\\x00\\x00\\x00(CONNECT_DATA=(COMMAND=version))')
print(s.recv(4096))
"
```

**SID enumeration** (TNS poisoning-era Oracle exposes SID guessing pre-auth on many still-deployed versions)
```
nmap -p 1521 --script oracle-sid-brute <target>
```

**Version-to-CVE mapping** — once you have the Oracle Database version (visible post-connect via `v$version`, or via listener banner on older/misconfigured versions), cross-reference Oracle's quarterly Critical Patch Update (CPU) advisories for that specific version.

## Key Vulnerabilities

### Default / Weak Accounts

Oracle ships (or historically shipped) a long list of default accounts, frequently left active in enterprise deployments:
```
SYS / change_on_install   (or blank on very old installs)
SYSTEM / manager
SCOTT / tiger              (the classic Oracle tutorial schema — almost always present if ever installed)
DBSNMP / dbsnmp
OUTLN / outln
MDSYS / mdsys
CTXSYS / ctxsys
```
Check the app-specific schema accounts too — Oracle E-Business Suite, PeopleSoft, and other Oracle enterprise apps ship their own well-documented default schema credentials.

```
# Test with sqlplus if installed, or a Python cx_Oracle/python-oracledb one-liner
sqlplus SCOTT/tiger@//<target>:1521/<SID_or_SERVICE>
```

### TNS Listener Poisoning / Hijacking (pre-12c)

On unpatched pre-12c listeners without `ADMIN_RESTRICTIONS` set, an attacker can dynamically register a rogue instance with the listener (`SERVICE_REGISTER` command), causing the listener to route legitimate client connections to the attacker's instance instead — effectively a MITM on database traffic without any credential.
```
# Registration abuse requires crafting a raw TNS SERVICE_REGISTER packet;
# confirm ADMIN_RESTRICTIONS_LISTENER is unset before attempting (patched
# listeners reject unauthenticated registration).
tnscmd10g services -h <target> -p 1521
```

### TNS Injection via Malformed Connect Strings

Oracle's connect-string parser has historically been vulnerable to malformed/oversized `CONNECT_DATA` structures causing parsing confusion or crashes (DoS class) — flag any oversized/malformed connect-string response inconsistency as a candidate finding, but treat active crash-testing as DoS-risk requiring a heads-up.

### PL/SQL Injection (distinct from generic SQLi)

Where a SQL injection point lands inside a PL/SQL block (anonymous block, or a vulnerable stored procedure that concatenates input into dynamic SQL via `EXECUTE IMMEDIATE`), the exploitation surface is *procedure/package execution*, not just row extraction:
```sql
-- Classic PL/SQL injection into EXECUTE IMMEDIATE
' || (SELECT some_func FROM dual) || '

-- Privilege-context abuse: a definer's-rights procedure runs with the
-- procedure owner's privileges regardless of caller — injection into a
-- SYS/SYSTEM-owned definer's-rights procedure escalates directly.
```

**`DBMS_*` package abuse** once you have any PL/SQL execution context:
- `DBMS_SCHEDULER` — schedule a job that runs OS commands (`DBMS_SCHEDULER.CREATE_JOB` with `job_type => 'EXECUTABLE'`) if the executing account has the privilege
- `UTL_HTTP` / `UTL_TCP` — SSRF primitive from inside the database, reaching internal services the DB host can route to
- `DBMS_LDAP` — similar SSRF-class primitive via LDAP calls
- `DBMS_XMLGEN` / `DBMS_XSLPROCESSOR` — historically implicated in XXE-class issues within certain versions

### Oracle-Specific Error-Based Extraction

Oracle error messages are information-dense by default; classic error-based extraction leans on functions that throw the injected value back in the error text:
```sql
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1)) --
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT password FROM dba_users WHERE rownum=1)) --
```

### Data Guard / Failover Misconfiguration

- Standby listener reachable and enumerable the same way as primary — check both
- Data Guard Broker configuration files (`dr1.dat`/`dr2.dat`) or broker port exposure leaking topology (primary/standby hostnames, SCN state)
- Role-transition triggers or apply-lag information disclosed via unauthenticated status queries if the broker listener is exposed without auth

## Testing Methodology

1. **Fingerprint the listener** — version, and whether `ADMIN_RESTRICTIONS_LISTENER` is set (registration-abuse gate).
2. **Enumerate SIDs/services** — via `tnscmd10g services`/`status` and SID brute where pre-auth enumeration is possible.
3. **Default-credential sweep** — the well-known account list above, one low-rate attempt each, against every discovered SID/service.
4. **Once authenticated (any account)** — check granted roles/privileges (`SELECT * FROM session_privs`), identify any definer's-rights procedures reachable, and check for `DBMS_SCHEDULER`/`UTL_HTTP` privilege grants as escalation/SSRF primitives.
5. **Trace injection points** — in the front-end app, distinguish generic string-concatenation SQLi from injection landing inside `EXECUTE IMMEDIATE`/dynamic PL/SQL blocks; the latter needs package-execution-context payloads, not just `UNION SELECT`.

## Validation

1. Show the exact TNS listener response (version/status output) as evidence for fingerprinting claims.
2. For default-credential findings, show the single successful low-rate authentication, and the resulting `session_privs`/role grants.
3. For PL/SQL injection, show the injected payload landing in a definer's-rights context and demonstrate (non-destructively) a resulting privileged read, not a destructive `DBMS_SCHEDULER` OS-command execution unless explicitly authorized.
4. For listener-registration/poisoning findings, confirm `ADMIN_RESTRICTIONS_LISTENER` state rather than assuming from version alone (some pre-12c installs have it manually hardened).

## False Positives

- Default account present but locked (`ACCOUNT_STATUS = LOCKED` in `dba_users`) — login will correctly fail regardless of password
- Version matches a historically-vulnerable range but the quarterly CPU patch was applied out-of-band (check `dba_registry_history` if you have query access, not just the marketing version string)
- PL/SQL injection point exists but the procedure runs with invoker's-rights (not definer's-rights) — no privilege escalation, just the caller's own access

## Impact

- Definer's-rights PL/SQL injection into a SYS/SYSTEM-owned procedure is a direct path to full database compromise from a low-privilege injection point
- TNS listener poisoning (pre-12c, unrestricted) intercepts all client-to-database traffic without any credential
- `DBMS_SCHEDULER`/`UTL_HTTP` abuse from an authenticated low-priv context can reach OS command execution or pivot into internal-network SSRF
- Default `SCOTT/tiger` or `SYSTEM/manager` left active on an enterprise instance is a critical finding on its own — these accounts often carry far more privilege than intended

## Pro Tips

1. `tnscmd10g` needs no valid SID to fingerprint a listener — always run it before anything credential-dependent.
2. Check `ADMIN_RESTRICTIONS_LISTENER` state before attempting any registration-based attack — patched listeners will simply reject it, and it's a wasted step otherwise.
3. Definer's-rights vs invoker's-rights is the single most important distinction for PL/SQL injection impact — always check which mode the target procedure runs in.
4. `DBMS_SCHEDULER` with `EXECUTABLE` job type is the cleanest OS-command-execution primitive once you have scheduler privileges — prefer it over more obscure package abuse.

## Tooling

```
sudo apt-get install -y oracle-instantclient-basic   # or download instant client manually if apt package unavailable
pip install oracledb                                  # python-oracledb, pure-Python, no instant client required for thin mode
pip install tnscmd10g                                 # or clone from GitHub if not packaged
```
- **python-oracledb** (`pip install oracledb`) — modern pure-Python driver with a "thin mode" that needs no Oracle Instant Client install; the fastest path to a working connection in the sandbox.
- **tnscmd10g** — the standard pre-auth TNS listener enumeration tool (version/status/services commands used throughout this skill).
- **sqlplus** (via Instant Client) if available — useful for interactive PL/SQL exploration once authenticated, but not required for initial recon.

## Summary

Oracle testing starts at the TNS listener, a distinct pre-auth surface generic database-testing playbooks skip entirely. Fingerprint it first, enumerate SIDs, sweep the well-documented default-account list, and once authenticated, distinguish PL/SQL injection landing in definer's-rights procedures (direct escalation) from invoker's-rights (no escalation). `DBMS_SCHEDULER` and `UTL_HTTP` are the standard privilege/SSRF pivots once you have any PL/SQL execution context.
