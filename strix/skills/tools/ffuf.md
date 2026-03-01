---
name: ffuf
description: Operator-assisted FFUF workflows for web fuzzing including directory discovery, parameter mining, and virtual host enumeration
category: tools
tags: [fuzzing, enumeration, recon, operator-assisted]
---

# FFUF

Fast web fuzzer for content discovery, parameter brute-forcing, header fuzzing, and virtual host enumeration. More flexible than Gobuster with multi-position fuzzing and advanced filtering.

## When to Request

- When flexible fuzzing positions are needed (URL, headers, POST body, cookies)
- Parameter discovery on API endpoints
- Subdomain and vhost enumeration with response filtering
- When response-based filtering is needed (size, words, lines, regex)

## Operator-Assisted Workflow

1. Agent identifies fuzzing targets and positions from application analysis
2. Agent crafts FFUF command with appropriate wordlist, position, and filters
3. Operator runs FFUF and provides output (prefer `-of json`)
4. Agent analyzes results, filtering false positives by response characteristics
5. Agent directs follow-up testing on discovered endpoints/parameters

## Key Commands

### Directory Discovery
```
ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -of json -o ffuf_dir.json
```

### Parameter Discovery (GET)
```
ffuf -u "https://TARGET/api/endpoint?FUZZ=test" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404 -of json -o params.json
```

### Parameter Discovery (POST)
```
ffuf -u https://TARGET/api/endpoint -X POST -d '{"FUZZ":"test"}' -H "Content-Type: application/json" -w params_wordlist.txt -mc all -fc 400 -of json -o post_params.json
```

### Subdomain Enumeration
```
ffuf -u https://FUZZ.target.com -w subdomains.txt -mc 200 -fs 0 -of json -o subdomains.json
```

### Virtual Host Discovery
```
ffuf -u https://TARGET -H "Host: FUZZ.target.com" -w subdomains.txt -mc 200 -fs SIZE_OF_DEFAULT -of json -o vhosts.json
```

### Multi-Position Fuzzing
```
ffuf -u https://TARGET/FUZZ1/FUZZ2 -w endpoints.txt:FUZZ1 -w ids.txt:FUZZ2 -mc 200 -of json -o multi.json
```

### Header Fuzzing
```
ffuf -u https://TARGET/admin -H "X-Custom-Header: FUZZ" -w values.txt -mc 200 -of json -o headers.json
```

## Filtering Options

- **`-mc`** -- match HTTP status codes (e.g., `-mc 200,301`)
- **`-fc`** -- filter (exclude) status codes (e.g., `-fc 404,403`)
- **`-fs`** -- filter by response size (exclude baseline size)
- **`-fw`** -- filter by word count
- **`-fl`** -- filter by line count
- **`-fr`** -- filter by regex pattern in response
- **`-ft`** -- filter by response time

## Output Analysis

- **Unique response sizes** -- different sizes from baseline indicate real content
- **Status code patterns** -- 200s are hits; 302 to login reveals auth-required paths; 500s suggest bugs
- **Discovered parameters** -- hidden params may bypass client-side restrictions or enable debug modes
- **Timing anomalies** -- slow responses may indicate backend processing worth investigating
- **Virtual hosts** -- different response from default host indicates distinct application

## Integration with Strix

- Discovered endpoints and parameters feed into targeted vulnerability testing via proxy
- Hidden parameters on API endpoints inform injection and access control testing
- Virtual hosts discovered expand the scope for Strix assessments
- Parameter names found here help craft targeted payloads for SQLi, XSS, IDOR testing
