---
name: owasp-zap
description: Operator-assisted OWASP ZAP workflows for automated web scanning, spidering, fuzzing, and API security testing
category: tools
tags: [proxy, web, scanning, open-source, operator-assisted]
---

# OWASP ZAP

Open-source web application security scanner with automated scanning, spidering, fuzzing, and API import. Free alternative to Burp Suite with strong CI/CD integration and API support.

## When to Request

- For automated web vulnerability scanning (free alternative to Burp active scanner)
- OpenAPI/Swagger import for API security testing
- When ZAP-specific features are needed (Ajax Spider, Fuzzer, scripting engine)
- CI/CD pipeline security testing integration

## Operator-Assisted Workflow

1. Agent identifies web targets and API specifications
2. Agent provides ZAP configuration: target URLs, authentication, scan policy
3. Operator runs ZAP (GUI or CLI) and provides scan results
4. Agent triages findings by confidence and risk
5. Agent directs manual verification of confirmed vulnerabilities

## Key Commands

### CLI Quick Scan
```
zap-cli quick-scan -s all -r https://TARGET -o report.html
```

### Full Scan (Docker)
```
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t https://TARGET -r report.html -J report.json
```

### API Scan (OpenAPI)
```
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t https://TARGET/openapi.json -f openapi -r api_report.html -J api_report.json
```

### Baseline Scan (Fast)
```
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://TARGET -r baseline.html -J baseline.json
```

### ZAP API (Automation)
```
# Start scan
curl "http://localhost:8080/JSON/ascan/action/scan/?url=https://TARGET&apikey=APIKEY"

# Get scan status
curl "http://localhost:8080/JSON/ascan/view/status/?scanId=0&apikey=APIKEY"

# Get alerts
curl "http://localhost:8080/JSON/core/view/alerts/?baseurl=https://TARGET&apikey=APIKEY"
```

### Authenticated Scanning
```
# Configure authentication in ZAP context
# Set login URL, credentials, logged-in indicator
# Spider and scan within authenticated context
```

## Output Analysis

- **High confidence alerts** -- likely true positives; verify and exploit
- **Medium confidence** -- need manual verification; may be false positives
- **Informational findings** -- security headers, technology detection; note for hardening recommendations
- **API-specific findings** -- broken authentication, injection in API parameters, mass assignment

## Integration with Strix

- ZAP scan results identify vulnerability types for targeted Strix agent testing
- API specification import ensures comprehensive API endpoint coverage
- ZAP findings complement Strix's manual testing with automated breadth
- JSON reports can be parsed to prioritize Strix's exploitation efforts

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
owasp-zap [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
