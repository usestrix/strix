# ---------------------------------------------------------------------------
# Builder stage: compile the Go tools here so the Go toolchain (~225MB) and the
# module/build caches never reach the runtime image. The resulting binaries are
# statically linked and copied into the final stage.
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling:latest AS gobuilder

RUN apt-get update && \
    apt-get install -y kali-archive-keyring && \
    apt-get update && \
    apt-get install -y --no-install-recommends golang-go git ca-certificates

ENV GOBIN=/out/bin
ENV CGO_ENABLED=0
RUN mkdir -p /out/bin && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -v golang.org/x/vuln/cmd/govulncheck@latest

RUN git clone --depth 1 --branch v1.8.0 https://github.com/projectdiscovery/katana.git /tmp/katana && \
    cd /tmp/katana && \
    go get github.com/jackc/pgx/v5@v5.9.0 && \
    go mod tidy && \
    go build -o /out/bin/katana ./cmd/katana

RUN GOBIN=/out/gitleaks go install -v -ldflags "-X github.com/zricethezav/gitleaks/v8/version.Version=8.30.1" github.com/zricethezav/gitleaks/v8@v8.30.1

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling:latest

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo,0 pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

# HOME is explicit (not left to /etc/passwd's NSS lookup): under OpenShift
# restricted SCC the container runs as an arbitrary UID with no /etc/passwd
# entry, so ${HOME} must resolve from the environment alone.
ENV HOME=/home/pentester

RUN mkdir -p /home/pentester/tools /home/pentester/certs && \
    chown -R pentester:pentester /home/pentester/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    software-properties-common \
    gcc libc6-dev \
    python3 python3-pip python3-venv python3-setuptools \
    net-tools dnsutils whois \
    file xxd \
    jq parallel ripgrep grep \
    less procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    nodejs npm pipx \
    golang-go \
    libcap2-bin \
    gdb \
    libnss3-tools \
    chromium fonts-liberation


# Move the real binary aside and put a capability-aware wrapper on PATH ahead
# of it (see nmap-wrapper.sh): file capabilities can only become effective if
# the *calling process's* capability bounding set already has them, so under a
# restricted-SCC Pod (no NET_ADMIN/NET_RAW in the bounding set) `setcap` alone
# is a no-op at exec time regardless of these bits — the wrapper detects that
# and degrades -sS to -sT instead of letting the scan fail outright. Under the
# Docker backend, which does grant NET_RAW/NET_ADMIN, the wrapper is a
# passthrough and these bits behave exactly as before.
RUN mkdir -p /usr/lib/strix-tools && \
    mv "$(which nmap)" /usr/lib/strix-tools/nmap && \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/lib/strix-tools/nmap
COPY --chmod=0755 containers/nmap-wrapper.sh /usr/local/bin/nmap

USER pentester
RUN openssl ecparam -name prime256v1 -genkey -noout -out /home/pentester/certs/ca.key && \
    openssl req -x509 -new -key /home/pentester/certs/ca.key \
    -out /home/pentester/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /home/pentester/certs/ca.p12 \
    -inkey /home/pentester/certs/ca.key \
    -in /home/pentester/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /home/pentester/certs/ca.crt && \
    chmod 600 /home/pentester/certs/ca.key && \
    chmod 600 /home/pentester/certs/ca.p12

USER root
RUN cp /home/pentester/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

USER pentester
WORKDIR /tmp

# Go tools are built in the gobuilder stage; copy the static binaries only.
COPY --from=gobuilder --chown=pentester:pentester /out/bin/ /home/pentester/go/bin/

RUN nuclei -update-templates

RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch 'setuptools<81' && \
    pipx install wafw00f

ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

RUN npm install -g retire@latest && \
    npm install -g eslint@latest && \
    npm install -g js-beautify@latest && \
    npm install -g @ast-grep/cli@latest && \
    npm install -g tree-sitter-cli@latest && \
    npm install -g agent-browser@0.26.0 && \
    npm cache clean --force && \
    # ast-grep ships two identical binaries (`ast-grep` and `sg`); dedupe (~52MB)
    ln -sf ast-grep /home/pentester/.npm-global/lib/node_modules/@ast-grep/cli/sg

ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ENV AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US"
ENV AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots
ENV AGENT_BROWSER_IDLE_TIMEOUT_MS=180000
USER root
RUN set -eu; \
    { \
        for var in AGENT_BROWSER_EXECUTABLE_PATH AGENT_BROWSER_USER_AGENT \
                   AGENT_BROWSER_ARGS AGENT_BROWSER_SCREENSHOT_DIR \
                   AGENT_BROWSER_IDLE_TIMEOUT_MS; do \
            eval "value=\${$var}"; \
            printf 'export %s="${%s:-%s}"\n' "$var" "$var" "$value"; \
        done; \
    } > /tmp/agent-browser.sh; \
    install -m 0644 /tmp/agent-browser.sh /etc/profile.d/agent-browser.sh; \
    rm /tmp/agent-browser.sh; \
    env -i bash -lc 'test "${AGENT_BROWSER_IDLE_TIMEOUT_MS}" = "180000"'
USER pentester
RUN /home/pentester/.npm-global/bin/agent-browser doctor --offline --quick

RUN set -eux; \
    TS_PARSER_DIR="/home/pentester/.tree-sitter/parsers"; \
    mkdir -p "${TS_PARSER_DIR}"; \
    for repo in tree-sitter-java tree-sitter-javascript tree-sitter-python tree-sitter-go tree-sitter-bash tree-sitter-json tree-sitter-yaml tree-sitter-typescript; do \
        if [ "$repo" = "tree-sitter-yaml" ]; then \
            repo_url="https://github.com/tree-sitter-grammars/${repo}.git"; \
        else \
            repo_url="https://github.com/tree-sitter/${repo}.git"; \
        fi; \
        if [ ! -d "${TS_PARSER_DIR}/${repo}" ]; then \
            git clone --depth 1 "${repo_url}" "${TS_PARSER_DIR}/${repo}"; \
        fi; \
    done; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" "${TS_PARSER_DIR}/tree-sitter-typescript-typescript"; \
    fi; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" "${TS_PARSER_DIR}/tree-sitter-typescript-tsx"; \
    fi; \
    tree-sitter init-config >/dev/null 2>&1 || true; \
    TS_CONFIG="/home/pentester/.config/tree-sitter/config.json"; \
    mkdir -p "$(dirname "${TS_CONFIG}")"; \
    [ -f "${TS_CONFIG}" ] || printf '{}\n' > "${TS_CONFIG}"; \
    TMP_CFG="$(mktemp)"; \
    jq --arg p "${TS_PARSER_DIR}" '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' "${TS_CONFIG}" > "${TMP_CFG}"; \
    mv "${TMP_CFG}" "${TS_CONFIG}"

WORKDIR /home/pentester/tools
RUN git clone https://github.com/aravind0x7/JS-Snooper.git && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone https://github.com/xchopath/jsniper.sh.git && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone https://github.com/ticarpi/jwt_tool.git && \
    chmod +x jwt_tool/jwt_tool.py

USER root

# Install trufflehog into a pentester-owned dir on PATH so its runtime self-update
# (which replaces the binary in place) succeeds: as non-root `pentester` it cannot
# overwrite a root-owned binary under /usr/local/bin, which otherwise fails with
# "cannot move binary" and aborts the scan. Pin the initial version for
# reproducible builds; self-update then pulls fresh detectors at runtime.
ARG TRUFFLEHOG_VERSION=3.99.2
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /home/pentester/.local/bin "v${TRUFFLEHOG_VERSION}" && \
    chown -R pentester:pentester /home/pentester/.local
COPY --from=gobuilder /out/gitleaks/gitleaks /usr/local/bin/gitleaks

ARG TRIVY_VERSION=0.76.1
ARG TRIVY_SHA256_X86=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
ARG TRIVY_SHA256_AARCH64=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f
RUN set -eux; \
    case "$(uname -m)" in \
        x86_64) TRIVY_ARCH="64bit"; TRIVY_SHA256="${TRIVY_SHA256_X86}" ;; \
        aarch64|arm64) TRIVY_ARCH="ARM64"; TRIVY_SHA256="${TRIVY_SHA256_AARCH64}" ;; \
        *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tgz; \
    echo "${TRIVY_SHA256}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f /tmp/trivy /tmp/trivy.tgz; \
    trivy --version

# CodeQL — the *bundle* (CLI + precompiled standard query packs), not the bare
# CLI: the bare CLI resolves query packs from the registry at analyze time,
# which costs network egress on every scan and breaks outright in an
# egress-restricted Pod. Pinned rather than :latest so a scan's results are
# reproducible against a known query set. ~1-2GB extracted — by far the
# largest single tool here; drop this block if image size matters more than
# taint-tracking depth (semgrep already covers breadth).
#
# Licensing: the CodeQL CLI is free for open source on public repos and for
# academic research; running it against private proprietary code requires
# GitHub Advanced Security. Confirm entitlement before enabling this in a
# pipeline that scans private repositories.
ARG CODEQL_BUNDLE_VERSION=v2.23.2
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) CODEQL_ARCH="linux64" ;; \
        aarch64|arm64) CODEQL_ARCH="linux-arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/github/codeql-action/releases/download/codeql-bundle-${CODEQL_BUNDLE_VERSION}/codeql-bundle-${CODEQL_ARCH}.tar.gz" -o /tmp/codeql.tgz; \
    mkdir -p /opt; \
    tar -xzf /tmp/codeql.tgz -C /opt; \
    rm -f /tmp/codeql.tgz; \
    ln -sf /opt/codeql/codeql /usr/local/bin/codeql; \
    codeql version --format=terse

RUN apt-get install -y wapiti

# CVE-2026-111497: out-of-bounds write in the brotli decoder, fixed in brotli
# 1.2.1 / Debian 1.2.0-4.1. kali-rolling still ships 1.2.0-4, and node, curl and
# python3 in this image all load the shared libbrotlidec, so every HTTP client here
# would decode a malicious `Content-Encoding: br` response with the vulnerable
# code. Install the fixed Debian packages until Kali picks them up.
ARG BROTLI_DEB_VERSION=1.2.0-4.1
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    for pkg in libbrotli1 python3-brotli; do \
        curl -fsSL "https://deb.debian.org/debian/pool/main/b/brotli/${pkg}_${BROTLI_DEB_VERSION}_${ARCH}.deb" -o "/tmp/${pkg}.deb"; \
    done; \
    dpkg -i /tmp/libbrotli1.deb /tmp/python3-brotli.deb; \
    rm -f /tmp/libbrotli1.deb /tmp/python3-brotli.deb; \
    test "$(dpkg-query -W -f='${Version}' libbrotli1)" = "${BROTLI_DEB_VERSION}"; \
    node -e 'const z=require("zlib");z.brotliDecompressSync(z.brotliCompressSync(Buffer.from("ok")))'

ARG OPENGREP_VERSION=1.31.0
ARG OPENGREP_SHA256_X86=dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147
ARG OPENGREP_SHA256_AARCH64=2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d
RUN set -eux; \
    case "$(uname -m)" in \
        x86_64) OPENGREP_ARCH="x86"; OPENGREP_SHA256="${OPENGREP_SHA256_X86}" ;; \
        aarch64|arm64) OPENGREP_ARCH="aarch64"; OPENGREP_SHA256="${OPENGREP_SHA256_AARCH64}" ;; \
        *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_${OPENGREP_ARCH}" -o /tmp/opengrep; \
    echo "${OPENGREP_SHA256}  /tmp/opengrep" | sha256sum -c -; \
    install -m 0755 /tmp/opengrep /usr/local/bin/opengrep; \
    rm -f /tmp/opengrep; \
    opengrep --version

# Opengrep ships no rule registry of its own; bake the community ruleset so
# scans run offline. Keep only rule YAML and LICENSE; drop tests, fixtures,
# tooling, and rules marked with a proprietary license.
ARG OPENGREP_RULES_REF=f1d2b562b414783763fd02a6ed2736eaed622efa
RUN set -eux; \
    mkdir -p /opt/opengrep-rules; \
    curl -fsSL "https://codeload.github.com/opengrep/opengrep-rules/tar.gz/${OPENGREP_RULES_REF}" \
        | tar -xz --strip-components=1 -C /opt/opengrep-rules; \
    cd /opt/opengrep-rules; \
    rm -rf .github scripts stats; \
    find . -maxdepth 1 -type f ! -name LICENSE -delete; \
    find . -mindepth 2 -type f \( ! \( -name '*.yaml' -o -name '*.yml' \) -o -name '*.test.yaml' -o -name '*.test.yml' -o -name '.*' \) -delete; \
    grep -rlZ 'license: proprietary' . | xargs -0 -r rm -f; \
    find . -type d -empty -delete; \
    chmod -R a+rX /opt/opengrep-rules

# Strix-authored rules that close gaps in the community ruleset.
COPY containers/opengrep-rules/ /opt/opengrep-rules/strix/
RUN chmod -R a+rX /opt/opengrep-rules/strix

USER pentester

RUN pipx install bandit

RUN npm install -g jshint

USER root

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    # Purge non-English locales (~160MB)
    find /usr/share/locale -mindepth 1 -maxdepth 1 -type d \
        ! -name 'en' ! -name 'en_US' ! -name 'C' -exec rm -rf {} + && \
    # Remove package documentation and man pages not needed at runtime (~95MB)
    rm -rf /usr/share/doc/* /usr/share/doc-base/* /usr/share/man/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

WORKDIR /app

ARG CAIDO_VERSION=0.56.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -O caido-cli.tar.gz "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

USER pentester
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir caido-sdk-client && \
    /app/.venv/bin/pip install --no-cache-dir \
        requests httpx beautifulsoup4 lxml pyjwt cryptography && \
    /app/.venv/bin/pip install --no-cache-dir -r /home/pentester/tools/jwt_tool/requirements.txt && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool

COPY --chown=pentester:pentester strix/tools/proxy/caido_api.py /opt/strix-python/caido_api.py
ENV PYTHONPATH=/opt/strix-python

# Orchestrator + tools, one image: install the strix-agent package itself
# into the same venv the tools above use, so a single Pod (no Docker daemon,
# no sibling sandbox container) can run `strix ...` directly — see
# STRIX_RUNTIME_BACKEND=local / strix/runtime/local_backend.py, which execs
# tools in-process against this same filesystem instead of `docker exec`-ing
# into a separate container.
#
# -e (editable): pyproject.toml's hatchling build hook (scripts/
# tui_sidecar_hook.py) compiles the Go Bubble Tea TUI sidecar into a regular
# wheel — unnecessary weight/toolchain/network dependency for this image,
# whose whole point is `strix -n ...` (non-interactive; see k8s/job.yaml).
# The hook explicitly no-ops for `pip install -e` (its own
# `if version == "editable": return"), which is exactly what we want here.
# The hook script still needs to be present for hatchling to invoke it at
# all, so it's copied alongside pyproject.toml even though it never runs.
COPY --chown=pentester:pentester pyproject.toml uv.lock README.md /app/strix-src/
COPY --chown=pentester:pentester scripts/ /app/strix-src/scripts/
COPY --chown=pentester:pentester strix/ /app/strix-src/strix/
RUN /app/.venv/bin/pip install --no-cache-dir -e /app/strix-src

# GridFS storage (artifact upload/download for the orchestrator and the
# fetch-target initContainer) is not a strix package dependency: only the
# container entrypoints need it.
RUN /app/.venv/bin/pip install --no-cache-dir "pymongo>=4.14"

# Login shells (e.g. `bash -lc`) source /etc/profile, which on Debian/Kali
# hard-resets PATH and drops the image's ENV PATH entries. Re-add the same
# directories here — including /app/.venv/bin — so `python3`/`pip` resolve to
# the venv (which ships requests, httpx, bs4, lxml, pyjwt, cryptography, and the
# Caido SDK) instead of the externally-managed system interpreter.
RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# --- Arbitrary-UID (OpenShift restricted SCC) support -----------------------
# The container may run as any UID the platform assigns, always as a member
# of GID 0. Normalize every path the workload writes to (plus the handful of
# /etc files the entrypoint optionally refreshes proxy settings into) to
# group-owned/group-writable so no sudo/chown/setcap is needed at runtime —
# entrypoint.sh only ever reads STRIX_HOST_UID/GID to match host bind-mount
# ownership for the classic Docker backend, a case that needs (and already
# has, via setpriv while still root) real root, not a GID-0 workaround.
# /usr/lib/strix-tools (the real nmap binary) is intentionally excluded:
# chown/chgrp clears a file's capability xattr, which would silently undo the
# setcap above.
RUN chgrp -R 0 /home/pentester /app /workspace /etc/passwd /etc/group /etc/profile.d && \
    chmod -R g=u /home/pentester /app /workspace && \
    chmod g=u /etc/passwd /etc/group /etc/profile.d && \
    touch /etc/environment /etc/wgetrc && \
    chgrp 0 /etc/environment /etc/wgetrc && \
    chmod g=u /etc/environment /etc/wgetrc

# Default USER is root (not pentester): entrypoint.sh needs it to drop
# privileges itself via setpriv without sudo (see its top section). OpenShift
# restricted SCC overrides this with its own arbitrary non-root UID
# regardless of what's declared here — this default only matters for a plain
# `docker run`, where it reproduces the previous sudo-based behavior exactly.
USER root
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
