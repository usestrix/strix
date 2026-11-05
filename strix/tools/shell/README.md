# shell — `exec_command` + `write_stdin`

SDK-provided shell tools wired per-run from the sandbox session. Every CLI
invocation the agent makes (nmap, ffuf, agent-browser, python3, …) goes
through `exec_command`. `write_stdin` streams input to a still-running
process started by an earlier `exec_command` (for interactive prompts).

## Reading a running command and typing into it

`exec_command` runs each command in a fresh **non-interactive** shell (plain
pipes, no TTY) by default and waits at most 30 s for output. A command still
running at that point keeps running; read the rest of its output and its exit
code with an empty write:

```text
exec_command(cmd="nmap -sV 10.0.0.5")      # returns "Process running with session ID <id>"
write_stdin(session_id=<id>, chars="")     # returns the new output, or the exit code
```

Typing into a process needs a PTY:

```text
exec_command(cmd="python3", tty=true)      # start a PTY-backed process
write_stdin(session_id=<id>, chars="print(1)\n")
```

Non-empty `chars` on a command started with the default `tty=false`, or on a
process that has already exited, fails with
`stdin is not available for this process. Start the command with 'tty=true' in
'exec_command' before using 'write_stdin'.` Use `tty=true` for REPLs,
`ssh`/`nc`/`ftp`, `msfconsole`, or to deliver a Ctrl-C to a long-running job.

- **Implementation:** `agents.sandbox.capabilities.tools.shell_tool.ShellTool`
  (in the upstream `agents` SDK)
- **Wired in:** `strix/agents/factory.py` — added per-run via the SDK
  `Shell` capability; `write_stdin` is wrapped to drop the SDK's `pid`
  arg from the function schema.
- **Sandbox env:** `http_proxy` / `https_proxy` route every shell child
  through Caido; `AGENT_BROWSER_*`, `REQUESTS_CA_BUNDLE` etc. come from
  `containers/Dockerfile`.
