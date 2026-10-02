# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or Discord.**

Report privately through one of these channels:

1. **GitHub private vulnerability reporting** — open the
   [Security tab](https://github.com/usestrix/strix/security) and use *Report a
   vulnerability*. This keeps the report private, gives you a thread with the
   maintainers, and can lead to a published advisory and a CVE.
2. **Email** — [hi@usestrix.com](mailto:hi@usestrix.com), with `SECURITY` in the
   subject line.

## What to include

A report is easiest to act on when it contains:

- the affected component — the CLI, the sandbox container, the agent runtime,
  the report writer, or the viewer;
- the version, from `strix --version`, and how it was installed;
- what an attacker gains, and what access they need to start;
- steps to reproduce, ideally a minimal case;
- any logs, scan artifacts, or proof-of-concept output.

Redact scan artifacts before sending them. A run directory can contain target
hostnames, captured credentials, and request bodies from whatever was scanned.

## Scope

Strix runs untrusted target content through an agent and writes artifacts a
human later opens, so the parts most worth reporting are the ones crossing that
boundary:

- sandbox escape, or anything giving the container more host access than the
  documented mounts and network policy;
- exposure of LLM API keys, proxy-captured credentials, or the MITM CA key;
- code execution or injection reached through scanned target content, including
  the generated reports — CSV, Markdown, PDF, SARIF and JSON;
- prompt injection from a target that escalates into actions outside the
  sandbox.

Findings that Strix reports about *your own* scan target are not
vulnerabilities in Strix. Neither is a scan running against a host you are not
authorised to test.

## Supported versions

Fixes land on the latest release. Given the current release cadence, upgrading
to the newest version is the supported path rather than backports to older
tags.

## Disclosure

Please give the maintainers a chance to ship a fix before publishing details.
If you would like credit in the advisory, say so in your report.
