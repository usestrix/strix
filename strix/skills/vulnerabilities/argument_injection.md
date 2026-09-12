---
name: argument-injection
description: Test shell-free command argument injection across argv builders and CLI parsers, including option smuggling, response/config-file parsing, argument-boundary reparsing, and Windows Unicode-to-ANSI Best-Fit transformations
---

# Argument Injection

Use this skill when attacker-influenced data reaches a trusted command-line program, even when no shell is involved. The security question is whether the input changes the program's **option set, operands, configuration, subcommand, or downstream parser state**.

Load `rce` when a shell parses the command string. Load `semantic_confusion` when validation and the final CLI/filesystem/configuration consumer see different representations.

## Model Every Parser Boundary

Build the actual transformation chain:

```text
request value
  -> application validation
  -> argv builder or command-line string serializer
  -> OS/process creation API
  -> runtime argv construction
  -> target option parser
  -> response/config/auth file parser, URL parser, or subcommand
```

Do not treat all process APIs alike:

- POSIX `execve(path, argv, envp)` and list-form subprocess APIs preserve array-element boundaries. Whitespace inside one element does not create another argument.
- Shell/string forms introduce shell tokenization before the target program sees `argv`.
- Windows process creation commonly serializes an argument array into one command-line string and lets the child runtime parse it back. Quoting rules differ across CRTs and applications.
- Some programs deliberately reparse an argument as a response file, configuration file, URL, expression, template, or nested command language.

Record the exact API, platform, runtime, target binary/version, option parser, and final `argv` observed by the child.

## Primitive 1: Option and Subcommand Injection

An attacker-controlled value placed where an operand is expected can be interpreted as an option when it begins with an option prefix:

```text
intended: ["tool", USER_VALUE]
supplied: USER_VALUE = "--output=/controlled/path"
actual:   tool parses an output option instead of an operand
```

Inventory security-relevant option classes rather than memorizing one payload:

- output, upload, extraction, log, cache, plugin, template, or configuration paths
- alternate URL schemes, proxies, certificates, credentials, and authentication files
- hooks, helpers, filters, interpreters, external programs, or dynamic libraries
- config overrides, environment definitions, working directories, and search paths
- subcommands that expose administrative, import/export, restore, diagnostic, or execution features

Check whether the target supports `--` as an end-of-options marker and whether the application places it before the untrusted operand. Do not assume every CLI honors `--`, or that it applies after a subcommand switches to a second parser.

## Primitive 2: Argument-Boundary Breakout

Require a component that reparses or reconstructs arguments. Candidate boundaries include:

- shell or command-string construction
- Windows quoting/escaping mismatches between parent and child runtimes
- newline-, NUL-, delimiter-, or quote-sensitive custom launchers
- wrappers that join an array and later split it
- CGI/interpreter mappings that turn request data into command-line options

Distinguish these outcomes:

```text
["tool", "user --flag"]       # one argv element; no split by execve
["tool", "user", "--flag"]  # extra argv element reached the target
["tool", "@args.txt"]        # one element, then reparsed by the target
```

Logs often render arrays as strings and can falsely suggest splitting. Capture the child's real arguments through source instrumentation, a wrapper process, debugger, audit trace, `/proc/<pid>/cmdline`, or the platform equivalent.

## Primitive 3: Response, Config, and Authentication Files

Many trusted programs consume a second language after argv parsing:

- `@response-file` syntax used by compilers, linkers, JVM tooling, and custom launchers
- `--config`, `-K`, credentials/auth files, include files, and rc/profile paths
- newline-delimited key/value files generated from attacker-controlled fields
- file contents where control characters create a new directive, identity, host, or option

Trace both attacker influence over the **file path** and influence over the **file content**. Correct shell quoting does not protect a file that is later tokenized by a different grammar. Record duplicate-key behavior, newline rules, comments, escaping, include directives, and first/last-value precedence.

## Windows Unicode-to-ANSI Best-Fit

On Windows, narrow-character APIs and CRT startup paths can convert Unicode command-line, environment, or filesystem data into an ANSI code page. Best-Fit mappings may introduce ASCII characters after earlier validation.

Relevant boundaries include:

- `GetCommandLineA` or a narrow `main(int, char **)` startup path
- `GetEnvironmentVariableA`, `GetCurrentDirectoryA`, and narrow filesystem APIs
- framework or native-extension transitions from UTF-16 strings to an ANSI code page

`CommandLineToArgvW` is the documented Windows command-line parser; there is no documented `CommandLineToArgvA`. Determine which CRT or application-specific parser constructs narrow `argv`.

Treat mappings as code-page-specific hypotheses, not universal payloads. Candidate transformations include soft hyphen to `-`, fullwidth/compatibility slash characters to `/` or `\`, and compatibility quotes or letters to ASCII equivalents. Capture:

- submitted Unicode code points and encoded bytes
- active system/process code page
- wide string before conversion
- narrow bytes and final `argv` or filesystem path after conversion

Using wide-character APIs removes this particular conversion boundary but does not fix ordinary option injection.

## Reconnaissance

In source, locate process creation and work forward into the consumer:

```text
exec*  posix_spawn  subprocess  ProcessBuilder  Runtime.exec
CreateProcess  ShellExecute  child_process  os/exec  Command
```

For each attacker-controlled argument, answer:

1. Is it a distinct argv element or part of a command string?
2. Can it begin with the target's option prefix?
3. Is an end-of-options marker supported and correctly positioned?
4. Does a wrapper, CRT, shell, or target reparse it?
5. Can it select a response/config/auth file or inject directives into one?
6. Which target option or subcommand turns that control into read, write, request, identity, or execution capability?

For black-box testing, compare an ordinary operand with option-prefixed, delimiter-bearing, control-character, and platform-specific Unicode variants. Match tests to options that actually exist in the deployed binary/version.

## Validation

- Show the final `argv` or secondary parser input, not only the application log line.
- Pair the candidate with a control where the same bytes remain a literal operand.
- Demonstrate the exact option, directive, subcommand, path, or handler selected.
- Reproduce against the deployed binary, runtime, code page, and configuration.
- Separate option control, additional-argument control, arbitrary directive control, and command execution; they are different primitives.

## False Positives

- The input is one argv element and the target treats it only as a positional operand.
- `--` is supported, placed before the value, and not bypassed by a subparser.
- A strict allowlist prevents option prefixes and all later transformations preserve it.
- A delimiter appears only in logging or display formatting.
- A response/config path is controllable but its contents or directives are not.
- A Unicode character is accepted but no narrow/Best-Fit conversion occurs.
- The injected option exists on another release or platform but not the deployed target.

## Remediation

- Use argument-array process APIs and avoid shell/string construction.
- Insert `--` before untrusted operands where every relevant parser supports it.
- Validate operands against the target CLI's grammar, not a generic shell blacklist.
- Fix security-sensitive option names and configuration paths in trusted code.
- Generate configuration/auth files with a format-aware serializer that rejects control characters and ambiguous duplicates.
- On Windows, keep data in wide-character APIs and verify child-runtime parsing rules.
- Enforce authorization again at the privileged operation selected by the CLI.

## Summary

Argument injection is control of a trusted program's behavior through its argv or a parser reached from argv. Preserve parser boundaries in the model: list-form execution, command-string tokenization, Windows runtime conversion, option parsing, and response/config-file parsing are distinct stages with distinct exploit conditions.
