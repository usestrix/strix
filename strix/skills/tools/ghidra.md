---
name: ghidra
description: Operator-assisted Ghidra workflows for binary reverse engineering, vulnerability discovery, and firmware analysis
category: tools
tags: [reverse-engineering, binary-analysis, firmware, operator-assisted]
---

# Ghidra

NSA's open-source reverse engineering framework for binary analysis, decompilation, and vulnerability research. Use when analyzing compiled binaries, firmware, or thick clients for security flaws.

## When to Request

- When analyzing compiled binaries (executables, libraries, firmware) for vulnerabilities
- For reverse engineering thick client applications
- To understand custom protocols or encryption implementations
- When analyzing malware or suspicious binaries found during assessment
- For firmware extraction and analysis of IoT devices

## Operator-Assisted Workflow

1. Agent identifies binaries needing analysis (from target app, firmware, thick client)
2. Agent specifies analysis objectives (find auth bypass, crypto flaws, hardcoded secrets)
3. Operator loads binary in Ghidra, runs auto-analysis, and investigates specified areas
4. Operator reports decompiled functions, strings, and identified vulnerabilities
5. Agent uses findings to craft targeted exploits or inform further testing

## Key Workflows

### Initial Analysis
```
1. Create new project and import binary
2. Run auto-analysis (all analyzers)
3. Review Defined Strings window for hardcoded secrets, URLs, keys
4. Check Symbol Tree for imported functions (crypto, network, auth)
5. Review Function Call Graph for critical paths
```

### Vulnerability Hunting
```
# Search for dangerous functions
- strcpy, strcat, sprintf, gets (buffer overflow)
- system, exec, popen (command injection)
- memcpy with user-controlled size (heap overflow)

# Search for crypto
- AES, DES, RSA key references
- Hardcoded keys/IVs in .data/.rodata sections

# Search for auth
- strcmp for password comparison (timing attack)
- Hardcoded credentials in strings
```

### Scripting (Ghidra Python)
```python
# Find all calls to dangerous functions
from ghidra.program.model.symbol import SourceType
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.getName() in ["strcpy", "sprintf", "system"]:
        refs = getReferencesTo(func.getEntryPoint())
        for ref in refs:
            print(f"{ref.getFromAddress()} calls {func.getName()}")
```

## Analysis Targets

- **Hardcoded credentials** -- API keys, passwords, encryption keys in string tables
- **Buffer overflows** -- unsafe string/memory operations with user input
- **Authentication bypass** -- client-side auth checks that can be patched or bypassed
- **Custom protocols** -- reverse engineer wire format for fuzzing and injection
- **Crypto weaknesses** -- weak algorithms, hardcoded keys, ECB mode usage

## Output Analysis

- **Decompiled code** -- understand application logic without source
- **String references** -- hardcoded URLs, keys, credentials, debug messages
- **Function signatures** -- identify security-relevant API usage patterns
- **Control flow** -- authentication and authorization decision points
- **Binary patches** -- identify where checks can be bypassed

## Integration with Strix

- Hardcoded credentials discovered feed into authentication testing
- Reverse-engineered APIs inform Strix's web/API testing approach
- Custom protocol understanding enables targeted fuzzing
- Identified vulnerabilities in binaries complement web-layer findings
