---
name: volatility
description: Operator-assisted Volatility workflows for memory forensics, credential extraction, and process analysis
category: tools
tags: [forensics, memory-analysis, credentials, operator-assisted]
---

# Volatility

Memory forensics framework for analyzing RAM dumps. Extract credentials, processes, network connections, and artifacts from memory images. Use during post-exploitation or incident analysis.

## When to Request

- After obtaining a memory dump from a compromised system
- For extracting credentials from memory (mimikatz-style without running on target)
- To analyze running processes and network connections from a memory snapshot
- During forensic analysis of compromised systems

## Operator-Assisted Workflow

1. Agent determines analysis objectives (credentials, processes, network, malware)
2. Agent provides Volatility commands for the target OS profile
3. Operator runs analysis on the memory dump and provides results
4. Agent correlates findings: credentials for lateral movement, processes for persistence
5. Agent directs follow-up based on memory artifacts

## Key Commands (Volatility 3)

### Profile Detection
```
vol -f memory.dmp windows.info
vol -f memory.dmp linux.bash
```

### Process Analysis
```
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.cmdline
vol -f memory.dmp windows.dlllist --pid PID
```

### Credential Extraction
```
vol -f memory.dmp windows.hashdump
vol -f memory.dmp windows.lsadump
vol -f memory.dmp windows.cachedump
```

### Network Connections
```
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.netstat
```

### File Extraction
```
vol -f memory.dmp windows.filescan
vol -f memory.dmp windows.dumpfiles --pid PID
```

### Registry Analysis
```
vol -f memory.dmp windows.registry.hivelist
vol -f memory.dmp windows.registry.printkey --key "SAM\Domains\Account\Users"
```

### Malware Detection
```
vol -f memory.dmp windows.malfind
vol -f memory.dmp windows.vadinfo --pid PID
```

## Output Analysis

- **Password hashes** -- NTLM, cached domain creds; crack with Hashcat or relay
- **Running processes** -- identify security tools, services, and suspicious processes
- **Network connections** -- active sessions, C2 channels, lateral movement evidence
- **Loaded DLLs** -- injected code, hooking, persistence mechanisms
- **Registry data** -- cached credentials, autorun entries, service configurations
- **File artifacts** -- extracted documents, configs, and temporary files

## Integration with Strix

- Extracted hashes feed into Hashcat/John for offline cracking
- Discovered credentials enable authenticated testing across networked services
- Network connection data reveals internal services for expanded Strix scope
- Process and service analysis informs post-exploitation strategy

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
volatility [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
