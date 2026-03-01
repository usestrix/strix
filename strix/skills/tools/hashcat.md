---
name: hashcat
description: Operator-assisted Hashcat workflows for GPU-accelerated offline password cracking with advanced attack modes
category: tools
tags: [password, cracking, gpu, credentials, operator-assisted]
---

# Hashcat

GPU-accelerated password cracker. Faster than John the Ripper for large hash sets. Supports 350+ hash types, multiple attack modes (dictionary, combinator, mask, hybrid), and rule engines.

## When to Request

- When large numbers of hashes need cracking (GPU speed advantage)
- For targeted mask attacks when password policy is known (length, charset)
- When advanced attack modes are needed (combinator, hybrid, prince)
- After John fails to crack remaining hashes; Hashcat's GPU may succeed with different approaches

## Operator-Assisted Workflow

1. Agent provides hashes and identifies the hash type (mode number)
2. Agent specifies attack mode and parameters based on known password policy
3. Operator runs Hashcat with GPU and reports results
4. Operator reports cracked passwords and session status
5. Agent uses credentials for further exploitation and credential reuse testing

## Key Commands

### Dictionary Attack
```
hashcat -m MODE -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```

### With Rules
```
hashcat -m MODE -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked.txt
```

### Mask Attack (Brute Force with Pattern)
```
# 8-char lowercase+digit
hashcat -m MODE -a 3 hashes.txt ?l?l?l?l?l?l?d?d -o cracked.txt

# Custom charset
hashcat -m MODE -a 3 hashes.txt -1 ?l?u?d ?1?1?1?1?1?1?1?1 -o cracked.txt
```

### Combinator Attack
```
hashcat -m MODE -a 1 hashes.txt wordlist1.txt wordlist2.txt -o cracked.txt
```

### Hybrid (Wordlist + Mask)
```
hashcat -m MODE -a 6 hashes.txt rockyou.txt ?d?d?d -o cracked.txt
hashcat -m MODE -a 7 hashes.txt ?d?d?d rockyou.txt -o cracked.txt
```

### Common Hash Modes
```
-m 0      MD5
-m 100    SHA1
-m 1000   NTLM
-m 1800   sha512crypt (Linux)
-m 3200   bcrypt
-m 5600   NetNTLMv2
-m 13100  Kerberos TGS-REP (Kerberoasting)
-m 18200  Kerberos AS-REP (ASREPRoasting)
-m 22000  WPA-PBKDF2-PMKID+EAPOL
```

### Session Management
```
hashcat --session=mycrack -m MODE -a 0 hashes.txt wordlist.txt
hashcat --session=mycrack --restore
hashcat --session=mycrack --show
```

## Mask Charsets

- `?l` lowercase, `?u` uppercase, `?d` digit, `?s` special, `?a` all, `?b` binary
- Custom: `-1 ?l?d` then use `?1` in mask

## Output Analysis

- **Cracked passwords** -- immediate credential reuse testing across all services
- **Cracking speed** -- if too slow, the hash type may be strong (bcrypt, argon2); note for reporting
- **Exhausted keyspace** -- password not in wordlist or mask range; try different attack strategy
- **Partial results** -- weak passwords crack first; adjust rules/masks for remaining

## Integration with Strix

- Hashes from Strix exploitation feed into Hashcat for GPU-accelerated cracking
- Cracked credentials enable authenticated application testing
- Password policy assessment based on cracking difficulty informs security recommendations
- NetNTLM and Kerberos hashes from AD testing feed directly into Hashcat

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
hashcat [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
