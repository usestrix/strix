---
name: john-the-ripper
description: Operator-assisted John the Ripper workflows for offline password cracking with wordlists, rules, and format detection
category: tools
tags: [password, cracking, credentials, operator-assisted]
---

# John the Ripper

Offline password cracker supporting hundreds of hash formats with wordlist, incremental, and rule-based attacks. Use when password hashes are obtained from database dumps, config files, or network captures.

## When to Request

- After extracting password hashes from databases (SQLi, backup files)
- When /etc/shadow or SAM/NTDS.dit hashes are obtained
- For cracking hashes found in config files, application databases, or network captures
- To test password policy strength with rule-based attacks

## Operator-Assisted Workflow

1. Agent obtains hashes via exploitation (SQLi, file read, credential dump)
2. Agent identifies hash format and provides John command with appropriate settings
3. Operator runs John with specified wordlist and rules
4. Operator reports cracked passwords
5. Agent tests cracked credentials against all services (credential reuse)

## Key Commands

### Auto-Detect and Crack
```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### Specify Format
```
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt
john --format=bcrypt --wordlist=rockyou.txt hashes.txt
john --format=NT --wordlist=rockyou.txt hashes.txt
john --format=sha512crypt --wordlist=rockyou.txt hashes.txt
```

### With Rules
```
john --wordlist=rockyou.txt --rules=best64 hashes.txt
john --wordlist=rockyou.txt --rules=jumbo hashes.txt
```

### Show Cracked Passwords
```
john --show hashes.txt
john --show --format=raw-md5 hashes.txt
```

### Hash Extraction Tools
```
# Linux shadow
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# SSH keys
ssh2john id_rsa > ssh_hash.txt

# ZIP files
zip2john protected.zip > zip_hash.txt

# Office documents
office2john document.docx > office_hash.txt

# KeePass
keepass2john database.kdbx > keepass_hash.txt

# PDF
pdf2john protected.pdf > pdf_hash.txt
```

### Incremental (Brute Force)
```
john --incremental --max-length=8 hashes.txt
```

## Output Analysis

- **Cracked passwords** -- test against all services; note password patterns for custom wordlists
- **Partial cracks** -- weak passwords crack first; remaining may need longer runs or better wordlists
- **Password patterns** -- inform custom rule creation for remaining hashes
- **Hash format** -- confirms the hashing algorithm; assess strength (MD5 weak, bcrypt strong)

## Integration with Strix

- Hashes obtained through Strix exploitation (SQLi, file read) feed directly into John
- Cracked passwords enable authenticated testing across all discovered services
- Password pattern analysis informs brute-force strategy for online attacks (Hydra)
- Hash format analysis contributes to security assessment of password storage practices
