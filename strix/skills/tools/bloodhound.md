---
name: bloodhound
description: Operator-assisted BloodHound workflows for Active Directory attack path analysis and privilege escalation mapping
category: tools
tags: [active-directory, enumeration, privilege-escalation, operator-assisted]
---

# BloodHound

Active Directory attack path visualization and analysis tool. Maps relationships between AD objects to identify privilege escalation paths, Kerberos delegation abuse, and shortest paths to domain admin.

## When to Request

- When assessing Active Directory environments for privilege escalation
- After obtaining any level of AD credentials (even low-privilege)
- To map attack paths from compromised accounts to high-value targets
- For identifying Kerberos delegation, ACL abuse, and group membership chains

## Operator-Assisted Workflow

1. Agent identifies AD environment and available credentials
2. Agent provides SharpHound/BloodHound.py collection commands
3. Operator runs collector and imports data into BloodHound
4. Operator queries for specific attack paths and shares results
5. Agent directs exploitation of identified attack paths

## Key Commands

### Data Collection (SharpHound)
```
# From Windows
SharpHound.exe -c All -d DOMAIN --zipfilename bloodhound.zip

# Specific collection methods
SharpHound.exe -c DCOnly,ACL,Group,Session,LoggedOn,Trusts
```

### Data Collection (BloodHound.py)
```
# From Linux
bloodhound-python -d DOMAIN -u USER -p PASSWORD -c All -ns DC_IP --zip

# Specific collection
bloodhound-python -d DOMAIN -u USER -p PASSWORD -c Group,ACL,Session -ns DC_IP
```

### Key Cypher Queries
```
# Shortest path to Domain Admin
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

# Kerberoastable users with admin paths
MATCH (u:User {hasspn:true})-[*1..5]->(g:Group {admincount:true}) RETURN u.name

# Users with DCSync rights
MATCH (u)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN u.name

# Unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

### Pre-Built Analysis
```
- Find all Domain Admins
- Find Shortest Paths to Domain Admins
- Find Principals with DCSync Rights
- Find Computers with Unconstrained Delegation
- Find Kerberoastable Users with Most Privileges
- Find ASREPRoastable Users
- Find Shortest Paths to High Value Targets
```

## Output Analysis

- **Attack paths** -- step-by-step privilege escalation chains from current access to Domain Admin
- **Kerberoastable accounts** -- extract and crack service ticket hashes
- **ACL abuse** -- GenericAll, GenericWrite, WriteDACL, ForceChangePassword on high-value targets
- **Delegation abuse** -- unconstrained, constrained, resource-based constrained delegation
- **Group membership chains** -- nested group memberships providing unintended access
- **Session data** -- where admins are logged in; target for credential theft

## Integration with Strix

- Attack paths guide Strix's operator-assisted exploitation order
- Kerberoastable accounts feed hashes to Hashcat for cracking
- Discovered web applications on AD-joined servers expand Strix's web testing scope
- Credential chains from AD inform authentication testing across all services
