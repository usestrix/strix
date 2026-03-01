---
name: maltego
description: Operator-assisted Maltego workflows for OSINT visualization, relationship mapping, and attack surface discovery
category: tools
tags: [osint, recon, visualization, operator-assisted]
---

# Maltego

OSINT and graphical link analysis tool for mapping relationships between people, organizations, domains, IPs, infrastructure, and social media. Visualizes attack surface and connections.

## When to Request

- During early reconnaissance for comprehensive target mapping
- When relationships between entities need visualization (people, domains, IPs, orgs)
- For infrastructure mapping and identifying shared hosting or CDN relationships
- To discover shadow IT, acquisitions, and related domains

## Operator-Assisted Workflow

1. Agent identifies seed entities (domain, company name, email, IP range)
2. Agent specifies which transforms to run and what intelligence to gather
3. Operator runs Maltego transforms and exports the resulting graph
4. Agent analyzes relationships: shared infrastructure, employee networks, subsidiary domains
5. Agent uses discovered assets to expand testing scope

## Key Transforms

### Domain Intelligence
```
- DNS to IP: resolve all associated IPs
- Domain to MX: identify mail servers
- Domain to NS: identify nameservers
- Domain to Subdomains: enumerate subdomains
- Domain to Website: identify web technologies
- Domain to WHOIS: registration details and contacts
```

### Person/Email Intelligence
```
- Email to Person: identify account owner
- Person to Email: find associated email addresses
- Email to Domain: map organizational relationships
- Person to Social Media: find profiles across platforms
```

### Infrastructure Mapping
```
- IP to Netblock: identify hosting ranges
- IP to ASN: determine network ownership
- IP to Geolocation: physical location mapping
- Netblock to Organization: identify who owns the infrastructure
```

### Company Intelligence
```
- Company to Domain: find all associated domains
- Company to Email Pattern: discover naming conventions
- Company to People: identify employees and roles
- Company to Technologies: technology stack identification
```

## Output Analysis

- **Shared infrastructure** -- multiple targets on same IP/hosting; compromise one to access others
- **Shadow IT domains** -- unmonitored assets with potentially weaker security
- **Employee relationships** -- org chart mapping for social engineering targeting
- **Technology overlap** -- shared tech stacks across subsidiaries suggest shared vulnerabilities
- **Mail infrastructure** -- MX records reveal email security (SPF, DKIM, DMARC) and potential relay abuse
- **Subsidiary domains** -- often have weaker security than parent; may share authentication

## Integration with Strix

- Discovered domains and subdomains feed into Strix's web application scanning scope
- Infrastructure relationships inform attack surface prioritization
- Employee intelligence supports social engineering assessment with SET
- Technology identification guides skill selection for targeted Strix agents

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
maltego [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
