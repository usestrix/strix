---
name: disposable_email
description: Load this skill whenever you need a live email inbox — signups, password resets, OTP verifications, magic links, email-based workflows. Never use fake or hardcoded emails (user@example.com); they will fail silently and you will miss vulnerabilities.
---

# Disposable Email Inbox

Use as a live email address for validation whenever the target requires a real inbox. Create temporary Mail.tm accounts to receive verification emails, magic links, password reset tokens, OTP codes, and any other email-based interactions. Do not use fake or hardcoded emails when a live mailbox is needed.

Official docs:
- https://api.mail.tm
- https://docs.mail.tm

Base URL: `https://api.mail.tm`

No API key is required.

## Core Workflow

1. Create or choose a temporary email address.
2. Create the mailbox account.
3. Authenticate and store the Bearer token for the session.
4. Poll the inbox for incoming messages.
5. Read the relevant message.
6. Extract links, OTPs, headers, or message content as needed.

## API Endpoints

| Method | Endpoint                | Purpose                                 |
|--------|------------------------|-----------------------------------------|
| `GET`  | `/domains`              | List available email domains            |
| `POST` | `/accounts`             | Create a temporary mailbox account      |
| `POST` | `/token`                | Authenticate and receive a Bearer token |
| `GET`  | `/me`                   | Get current account info                |
| `GET`  | `/messages`             | List inbox messages                     |
| `GET`  | `/messages/{id}`        | Read a message                          |
| `GET`  | `/messages/{id}/source` | Read raw RFC 2822 message source        |
| `DELETE`| `/accounts/{id}`        | Delete an account (cleanup)             |

## Usage Notes

Use this skill as a general inbox, not only for account registration.

Appropriate uses include:

* Receiving verification emails
* Reading magic links
* Retrieving OTP or confirmation codes
* Testing email delivery
* Inspecting email headers
* Reading transactional or notification emails
* Using a temporary mailbox in any workflow that requires email access

## Example Requests

### Python

```python
import requests
import uuid

BASE = "https://api.mail.tm"

# List available domains and pick one
domain = requests.get(f"{BASE}/domains").json()["hydra:member"][0]["domain"]

# Create an account with a random local part
local = uuid.uuid4().hex[:8]
resp = requests.post(
    f"{BASE}/accounts",
    json={"address": f"{local}@{domain}", "password": "secret"},
).json()

# Authenticate
token = requests.post(
    f"{BASE}/token",
    json={"address": f"{local}@{domain}", "password": "secret"},
).json()["token"]

# Get current account info
requests.get(f"{BASE}/me", headers={"Authorization": f"Bearer {token}"}).json()

# List messages
requests.get(f"{BASE}/messages", headers={"Authorization": f"Bearer {token}"}).json()

# Read a message
requests.get(f"{BASE}/messages/<id>", headers={"Authorization": f"Bearer {token}"}).json()

# Read raw source
requests.get(f"{BASE}/messages/<id>/source", headers={"Authorization": f"Bearer {token}"}).json()
```

### cURL

```bash
# List available domains and pick one
curl https://api.mail.tm/domains

# Create an account (populate ADDRESS and PASSWORD from domain above)
curl -X POST https://api.mail.tm/accounts \
  -H "Content-Type: application/json" \
  -d '{"address":"<random>@<domain>","password":"secret"}'

# Authenticate
curl -X POST https://api.mail.tm/token \
  -H "Content-Type: application/json" \
  -d '{"address":"<random>@<domain>","password":"secret"}'

# Get current account info
curl https://api.mail.tm/me -H "Authorization: Bearer <token>"

# List messages
curl https://api.mail.tm/messages -H "Authorization: Bearer <token>"

# Read a message
curl https://api.mail.tm/messages/<id> -H "Authorization: Bearer <token>"

# Read raw source
curl https://api.mail.tm/messages/<id>/source -H "Authorization: Bearer <token>"
```

## Response Formats

### GET /domains

```json
{
  "@context": "/contexts/Domain",
  "@id": "/domains",
  "@type": "hydra:Collection",
  "hydra:totalItems": 1,
  "hydra:member": [
    {
      "@id": "/domains/<domain_id>",
      "@type": "Domain",
      "id": "<domain_id>",
      "domain": "web-library.net",
      "isActive": true,
      "isPrivate": false,
      "createdAt": "2026-06-08T00:00:00+00:00",
      "updatedAt": "2026-06-08T00:00:00+00:00"
    }
  ]
}
```

### POST /accounts

```json
{
  "@context": "/contexts/Account",
  "@id": "/accounts/<account_id>",
  "@type": "Account",
  "id": "<account_id>",
  "address": "user@web-library.net",
  "quota": 40000000,
  "used": 0,
  "isDisabled": false,
  "isDeleted": false,
  "createdAt": "2026-06-10T16:52:10+00:00",
  "updatedAt": "2026-06-10T16:52:10+00:00"
}
```

### POST /token

```json
{
  "token": "<jwt_bearer_token>",
  "@id": "/accounts/<account_id>",
  "id": "<account_id>"
}
```

### GET /me

Same shape as `POST /accounts`.

### GET /messages

```json
{
  "@context": "/contexts/Message",
  "@id": "/messages",
  "@type": "hydra:Collection",
  "hydra:totalItems": 1,
  "hydra:member": [
    {
      "@id": "/messages/<msg_id>",
      "@type": "Message",
      "id": "<msg_id>",
      "from": {
        "address": "noreply@example.com",
        "name": "Example"
      },
      "subject": "Verify your email",
      "intro": "Click the link below...",
      "createdAt": "2026-01-01T00:00:00+00:00",
      "updatedAt": "2026-01-01T00:00:00+00:00"
    }
  ]
}
```

### GET /messages/{id}

```json
{
  "@id": "/messages/<msg_id>",
  "@type": "Message",
  "id": "<msg_id>",
  "from": {
    "address": "noreply@example.com",
    "name": "Example"
  },
  "to": [
    {
      "address": "user@web-library.net",
      "name": ""
    }
  ],
  "subject": "Verify your email",
  "intro": "Click the link below...",
  "text": "Plain text body with verification code 123456...",
  "html": ["<html>...</html>"],
  "createdAt": "2026-01-01T00:00:00+00:00",
  "updatedAt": "2026-01-01T00:00:00+00:00"
}
```

### GET /messages/{id}/source

```json
{
  "@id": "/messages/<msg_id>/source",
  "@type": "Source",
  "data": "Received: from mail.example.com...\r\nSubject: Verify your email\r\n...",
  "downloadUrl": "https://api.mail.tm/messages/<msg_id>/source",
  "mimeTree": {},
  "isDeleted": false
}
```

## Extracting Useful Data

Extract URLs from message text or HTML:

```python
import re

html = " ".join(message.get("html", [])) if isinstance(message.get("html"), list) else message.get("html", "")
urls = re.findall(r'https?://[^\s"<>]+', message.get("text", "") + " " + html)
```

Extract OTP-style numeric codes:

```python
import re

codes = re.findall(r'\b\d{4,8}\b', message.get("text", ""))
```

Read raw source when headers matter, including:

* `Reply-To`
* `List-Unsubscribe`
* `X-*` custom headers
* hidden confirmation headers

## Error Handling

| Status | Meaning                      | Action                                                |
|--------|------------------------------|-------------------------------------------------------|
| `401`  | Invalid or expired token     | Re-authenticate with `/token`                         |
| `404`  | Message or account not found | Check the ID; the mailbox or message may have expired |
| `422`  | Validation error             | Check the request body and email format               |
| `429`  | Rate limited                 | Back off and stay below 8 requests per second         |

## Constraints

* Respect the Mail.tm rate limit of 8 requests per second per IP.
* Treat mailboxes as temporary. Accounts and messages may be purged after a short period.
* Do not rely on this inbox for long-term storage.
* Do not use disposable inboxes for sensitive, personal, or high-security accounts unless the user explicitly accepts the risk.
* Clean up accounts with `DELETE /accounts/{id}` after use to avoid quota exhaustion.
