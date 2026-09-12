---
name: auth0
description: Auth0 tenant security testing covering misconfigured rules/actions, scope escalation, MFA bypass, and cross-application token confusion
---

# Auth0

Auth0 misconfigurations enable account takeover, cross-tenant data access, and privilege escalation through Rules/Actions, loose application settings, weak API authorization, and token acceptance bugs in consuming applications. Test both the Auth0 tenant configuration and how downstream APIs validate Auth0-issued tokens.

## Attack Surface

**Auth0 Components**
- Applications: SPA, Regular Web, Native, Machine-to-Machine (M2M)
- APIs (Resource Servers): identifiers, scopes, RBAC, permissions
- Connections: database, social, enterprise (SAML/OIDC)
- Rules (legacy) and Actions (post-login, pre-user-registration, credentials exchange)
- Organizations (multi-tenant B2B), roles, permissions
- Universal Login, custom domains, custom database scripts

**Token Types**
- ID Token (OIDC), Access Token (JWT or opaque), Refresh Token
- Management API tokens, client credentials tokens (M2M)
- PAR, PKCE flows for public clients

**Management**
- Auth0 Management API (`/api/v2/`)
- Tenant settings, attack protection, MFA policies, anomaly detection
- Logs streaming, hooks, custom prompts

## Reconnaissance

**Tenant Discovery**
```
# From app config, JS bundles, mobile apps
domain: tenant.us.auth0.com / tenant.eu.auth0.com / login.customdomain.com
client_id, audience, scope values in authorize URLs
```

**OIDC Discovery**
```
GET https://TENANT.auth0.com/.well-known/openid-configuration
GET https://TENANT.auth0.com/.well-known/jwks.json
```

**Authenticated Userinfo** (requires bearer access token — unauthenticated requests return 401)
```
GET https://TENANT.auth0.com/userinfo
Authorization: Bearer <access_token>
```

**Application Fingerprint**
- Login redirect to `https://TENANT.auth0.com/authorize?client_id=...`
- `auth0-js`, `@auth0/auth0-spa-js`, `auth0-react` in frontend bundles
- API `audience` parameter in token requests

**Management API Exposure**
- Leaked M2M credentials with `read:users`, `update:users`, `create:users` scopes
- Management API called from browser (CORS misconfiguration)

## Key Vulnerabilities

### Application Configuration

**Callback URL / Origin Misconfigurations**
- Wildcard or overly broad Allowed Callback URLs: `https://app.com/*`, `http://localhost:*`
- Allowed Logout URLs, Web Origins, CORS origins too permissive
- Native app custom scheme hijacking (`com.app://callback`)

**Token Settings**
- ID Token used as API access token (audience/scope confusion)
- Refresh token rotation disabled; overly long TTL
- Signing algorithm downgrade if RS256 not enforced downstream

### API Authorization (Resource Server)

**Missing Scope/RBAC Enforcement**
- API accepts any valid access token without required `scope` or `permissions` claim
- RBAC enabled in Auth0 but API doesn't call `/userinfo` or validate `permissions` array
- Wrong `audience` accepted — token for App A works on App B's API

**Test:**
```
# Token for audience A used against API B
Authorization: Bearer <token_with_audience_A>
```

### Rules and Actions Abuse

**Post-Login Rule/Action Injection**
- Rules that add claims based on unvalidated user metadata:
  ```javascript
  user.app_metadata.role = 'admin'  // if user can set app_metadata via signup/API
  ```
- `context.authorization` manipulation in Actions
- Secrets in Rule code exposed to tenant admins or via Management API leak

**Signup / Registration Actions**
- `pre-user-registration` not blocking disposable emails or role self-assignment
- Social connection account linking without verified email → account takeover

### Organizations (B2B Multi-Tenancy)

- Missing `org_id` validation in API — user from Org A accesses Org B data
- Invitation flows accepting attacker email domains
- Organization membership not re-checked after role change

### MFA Bypass

- MFA not enforced on Management API or high-risk applications
- Remember-browser cookie bypasses step-up for sensitive actions
- MFA challenge only on Universal Login but API accepts password-grant tokens without MFA
- Recovery codes/brute-force on enrollment endpoints

### Account Takeover Vectors

- Password reset link not invalidated after use; predictable reset tokens
- Email verification not required before sensitive actions
- Change password without re-auth or MFA
- Linking attacker's social IdP to victim account (same email, unverified)

### Management API

- M2M app with excessive scopes: `delete:users`, `update:users_app_metadata`
- Management API token in frontend JavaScript or mobile app
- Rate limiting absent on `/api/v2/users` enumeration

### Custom Database Scripts

- Custom login script with SQL injection in username lookup
- `get_user` script returning excessive profile fields
- Scripts with hardcoded credentials or weak hashing

## Advanced Techniques

**Cross-Application Token Confusion**
- Same `client_secret` reused across environments (dev/prod)
- Multiple APIs sharing signing keys without `aud` validation

**Resource Owner Password Grant (if enabled)**
- Legacy grant enabled — direct username/password to token endpoint, bypassing Universal Login MFA

**Impersonation / Delegation**
- `act_as` or delegation features misconfigured (legacy features in older tenants)

## Testing Methodology

1. **Extract tenant config** — Domain, client_id, audience, scopes from app
2. **Callback/origin matrix** — Fuzz Allowed Callback URLs and Web Origins
3. **Token validation** — Swap audiences, strip scopes, expired tokens, wrong signing keys
4. **Org boundary** — Two org users accessing each other's org-scoped resources
5. **MFA policy** — Sensitive actions without step-up; API paths bypassing MFA
6. **Management API** — Hunt for leaked M2M creds; test scope boundaries
7. **Rules/Actions** — Trace claim injection from `user_metadata` / `app_metadata`

## Validation

1. Demonstrate account takeover or cross-org access with token/callback/metadata abuse
2. Show API accepting token without required scope/permission/audience
3. MFA bypass PoC on protected application flow
4. Document Auth0 setting (Rule, Application config, API RBAC) root cause
5. Provide authorize → callback → API request chain with evidence

## False Positives

- Callback URL validation rejects all fuzz attempts consistently
- API validates `aud`, `iss`, `scope`/`permissions` on every request
- MFA enforced via Auth0 Action on every login for sensitive apps
- `app_metadata` writable only by admin via Management API, not user signup
- Organizations feature correctly binds `org_id` in token and API enforces it

## Impact

- Full account takeover across Auth0-connected applications
- Cross-tenant data breach in B2B org deployments
- Privilege escalation via metadata/claim injection in Rules
- Mass user enumeration/modification via Management API abuse

## Pro Tips

1. Always capture full authorize URL — `audience` and `scope` reveal API targets
2. Decode access token JWT — check `permissions`, `scope`, `org_id`, `https://.../roles` claims
3. Test dev/stage tenants separately — often weaker callback rules
4. Pair with `oauth` and `authentication_jwt` skills for flow/token layer testing
5. Management API M2M creds in CI logs are high-value — search GitHub, buckets, artifacts

## Summary

Auth0 security spans tenant configuration (callbacks, MFA, Rules) and downstream API token validation (`aud`, `scope`, `permissions`, `org_id`). A perfectly configured Universal Login fails if the API accepts tokens without enforcing Auth0's authorization model.
