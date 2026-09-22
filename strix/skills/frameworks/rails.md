---
name: rails
description: Ruby on Rails security testing covering mass assignment, YAML/Marshal deserialization RCE, secret_key_base compromise, and SQL/path injection
---

# Ruby on Rails

Rails' "convention over configuration" cuts both ways for security testing: strong parameters and parameterized ActiveRecord queries are safe by default, but the framework has a long, well-documented history of deserialization RCE (`YAML.load`, `Marshal.load` on cookie-store session data) tied directly to a single secret — `secret_key_base`. Recover that secret and, depending on version/config, you may go straight to RCE via a forged session cookie.

## Attack Surface

**Core components**
- ActionController (strong parameters, filters), ActiveRecord (query interface, raw SQL escape hatches)
- ActionView/ERB templates, asset pipeline (Sprockets/Propshaft)
- Session store — `CookieStore` (default: client-side, signed+encrypted with `secret_key_base`) vs server-side (Redis/DB)
- ActiveJob (background jobs, often Sidekiq/Redis-backed), ActionCable (WebSockets)

**Config surface**
- `config/master.key` / `config/credentials.yml.enc` (Rails 5.2+ encrypted credentials) or `config/secrets.yml` (older)
- `SECRET_KEY_BASE` env var, `config.action_controller.permit_all_parameters` (dangerous if ever true)

## Reconnaissance

**Version/environment fingerprint**
```
GET /nonexistent   # dev-mode error page leaks Rails version, gem list, full stack trace, and can include config values in local variables dump
curl -I https://target/   # X-Runtime, Set-Cookie name (_appname_session) often reveal app name
```

**Secret exposure**
```
GET /config/master.key
GET /config/secrets.yml
GET /.git/config, /.git/HEAD   # if git artifacts weren't excluded from deployment
```
`config/master.key` decrypts `credentials.yml.enc`, which frequently contains `secret_key_base` directly alongside other app secrets.

**Session cookie inspection**
Decode the `_appname_session` cookie (Base64, `--` separated segments for `CookieStore`) to see if the payload format is JSON (modern default, safer) or Marshal (legacy, deserialization-RCE-capable) — this single detail determines whether a `secret_key_base` leak is "just" session forgery or full RCE.

## Key Vulnerabilities

### secret_key_base compromise

Once recovered (via `master.key`/`credentials.yml.enc`, leaked `.env`, exposed `config/secrets.yml`, or a Rails-specific CVE in the key derivation), everything protected by it is forgeable:
- **Session forgery** — forge `_appname_session` cookies with arbitrary user IDs/roles if the app trusts session data for authorization decisions.
- **Marshal-based RCE** (Rails ≤4 defaults, or any app explicitly configured with `Marshal`-serialized cookie sessions) — craft a Marshal-serialized Ruby gadget chain (`universal-rce`/`RailsBuiltinDeserializationGadgetChain` per `ruby-marshal-exploitation` toolkits), sign it correctly with the recovered `secret_key_base`, and submit as the session cookie for on-postback RCE.
- **Known Rails secret-derivation CVEs** — CVE-2019-5420 (development-mode `secret_token`/`secret_key_base` predictable derivation from a known `config/secrets.yml` template when `Rails.application.config.secret_key_base` falls back to a derived default) chained with `ActiveSupport::MessageVerifier`/`MessageEncryptor` gadget deserialization is a historical unauthenticated RCE for apps that never explicitly set the secret.

### Mass assignment / strong parameters bypass

```ruby
# Vulnerable: permits too broadly or skips strong params entirely
User.create(params[:user])                        # Rails <4 default, or explicit params.permit! misuse
params.require(:user).permit(:name, :email, :role) # 'role' shouldn't be user-settable
```
Fuzz every create/update action with fields not present in the legitimate form (`admin=true`, `role=admin`, `verified=true`, `account_balance=...`) — same class of bug as Laravel's Eloquent guard gaps, just Rails' strong-parameters equivalent.

### YAML deserialization

`YAML.load` (not `YAML.safe_load`) on attacker-influenced input — config import features, "restore from backup" functionality, certain gem defaults pre-Psych-4 — deserializes arbitrary Ruby objects. Known universal RCE gadget chains exist for common gemsets (`ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy`, `Gem::Requirement`); Rails moved to `YAML.safe_load`/Psych 4 defaults in later versions specifically to close this, so confirm the actual Ruby/Rails/Psych version before assuming it's exploitable.
```
GET /admin/import  →  crafted YAML payload uploaded/posted, triggers Marshal-equivalent gadget on Object#init
```

### Raw SQL / dynamic finder injection

ActiveRecord's query interface is safe when using placeholders; injection reappears in these escape hatches:
```ruby
User.where("email = '#{params[:email]}'")          # string interpolation — classic SQLi
User.order(params[:sort])                            # unvalidated column name in ORDER BY
User.find_by_sql("SELECT * FROM users WHERE #{cond}")
```
Test every `order`/`group`/`having`/`where` call that takes a raw string built from request params, and every `find_by_sql`/`.where("...")` with string interpolation.

### File handling / asset pipeline

- `send_file`/`send_data` with a user-controlled path argument → path traversal to arbitrary file read.
- Sprockets (pre-4.0) asset-pipeline path traversal (CVE-2018-3760-class) via crafted asset URLs reaching files outside the public asset root.
- File upload validated only by extension/content-type header (not actual content) → same upload-bypass techniques as any other stack; check `insecure_file_uploads` skill.

### ActionCable / WebSocket auth parity

ActionCable channels often authenticate at connection time but not per-subscription — verify each channel's `subscribed` method independently re-checks authorization rather than trusting the connection-level identity for every channel a user can subscribe to.

## Testing Methodology

1. **Secret exposure sweep** — `master.key`, `credentials.yml.enc`, `secrets.yml`, git artifacts, `.env`.
2. **Session format check** — decode the session cookie to determine JSON vs Marshal serialization; this gates whether secret compromise means "just" forgery or full RCE.
3. **If secret recovered** — attempt session forgery first (lowest effort, immediate value), then Marshal gadget-chain RCE if the format supports it.
4. **Mass-assignment matrix** — every create/update controller action, fuzz for unpermitted privileged fields.
5. **Raw SQL/dynamic finder audit (white-box)** — grep for string interpolation into `where`/`order`/`find_by_sql`.
6. **YAML sink check** — any import/restore/config-upload feature; confirm `YAML.load` vs `YAML.safe_load` in source if available.

## Validation

1. Secret compromise: show the forged session cookie accepted by the live app (e.g., accessing an admin-only page as a forged privileged user).
2. Marshal RCE: command output returned or received out-of-band, with the exact gadget chain and signed cookie value used.
3. Mass assignment: side-by-side request diff showing the injected field's effect on the created/updated record.
4. SQLi: deterministic oracle (error-based, boolean, or time-based) tied to the specific interpolated parameter.

## False Positives

- Session cookie payload is JSON-serialized (modern Rails default) — Marshal gadget-chain RCE does not apply even with a recovered `secret_key_base`; only forgery does.
- `credentials.yml.enc` present but `master.key`/`RAILS_MASTER_KEY` genuinely inaccessible — encrypted blob alone isn't exploitable.
- Strong parameters correctly scoped on every controller action tested — mass-assignment fuzzing consistently rejected.
- `YAML.safe_load` (or Psych 4+ default-safe `YAML.load`) confirmed in use — deserialization payloads correctly rejected with a type error.

## Impact

- Unauthenticated RCE via Marshal-based session deserialization or YAML gadget chains once `secret_key_base` or a YAML sink is reachable.
- Session/account forgery and privilege escalation via signed-cookie forgery.
- Data tampering/privilege escalation via mass assignment on unpermitted fields.
- SQL injection via string-interpolated ActiveRecord query methods.

## Pro Tips

1. Decode the session cookie's format before anything else — it determines whether a `secret_key_base` leak is catastrophic (Marshal) or merely serious (JSON forgery only).
2. `config/master.key` is the single key that unlocks `credentials.yml.enc` — treat any leak of it as a full secrets compromise, not just one value.
3. Rails' own security advisories (`CVE-2019-5420`-class) are worth checking against the fingerprinted version before assuming a deserialization path is closed.
4. Pair with `insecure_deserialization` for the general gadget-chain methodology and `sql_injection` for the raw-SQL escape-hatch patterns.

## Summary

Rails testing centers on `secret_key_base`: recover it and, depending on session-store format, you have either session forgery or full Marshal-deserialization RCE. Independently, mass assignment and string-interpolated ActiveRecord calls remain the everyday bug classes — Rails' safe defaults only hold where they're actually used consistently.
