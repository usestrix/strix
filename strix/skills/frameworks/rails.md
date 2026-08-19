---
name: rails
description: Security testing playbook for Ruby on Rails applications covering mass assignment, params parsing, signed-cookie forgery, host header abuse, and known CVEs
---

# Ruby on Rails

Rails is a batteries-included MVC framework whose conventions protect developers - until a convention is bypassed. Classic Rails bugs come from strong-parameters gaps (mass assignment), permissive params parsers (YAML/XML deserialization), `secret_key_base` leaks (cookie forgery), and host-header handling (password-reset poisoning). Rails has also shipped a string of famous path traversal/file-read CVEs that are worth checking by version.

## Attack Surface

- Params parsing: JSON/XML content types that hit `ActionDispatch::ParamsParser` (YAML deserialization in old versions), nested/array params
- Mass assignment: missing `strong_parameters` (`permit` gaps, `params.require(:user).permit!`), `attributes=`/`update_attributes` with unfiltered hashes
- Sessions: signed cookies (Marshal in old versions, JSON in new), `secret_key_base`, cookie flags
- Host header: `request.host`/`url_for`/`default_url_options` in mailers and redirects
- Asset pipeline: Sprockets file disclosure (CVE-2018-3760), Action View file reads (CVE-2019-5418)
- Template rendering: `render inline:`, ERB in mailers/templates, unsafe `render file:`
- Query interfaces: string-built `where`, `order`, `pluck` with user input
- File handling: `send_file`/`send_data` with user paths, uploads (CarrierWave/ActiveStorage) filename handling
- Known CVEs by version: CVE-2013-0156 (params YAML deserialization), CVE-2018-3760 (Sprockets), CVE-2019-5418 (Action View accept header), CVE-2020-8163 (mailer command injection), CVE-2022-32209 (Rack multipart parsing DoS)

## Reconnaissance

1. **Fingerprint Rails**: `X-Runtime`, `ETag`/`Cache-Control` patterns, `_rails`/`_session` cookie names, Rails 404/500 pages, `rails` version via error pages/`public/assets` digests
2. **Probe params parsers**: send `Content-Type: application/xml` and `application/yaml` with nested payloads; observe 400/parse errors and whether hash keys become model attributes
3. **Source-aware**: grep `permit!`, `params[:x]` direct into `create/update`, `render inline`, `render file`, `where("...")`, `send_file`, `secret_key_base`, `config.force_ssl`
4. **Inspect cookies**: decode the Rails session cookie; on old versions it is Marshal (can be signed/encrypted), on new versions JSON - look for forgeable user/role claims
5. **Map routes**: `bin/rails routes` (whitebox), or crawl + `routes`-derived endpoints blackbox

## Key Vulnerabilities

### Mass Assignment

Rails 3-era `attr_accessible` gaps and modern `strong_parameters` mistakes:

```
POST /users {"user": {"name": "x", "admin": true}}
```

Check every write endpoint for undeclared attributes (`role`, `admin`, `balance`, `account_id`). `permit!` or `params.require(:user).permit(...).except(:id)` are common root causes. See `mass_assignment`.

### Params Parser Deserialization (CVE-2013-0156)

Old Rails (< 4.0) parsed `application/xml` with `ActiveSupport::XMLConverter` and `application/yaml` params, leading to `YAML.load` deserialization RCE:

```
POST /users/sign_in HTTP/1.1
Content-Type: application/xml

<hash><yaml><![CDATA[--- !ruby/object:Gem::Installer ... ]]></yaml></hash>
```

Check the Rails version before exploiting; this is a historical CVE but still worth knowing for legacy codebases.

### Signed Cookie / Session Forgery

With `secret_key_base` (leaked via env, source, or backups), forge the Rails session cookie:

```
# v4+: signed JSON cookie, base64 + "--" + HMAC-SHA256 digest
```

Even without the key, decode cookies to find client-trusted identity fields. Test whether the app validates the session against server state.

### Host Header Poisoning

Password-reset and confirmation mailers built from `request.host`/`url_for` trust the `Host` header:

```
GET /password/new HTTP/1.1
Host: attacker.example
```

If the reset link uses the poisoned host, the victim's reset token is sent to the attacker's URL (see `header_injection` for payloads and validation).

### File Disclosure CVEs

- **CVE-2019-5418** (Action View < 5.2.2.1): path traversal via `Accept` header when a template renders with `render file:`:
  ```
  GET /some_path HTTP/1.1
  Accept: ../../../../../../etc/passwd{{
  ```
- **CVE-2018-3760** (Sprockets < 3.7.2): `%2e%2e%2f` traversal in the asset pipeline to read files:
  ```
  GET /assets/file:%2e%2e%2f%2e%2e%2fetc/passwd
  ```

Version-check before testing; patched apps reject these.

### Template / Mailer Injection

- `render inline: user_input` -> ERB injection (see `ssti`)
- `render file: user_input` -> arbitrary file render (CVE-2019-5418 class)
- `render html:`/`render json:` with unescaped user data -> XSS/JSONP
- Mailer command injection (CVE-2020-8163) in `deliver_later` with user-controlled email addresses on affected versions

### SQL Injection

- `Model.where("name = '#{params[:name]}'")`, `order(params[:sort])`, `group`/`pluck` with string input
- `find_by_sql`/`sanitize_sql` misuse
- PostgreSQL-specific `||`/`json` functions in string-built queries

### Unsafe Query / Reflection

- `send(params[:method])` in controllers -> arbitrary method invocation
- `constantize`/`classify` on user input -> class/object instantiation
- `find(params[:id])` gaps: `find_by` vs `find` behaviors, negative/array IDs

## Advanced Techniques

- **Session cookie without secret**: try default/empty `secret_key_base` (legacy), leaked keys from env dumps, and wordlist brute force for short keys
- **Strong params bypass**: array/nested params (`user[admin]=1`), JSON body with string keys, duplicate keys (`user[role]=user&user[role]=admin` - last wins), `_method` override
- **CSRF via `_method`**: hidden `_method=PATCH`/`DELETE` on simple content types (see `csrf`)
- **Cache + host header**: poison cached password-reset pages (see `web_cache_poisoning`)
- **YAML/ERB in mailers**: mailer templates are ERB - user-controlled values reaching `render`/layout names can inject

## Testing Methodology

1. Fingerprint Rails version from headers/errors/assets
2. Decode session cookies; check for client-trusted claims and secret usage
3. Test params parsers (JSON/XML/YAML content types) on every write endpoint
4. Audit strong parameters in source, or blackbox-test undeclared fields per endpoint
5. Probe host-header sinks (password reset, redirects, mailers)
6. Version-check and test the known file-disclosure CVEs
7. Fuzz `render`/`send_file`/`where`/`order` sinks
8. Validate every finding with exact request/response pairs

## Validation

1. Mass assignment: two-account or baseline-diff proof that an undeclared attribute persisted
2. Host header: show a reset/redirect URL generated with the attacker host
3. File read: read a real sensitive file (`/etc/passwd`, `config/database.yml`, `secret_key_base` sources)
4. Session forgery: authenticate as another user with a forged cookie (minimal, non-destructive)
5. SQLi: standard evidence per `sql_injection`

## False Positives

- Mass-assigned field silently dropped by `permit`/`strong_parameters` (no DB change)
- Rails session cookie contains claims the app does not trust server-side
- `Accept` header traversal rejected on patched Action View
- Host header accepted by app but reset links/redirects use `default_url_options` or a fixed host
- `render inline:` present but with no user-controlled input

## Impact

- RCE via params deserialization on legacy versions or template injection
- Account takeover via forged sessions or host-header reset poisoning
- Data disclosure via the file-read CVEs and traversal
- Privilege escalation via mass assignment

## Pro Tips

1. Version-check before CVE testing - Rails patches fast, and unpatched targets are increasingly rare
2. Decode every Rails session cookie; client-trusted claims are a fast account-takeover path
3. Test host-header poisoning against every mailer-driven flow (reset, confirm, invite)
4. Strong-params gaps are the most common *current* Rails bug - test every write endpoint
5. Pair with `mass_assignment`, `ssti`, `insecure_deserialization`, `header_injection`, and `sql_injection` skills

## Summary

Rails security follows conventions: where strong parameters are bypassed, where params parsers deserialize, where the host header reaches mailers, and where `secret_key_base` leaks. Version-check known CVEs, decode cookies, test every write endpoint for mass assignment, and validate with exact proofs.
