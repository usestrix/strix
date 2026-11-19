---
name: rails
description: Security testing playbook for Ruby on Rails covering mass assignment, ORM injection, CSRF gaps, and debug/admin surface exposure
---

# Ruby on Rails

Security testing for Ruby on Rails applications (6.1 through 8). Focus on strong-parameter bypasses, interpolated ActiveRecord, `before_action` gaps, cookie/session forgery, and debug/admin mounts that leak into production.

## Attack Surface

**Routing & controllers** — `config/routes.rb` (`resources`, `namespace :admin`, `mount`, `draw`, `match '*path'`); `ApplicationController` `before_action` chains (`authenticate_user!`, authorize) and `skip`/`only`/`except` holes; strong parameters (`permit`, `permit!`, nested hashes); HTML vs JSON vs Turbo vs `ActionController::API` (API-only skips CSRF).

**Data, views, mail, files** — ActiveRecord (`where`/`order`/`pluck`/`find_by_sql`/`calculate`, `Arel.sql`); ERB (`<%= %>` vs `<%== %>`), HAML (`!=`, `raw`, `html_safe`); ActiveStorage direct uploads and blob proxy/redirect; ActionMailer previews (`/rails/mailers`).

**Realtime, jobs, engines, secrets** — ActionCable (`stream_from`/`stream_for`); ActiveJob / Sidekiq / Solid Queue dashboards; engines and admin gems (ActiveAdmin, RailsAdmin, Administrate, Blazer, PgHero); credentials (`config/credentials.yml.enc`, `master.key`, `secret_key_base`, `RAILS_MASTER_KEY`).

**Deployment** — `config.hosts` / HostAuthorization, `consider_all_requests_local`, `force_ssl`; web-console; letter_opener; `/rails/info`.

High-value routes: `POST/PATCH /users` and nested `*_attributes`; sort/filter params; login `?next=` / `redirect_to params[:...]`; `/admin`, `/rails/info/routes`, `/rails/mailers`, `/sidekiq`; `/rails/active_storage/direct_uploads` and `/blobs/{redirect,proxy}/*`; `/cable`; leaked `master.key` / `SECRET_KEY_BASE`.

## Reconnaissance

**Fingerprinting**
```
curl -I https://target/
# Set-Cookie: _<app>_session, X-Runtime, csrf-token meta
GET /rails/info/properties
GET /rails/info/routes
GET /rails/mailers
GET /sidekiq
GET /admin
```
Cookie `_app_session` plus `authenticity_token` is Rails. JSON APIs often still set the session cookie.

**White-box map (source-aware)**
```
rg -n "permit!|accepts_nested_attributes_for|skip_forgery_protection|protect_from_forgery" .
rg -n "where\(\".*#\{|order\(.*params|find_by_sql|Arel\.sql|constantize|public_send" .
rg -n "redirect_to params|render inline:|render file:|mount Sidekiq::Web|LetterOpener|web-console" .
brakeman -q
bundle audit
```

## Key Vulnerabilities

### Mass Assignment

`permit!` and nested attributes are the Rails path to role/tenant escalation.

Black-box — extra fields on register/PATCH (JSON, form, multipart; with and without wrap_parameters root):
```
POST /users  user[email]=a@x&user[admin]=true&user[role]=admin
PATCH /users/1.json  {"user":{"admin":true,"memberships_attributes":[{"role":"admin"}]}}
```
White-box: `rg -n "permit!" app/controllers`; `accepts_nested_attributes_for` that permits `role`/`admin`; legacy `User.new(params[:user])` in engines.

Validate: two accounts; attacker self-PATCHes `admin=true`; privileged route succeeds. Confirm `saved_changes` (or DB) flipped. False positive: column missing, callback resets it, or Pundit/CanCanCan still denies. Impact: vertical privilege escalation.

### SQL Injection (ActiveRecord)

Hash/`?` binds are safe. Interpolated strings and user-controlled column names are not:
```ruby
User.where("name = '#{params[:name]}'")
User.order(Arel.sql("#{params[:sort]} #{params[:dir]}"))
User.pluck(params[:col]); User.calculate(:sum, params[:col])
User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
User.where(Arel.sql("id = #{params[:id]}"))
```
`order("#{params[:sort]}")` without `Arel.sql` raises `ActiveRecord::UnknownAttributeReference` on 6.1+ (a useful black-box 500). The common "fix" is wrapping `Arel.sql`, which is the live 6.1–8 sink. `where("... #{params}")` still executes as SQL on 6.1–8.

Black-box:
```
GET /users?sort=email;select+1--
GET /users?sort=CASE+WHEN+(SELECT+1)=1+THEN+email+ELSE+id+END
GET /users?sort=email+ASC;%20SELECT%20pg_sleep(3)--
```
Oracle: SQL error text, timing, or ORDER BY CASE flipping row order. White-box: the `rg` above plus Brakeman `SQL Injection`.

Validate: deterministic order flip or delay, not a generic 500. False positive: allowlisted `%w[name email]` or Arel column objects. Impact: data dump or auth-query bypass.

### Unsafe Render / SSTI / LFI

```ruby
render inline: params[:template]
render file: params[:path]
render template: params[:view]
```
Black-box: `?template=<%=7*7%>`, `?path=/etc/passwd`, `?view=../../../../etc/passwd`.
White-box: those `render` forms; ERB `<%== params[:x] %>`, HAML `!=`, `.html_safe` on request data.

Validate: `7*7` → `49`, or in-scope file contents. False positive: name constrained to a glob under `app/views`. Impact: ERB RCE or file disclosure.

### Unsafe Reflection

```ruby
params[:type].constantize
obj.send(params[:method]); obj.public_send(params[:action])
```
Black-box: STI `type`, `?handler=`, polymorphic `commentable_type`.
White-box: `constantize`/`safe_constantize`/`send(`/`public_send(` — `safe_constantize` still loads any in-app constant.

Validate: reach a class/method you should not, with a visible side effect. False positive: allowlist before constantize. Impact: RCE or authz bypass.

### Open Redirects

```ruby
redirect_to params[:next]
redirect_to params[:return_to], allow_other_host: true
```
**Versions:** `load_defaults 6.1` (and earlier) allow external hosts (`raise_on_open_redirects` default false). `load_defaults 7.0+` on Rails 7.0–8.0 sets `raise_on_open_redirects` and raises `UnsafeRedirectError` unless `allow_other_host: true`. Rails 8.1+ deprecates that flag for `config.action_controller.action_on_open_redirect` (`:raise` at 7.0+ defaults, `:log` on older defaults; `raise_on_open_redirects = true` still forces `:raise`). `allow_other_host: true` only skips the host check — `redirect_to '/dashboard', allow_other_host: true` is not an open redirect. Upgraded 6.1 apps that never flipped `load_defaults` still redirect off-site.

Black-box: `GET /login?next=https://evil.example/` and `//evil.example/`, `/\evil.example`.
Validate: 302/303 `Location` to an attacker host from attacker-controlled input. False positive: 7.0+ defaults raising, a same-origin allowlist, or `allow_other_host` on a hardcoded URL. Impact: token/session theft via login bounce.

### CSRF Gaps

Default `protect_from_forgery` on `ActionController::Base`. Gaps: `skip_forgery_protection`; `protect_from_forgery with: :null_session` on cookie-session HTML; `config.api_only = true` while the browser still sends the session cookie; GET/HEAD mutators (`get 'follow'`); JSON clients missing `X-CSRF-Token`.

Black-box: cross-origin POST without token; GET that changes state.
White-box: `skip_forgery_protection|null_session|protect_from_forgery` in `app/` and `config/`. Rails 6.1–8 CSRF defaults on `Base` are unchanged.

Validate: state change with the victim cookie. False positive: SameSite=Lax blocking POST (still try top-level GET mutators).

### IDOR

`Model.find(params[:id])` / `find_by!(id:)` without `current_user.records`. Black-box: two users, swap IDs on `/posts/:id`, invoices, nested `/users/:user_id/settings`. White-box: `.find(params[:id])` vs `policy_scope` / `current_user.*.find`. Validate: read/update/delete another user's row. Unguessable UUIDs with no authorization are still failed access control once an ID is obtained.

### Unsafe Deserialization

- `YAML.unsafe_load` / `YAML.load` on request data or YAML columns (`config.active_record.use_yaml_unsafe_load`)
- Cookie serializer `:marshal` or `:hybrid` (Rails 7.1+ also accepts `:json_allow_marshal`; `:hybrid` maps to that Marshal-reading JSON fallback) plus leaked `secret_key_base` → cookie RCE
- **Versions:** YAML safety follows the installed Psych, not the Rails gem. Psych 3 (`YAML.load` aliases `unsafe_load`) deserializes arbitrary objects — common on Rails 6.1/7.0 with Ruby 2.7–3.0. Psych 4+ (`YAML.load` is `safe_load` with `Symbol` permitted) rejects unknown classes; `YAML.unsafe_load` and `config.active_record.use_yaml_unsafe_load` are the RCE footguns. Read `Gemfile.lock` / `bundle show psych` (Ruby 3.1+ bundles Psych 4+). `cookies_serializer` is `:marshal` on pre-7.0 defaults and `:json` on `load_defaults 7.0+` (Rails 8 keeps JSON).

Black-box: YAML/XML uploads. Session cookies are encrypted by default — after decrypting with the app key, Marshal payloads start `\x04\x08`; JSON payloads do not. White-box: `unsafe_load|YAML\.load|cookies_serializer|secret_key_base`. Validate: an in-scope side effect, not merely "Marshal is enabled". Impact: RCE.

### ActiveStorage

Default routes: `POST /rails/active_storage/direct_uploads`; `GET /rails/active_storage/blobs/{redirect,proxy}/:signed_id/*filename`; representations under the same prefix.

Black-box: unauthenticated `direct_uploads`; reuse another user's `signed_id`; upload HTML/SVG and fetch it for stored XSS. White-box: `has_one_attached` without ownership checks; Disk vs S3; `config.active_storage.draw_routes`. Validate: read/replace another tenant's blob, or XSS on a same-origin blob URL. False positive: expired signed IDs or auth wrapping the engine.

### ActionCable

`/cable`. Missing `identified_by :current_user` → anonymous subscribe. `stream_from "chat_#{params[:room]}"` without membership check. Black-box: connect with/without session cookie; subscribe to another user's stream. White-box: `app/channels/**`, `config/cable.yml`. Validate: receive another user's broadcast.

### Debug, Mailers, Jobs, Hosts

```
GET /rails/info/properties
GET /rails/info/routes
GET /rails/mailers
GET /rails/mailers/<preview>
GET /sidekiq
GET /jobs
```
`web-console` evaluates Ruby in-page; letter_opener serves mail in-browser. `Sidekiq::Web` is often mounted with no constraint. `config.hosts` is empty in production (HostAuthorization off except development); `config.hosts.clear` or `/./` enables DNS rebinding. Send `Host: attacker.example` against password-reset and cache keys.

White-box: `production.rb`, route mounts, Gemfile (`web-console`, `letter_opener`). Validate: properties/routes dump, mail preview with query-arg constructors, Sidekiq retry/delete, or Host-poisoned reset links. 404 in production is correct. `consider_all_requests_local = true` in production is a lead: trigger an error and show the debug page (stack/locals) before reporting.

### Source-Aware Dependencies

```
brakeman -A -q
bundle audit
rg -n "secret_key_base|RAILS_MASTER_KEY" . --glob '!vendor/**'
```
Brakeman maps to the sinks above (Mass Assignment, SQL Injection, Redirect, File Access, Dangerous Send, XSS). `bundler-audit` flags known-vuln Rails/Rack versions — confirm the locked version before reporting. Cite the advisory URL the scanner printed; do not invent CVE numbers.

## Bypass Techniques

- JSON vs form vs multipart vs wrap_parameters root-key presence
- POST with `_method=PATCH` in the form body or `X-HTTP-Method-Override: PATCH`; Rack::MethodOverride only honors POST (query-string `?_method=` on GET never reaches PATCH). Rails then checks CSRF using the overridden method. Test GET/HEAD routes that change state separately.
- Engine routes (`/admin`, `/letter_opener`) skipping app `before_action`
- API namespace without Devise/Warden while the cookie still authenticates
- STI `type` and nested `*_attributes` omitted from the parent permit list

## Testing Methodology

1. Fingerprint version (session cookie, `/rails/info`, `X-Runtime`, `Gemfile.lock` including `psych`)
2. Map `routes.rb` and fuzz `/rails/*`, `/admin`, `/sidekiq`
3. Auth matrix: unauth / user / admin × HTML / JSON × each `resources` member
4. Extra boolean/role/nested attributes on every write; inject every `sort`/`order`/`q`
5. Redirect params on login/logout/OAuth; CSRF (cookie POST without token, GET mutators)
6. Swap IDs across two users; Cable subscribe; ActiveStorage signed IDs
7. Brakeman + `bundle audit` + credential files

## Validation

1. Privilege bit or nested role persisted and usable
2. SQLi oracle that is not a generic 500
3. 302/303 `Location` to an attacker host from attacker-controlled input (`allow_other_host: true` on a fixed path is not enough)
4. CSRF state change, or GET mutator
5. Cross-user record/blob/cable proof
6. Debug/mailer/job UI reachable without the expected auth

## False Positives

- `permit` allowlist drops the extra key (`user.saved_changes` empty)
- `order(params[:sort])` behind a column allowlist or Arel attributes
- Open redirect blocked by `raise_on_open_redirects` / `action_on_open_redirect = :raise` and no attacker-controlled URL reaching `allow_other_host: true`
- `/rails/info` 404 in production
- Marshal cookies without a leaked `secret_key_base` (theoretical only)
- Brakeman warning on a path behind a proven allowlist

## Impact

- Admin takeover via mass assignment or CSRF on account endpoints
- Full DB read/write via interpolated ActiveRecord
- RCE via ERB `render inline`, Marshal cookies, or `constantize`/`send`
- Session theft via open redirect plus leaked `secret_key_base`
- Cross-tenant file and cable leaks via ActiveStorage and ActionCable

## Pro Tips

1. `permit!` in one inherited controller poisons every child — grep engines, not only `app/controllers`
2. Devise/Warden authenticates; Pundit/CanCanCan/action_policy authorize — missing one is the usual IDOR
3. Read `config.load_defaults` in `application.rb`: a 6.1 default set on a 7.2 gem is the open-redirect / Marshal-cookie story
4. Sidekiq::Web and ActiveAdmin often have HTTP basic in source that is commented out in production
5. Mailer previews take constructor args from the query string — unauthenticated RPC if mounted

## Tooling

White-box (sandbox has `ripgrep`; install Ruby tools when source is present):

- **brakeman** — Rails SAST for the sinks above: `brakeman -A -q -f json`
- **bundler-audit** — `Gemfile.lock` advisories: `bundle audit check --update`
- **ripgrep** — `permit!`, interpolated `where`/`order`, `constantize`, `redirect_to params`
- Session forgery with a leaked `secret_key_base` uses `ActiveSupport::MessageVerifier` / `MessageEncryptor`. Read the target's cookie salts, cipher, and key-derivation settings (`signed cookie`, `authenticated encrypted cookie`, `encrypted cookie`, `signed encrypted cookie`, `use_authenticated_cookie_encryption`, `key_generator_hash_digest_class`); `_session` is a cookie-name suffix (`key: "_app_session"`), not a salt. CookieStore uses the encrypted jar by default. JSON sessions forge data, not RCE; Marshal sessions can.

## Summary

Rails defaults (CSRF, strong parameters, HostAuthorization in development, JSON cookies since `load_defaults 7.0`) fail open as soon as a controller `permit!`s, interpolates SQL, skips forgery protection, or mounts a gem UI. Test writes for extra attributes, reads for interpolated query params, and production for `/rails/*` plus job/admin mounts. Always read `config.load_defaults` and the locked Psych version before claiming a 7.x/8 default protects an upgraded 6.1 app.
