---
name: laravel
description: Laravel/PHP security testing covering APP_KEY exposure, mass assignment, cookie/session deserialization RCE, and framework CVE chains
---

# Laravel

Laravel's convention-heavy defaults (signed cookies, Eloquent mass-assignment guards, Blade auto-escaping) are safe when followed and catastrophic when bypassed — a leaked `APP_KEY` doesn't just decrypt data, it lets you forge signed cookies and, on vulnerable versions, chain straight to RCE via cookie deserialization. Prioritize finding the key before anything else.

## Attack Surface

**Core components**
- Routing (`routes/web.php`, `routes/api.php`), controllers, Form Requests, middleware pipeline
- Eloquent ORM (`$fillable`/`$guarded`, relationships, query builder), raw queries (`DB::raw`, `whereRaw`)
- Blade templates, session/cookie encryption (`APP_KEY`, `EncryptCookies` middleware)
- Queues (Redis/database/SQS-backed jobs), Laravel Horizon dashboard
- Sanctum/Passport (API auth), broadcasting (Pusher/WebSockets)

**High-value config**
- `.env` (`APP_KEY`, `APP_DEBUG`, DB creds, mail/queue creds)
- `config/app.php` — `debug` flag, `cipher` (AES-256-CBC default)

## Reconnaissance

**Debug mode fingerprint**
```
GET /nonexistent-route-to-trigger-500
```
`APP_DEBUG=true` renders a full Whoops/Ignition stack trace: file paths, environment variables (sometimes including `APP_KEY` itself in the "Environment & Details" tab), loaded config, and — on Laravel <8.4.2 with Ignition <2.5.2 — a working RCE via the `/​_ignition/execute-solution` endpoint (CVE-2021-3129, phpggc `Monolog/RCE1` gadget through the log viewer).

**`.env` exposure**
```
GET /.env
GET /storage/logs/laravel.log
GET /.git/config   # if .git wasn't excluded from deployment
```

**Fingerprint version**
- `X-Powered-By` header, `laravel_session` cookie name, 419 CSRF error page styling, `mix-manifest.json` / Vite manifest asset hashes correlate to release dates.

## Key Vulnerabilities

### APP_KEY compromise → cookie/session forgery

A leaked `APP_KEY` (via `.env` exposure, debug page, git history, or a misconfigured CI artifact) breaks the entire trust model:
- Laravel's encrypted cookies (`XSRF-TOKEN`, `laravel_session` when using `CookieSessionHandler`) are `AES-256-CBC` + HMAC under `APP_KEY` — with the key, forge arbitrary values via `Illuminate\Encryption\Encrypter` (`php artisan tinker` locally, or replicate the scheme with PyCryptodome).
- **Cookie deserialization RCE**: pre-Laravel-9 / misconfigured apps that still unserialize decrypted cookie payloads let a forged cookie deliver a PHP object-injection gadget chain. Use `phpggc` to generate a Laravel-compatible gadget (`Laravel/RCE13`, `Laravel/RCE9` depending on version), encrypt it with the recovered key, and set it as the cookie value.
```
phpggc Laravel/RCE13 system 'id' -b   # base64 gadget
# encrypt gadget payload with recovered APP_KEY using Encrypter-compatible scheme, set as cookie
```
- Signed URLs (`URL::signedRoute`) forged the same way once the key is known — bypasses any route relying on signature-only auth (common on unsubscribe/email-verification links).

### Mass assignment

```php
// Vulnerable: model has no $fillable/$guarded, or $guarded = []
User::create($request->all());
```
Test every `create()`/`update()`/`fill()` call reachable from user input by adding unexpected fields to the POST body: `is_admin=1`, `role=admin`, `email_verified_at=<future date>`, `balance=99999`. Also check `$fillable` on **nested** relations touched via `save()` on a related model from user-controlled input.

### Route-model binding IDOR

```php
Route::get('/orders/{order}', [OrderController::class, 'show']);
public function show(Order $order) { return $order; }  // no ownership check!
```
Implicit route-model binding resolves any ID to any record — the controller must explicitly check `$order->user_id === auth()->id()` or use a route-model binding scoped query (`Route::bind` override, or policy-based authorization via `$this->authorize()`). Missing `Gate`/`Policy` checks here are the most common Laravel IDOR pattern.

### Blade SSTI (rare, but check dynamic templates)

`Blade::compileString($userInput)` or `view()->make()` fed a user-controlled template string is a direct SSTI → RCE, since compiled Blade is raw PHP. Also check third-party packages that expose "custom email template" or "page builder" features — they sometimes route through raw Blade compilation.

### Queue/job deserialization

Queued jobs are PHP-serialized (or JSON with `Illuminate\Contracts\Queue\ShouldQueue` type hints) and stored in Redis/DB. If the queue backend is reachable and writable by an attacker (exposed Redis, SSRF to the queue driver, or a job-dispatch endpoint accepting arbitrary class names), a crafted serialized job payload can trigger RCE on the worker when unserialized — check `dispatch()` calls that accept user-controlled class/payload data.

### Package-specific CVEs

- **Ignition RCE** (CVE-2021-3129) — see debug-mode section above.
- **phpunit eval-stdin** (CVE-2017-9841) — `vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` left deployed to production `vendor/` is unauthenticated RCE; check `GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` on any exposed `vendor/` directory.
- **Laravel Debugbar** left enabled in production leaks the same env/query/route data as Ignition without the RCE, but is still a serious info-disclosure finding.

## Testing Methodology

1. **Debug/config exposure sweep** — `.env`, `/_ignition/`, `storage/logs/`, exposed `vendor/`, git artifacts.
2. **If `APP_KEY` recovered** — attempt cookie forgery, signed-URL forgery, and gadget-chain RCE in that order (increasing impact).
3. **Mass-assignment matrix** — every create/update endpoint, fuzz with privilege/ownership fields not present in the legitimate form.
4. **Route-model binding audit** — every `{model}` route parameter, swap IDs across two test accounts.
5. **Package/version CVE check** — `composer.lock` (if source-available) or fingerprint-derived version against known Laravel/Ignition/phpunit CVEs.

## Validation

1. Show the recovered `APP_KEY` and a forged cookie/signed-URL accepted by the live app as proof, not just theoretical derivation.
2. Mass assignment: side-by-side request without vs with the injected privileged field, showing the resulting record.
3. RCE via gadget chain: command output returned in response or via out-of-band callback, with the exact `phpggc` gadget and cookie value used.

## False Positives

- `.env` returns 403/404 consistently (web server correctly blocks dotfiles) — not exploitable even if debug mode is on elsewhere.
- `$fillable` explicitly whitelists only safe fields on every reachable model — mass assignment attempts correctly rejected.
- Route-model-bound controller explicitly scopes the query or calls `$this->authorize()`/a Policy before returning data.

## Impact

- Full RCE via APP_KEY-derived gadget chain or Ignition debug-mode exploit.
- Privilege escalation / data tampering via mass assignment on `is_admin`/`role`/billing fields.
- Horizontal/vertical IDOR via unguarded route-model binding.
- Session/account takeover via forged signed cookies once `APP_KEY` is known.

## Pro Tips

1. `APP_KEY` recovery is the single highest-leverage step — check debug pages, `.env`, and git history before anything else.
2. Ignition's exposed endpoint changed across versions (`/​_ignition/execute-solution` vs `/​_ignition/health-check`) — confirm the exact Laravel/Ignition version before assuming the CVE applies.
3. Mass assignment bugs hide in nested relationship saves (`$order->items()->create($request->item)`), not just the top-level model.
4. `phpggc` (PHPGGC) is the go-to gadget-chain generator for the deserialization path — install via `pipx install phpggc` equivalent or `git clone` + composer if not already present.

## Summary

Laravel security testing is APP_KEY-centric: recover it (via `.env`, debug pages, or git history) and cookie/session forgery, signed-URL bypass, and on older stacks full RCE all follow. Independent of that, mass assignment and unguarded route-model binding are the two most common everyday Laravel bugs — test every writable model field and every `{model}`-bound route for ownership enforcement.
