---
name: laravel
description: Security testing playbook for Laravel/PHP applications covering APP_KEY abuse, debug-mode RCE, mass assignment, .env exposure, and Blade/query flaws
---

# Laravel / PHP

Laravel is the most popular PHP framework. Its security hinges on a few artifacts: the `APP_KEY` (used to sign/encrypt cookies and signed URLs), debug mode (Ignition/Whoops error pages), and Eloquent's mass assignment protection. A leaked `APP_KEY` or an exposed `.env` file historically leads straight to RCE, and debug mode turns an error into a file-read/RCE primitive.

## Attack Surface

- `.env` exposure: `APP_KEY`, `APP_DEBUG`, `DB_*`, `MAIL_*`, `AWS_*`, `STRIPE_*` at the web root
- Debug mode (`APP_DEBUG=true`): Ignition error pages with log-file access, Whoops dumps, `phpinfo`
- `APP_KEY` abuse: encrypted cookie/XSRF token deserialization (CVE-2018-15133), signed URL forgery, `laravel_session` forgery
- Eloquent mass assignment: `$fillable`/`$guarded` gaps, `Model::create($request->all())`, `update($request->all())`
- Blade templating: `{{ }}` escapes by default but `{!! !!}` and `@php`/`@include` with user input do not
- Query builder/raw SQL: `DB::raw`, `whereRaw`, string concatenation
- File uploads: storage paths, mime/extension validation, symlink tricks
- Routes and middleware: `auth` middleware order, API token handling, signed routes (`signed` middleware)
- Packages: Telescope, Horizon, Nova, Debugbar, Adminer, phpMyAdmin exposed in production

## Reconnaissance

1. **Probe for `.env` and config leaks**: `/.env`, `/.env.backup`, `/.env.old`, `/storage/logs/laravel.log`, `/phpinfo.php`, `/.git/config`
2. **Fingerprint**: `X-Powered-By: PHP`, Laravel default error pages, `laravel_session`/`XSRF-TOKEN` cookies, `/api`, `/sanctum/csrf-cookie` (Laravel Sanctum), `vendor/`/`storage/` paths in errors
3. **Check debug mode**: trigger a 404/validation error and look for Whoops/Ignition with file paths and stack traces; test `/ignition/execute-solution` and `/_ignition/execute-solution` endpoints when Ignition is present
4. **Source-aware**: grep for `APP_KEY`, `APP_DEBUG`, `$request->all()`, `create(`, `update(`, `whereRaw`, `DB::raw`, `{!!`, `unserialize`, `Storage::`/`move_uploaded_file`
5. **Enumerate routes**: `php artisan route:list` (whitebox), blackbox via crawl/JS/`swagger`

## Key Vulnerabilities

### APP_KEY Leak -> RCE (CVE-2018-15133)

If `APP_KEY` is exposed (`.env`, debug page, `config` dump) on vulnerable versions (or cookie-session configurations), craft an encrypted Laravel cookie/XSRF token containing a PHP gadget chain:

```
phpggc Laravel/RCE1 system 'id' > payload
python3 - <<'PY'
# encrypt payload with APP_KEY (AES-256-CBC + HMAC, base64) into X-XSRF-TOKEN
PY
curl -X POST https://target/ -H 'X-XSRF-TOKEN: <encrypted>' ...
```

The server `unserialize()`s the decrypted value. Without a gadget, the same primitive yields session forgery and signed-URL forgery.

### Ignition RCE (CVE-2021-3129)

Older Ignition (`facade/ignition < 2.5.2`) exposed `/_ignition/execute-solution` with a file-path parameter that could reach `php://filter` chains to write a phar and trigger deserialization -> RCE. Fingerprint Ignition first, then apply the documented chain only on confirmed affected versions.

### `.env` / Config Disclosure

A readable `.env` is credentials-as-a-finding: database, mail, cache, cloud, and payment keys. Even `APP_DEBUG` alone changes the attack surface (debug pages).

### Mass Assignment

Eloquent models with broad `$guarded = []` (or missing `$fillable`) and `$request->all()` pass client-controlled fields straight into the database:

```
POST /api/users {"name":"x","is_admin":true,"role":"admin"}
```

Test every create/update endpoint for undeclared fields (`admin`, `role`, `verified`, `balance`). See `mass_assignment`.

### Blade / Template Injection

- `{!! $userInput !!}` renders unescaped HTML -> XSS
- `@include($userInput)` / `view($userInput)` with user-controlled template names -> file read/LFI or template injection
- `@php` blocks with user data in server-rendered templates

### SQL Injection

- `whereRaw`/`DB::raw`/`orderByRaw` with user input
- `->where('col', $request->input('x'))` is safe, but `->whereRaw("col = '$x'")` is not
- Eloquent `firstOrCreate`/`updateOrCreate` with unvalidated attributes

### Signed URLs

Laravel signed routes (`URL::signedRoute`, `->signed`) embed an HMAC signature from `APP_KEY`. With the key, forge signatures for arbitrary parameters (e.g., `user_id` in unsubscribe/verify links). With a live app, test whether `expires` and signature are validated on the actual route.

### Upload Flaws

- Extension whitelist bypass (`.php.jpg`, `.phtml`, double extensions, case variants)
- Stored uploads under web root with guessed paths
- `Storage::put` with user-controlled filenames -> path traversal in storage

## Advanced Techniques

- **Cookie/session decryption**: with `APP_KEY`, decrypt `laravel_session`/XSRF cookies to read and forge session state
- **Signed URL forgery**: reproduce Laravel's `URL::signature` (HMAC-SHA256 over the URL) with the key
- **Telescope/Debugbar exposure**: `/telescope`, `/_debugbar` leak requests, queries, and auth tokens
- **Queue/job abuse**: serialized jobs in queues; if a job unserializes attacker input, RCE (see `insecure_deserialization`)
- **Race on idempotency**: payment/webhook handlers without idempotency keys (see `race_conditions`, `payment_gateways`)
- **Log poisoning -> LFI**: `laravel.log` with attacker-controlled content, then read via debug/file endpoints

## Testing Methodology

1. Probe `.env`, debug pages, and Ignition endpoints first - they shortcut everything
2. Fingerprint Laravel/PHP versions from headers/errors/cookies
3. Test mass assignment on every create/update endpoint
4. Audit query builder sinks and Blade output for injection
5. Check signed URLs and session cookies once `APP_KEY` is known or suspected
6. Test uploads and storage paths for traversal/execution
7. Verify debug/package exposures (Telescope, Debugbar, Adminer)

## Validation

1. `.env`/config disclosure: show real credentials and their impact (DB login, payment key)
2. Mass assignment: create/update with an undeclared privileged field and show server-side effect
3. CVE paths: only exploit confirmed versions; show a benign command/marker proof
4. SQLi: standard in-band/blind proof (see `sql_injection`)
5. Signed URL: forge a signature for a parameter the app honors (e.g., user ID in a verification link)

## False Positives

- `.env` returned as a 404/SPA fallback page (200 with app HTML, not the file)
- `APP_DEBUG` false - Ignition/Whoops not exploitable, but stack traces may still leak paths
- Mass assignment rejected by `$fillable` (no effect) or `$guarded` fields silently dropped
- Blade `{!! !!}` rendering server-side templates without user input (no injection point)
- Signed URL rejected due to `expires`/signature validation

## Impact

- RCE via APP_KEY deserialization or Ignition on affected versions
- Credential theft and lateral movement via `.env`/config disclosure
- Account/role takeover via mass assignment
- Data theft via SQLi, file reads, and log leaks

## Pro Tips

1. `.env` is the crown jewel - always probe it before anything else on a PHP app
2. Test mass assignment fields on *every* write endpoint; `$guarded` is often missing or empty
3. `APP_KEY` exposure is a finding even when RCE chains fail - session and signed-URL forgery remain
4. Check `APP_DEBUG` behavior deliberately: trigger errors and read the page source for leaked paths/config
5. Pair with `mass_assignment`, `sql_injection`, `insecure_deserialization`, `ssti`, and `insecure_file_uploads` skills

## Summary

Laravel attacks start with the artifacts: `.env`, `APP_KEY`, debug/Ignition pages. Then hunt mass assignment on every write path, raw SQL and Blade sinks, signed-URL forgery, and exposed dev packages. Prove each with real requests and minimal impact.
