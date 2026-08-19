---
name: flask
description: Security testing playbook for Flask/Werkzeug applications covering debug-mode PIN RCE, session forgery, SSTI, and common misconfigurations
---

# Flask / Werkzeug

Flask is Python's most popular microframework. Its session cookie is signed (not encrypted) with `SECRET_KEY`, its dev server ships a debugger whose PIN is derivable from machine fingerprints, and its template engine (Jinja2) is a favorite SSTI target. A leaked secret key, an enabled debugger, or a single `render_template_string` call turns a small app into RCE.

## Attack Surface

- `SECRET_KEY` handling: hardcoded in source, `.env`, config files, or weak/guessable values
- Debug mode (`app.run(debug=True)`, `FLASK_DEBUG=1`): Werkzeug debugger console at `/console` with PIN auth
- Template rendering: `render_template_string`, `render_template` with user-controlled template names/context
- Session cookies: signed with `itsdangerous`; contents readable (base64) and forgeable with the key
- Routes/params: `request.args`, `request.form`, `request.json`, `request.values` into queries, files, shell, URLs
- File handling: `send_file`, `send_from_directory`, uploads (`secure_filename` misuse), static folders
- Auth: `flask-login`, session-based auth, `@login_required` ordering, `before_request` gaps
- SQLAlchemy ORM and raw SQL; `jsonify`/`pickle`/`yaml` deserialization in APIs

## Reconnaissance

1. **Fingerprint**: `Server: Werkzeug/<ver> Python/<ver>` header, 404/500 page shapes, debugger badge when debug is on
2. **Probe `/console`** - if the Werkzeug debugger loads, PIN auth protects it; the page leaks the debugger version and sometimes the module path
3. **Decode the session cookie** (`flask-unsign --decode --cookie <cookie>` or base64) - it often reveals user IDs, roles, and whether the key is short/weak
4. **Source-aware**: grep for `SECRET_KEY`, `render_template_string`, `debug=True`, `pickle`, `eval(`, `subprocess`, `os.system`
5. **Enumerate routes**: `url_map` via source, blackbox via crawl + JS; check `/static`, `/api/*`, `/admin`

## Key Vulnerabilities

### Werkzeug Debugger PIN RCE

With `debug=True` and an exposed `/console`, the console is gated by a PIN derived from `machine-id`, MAC, and `modname`. The PIN is obtainable:

- From a file read / SSTI / SSRF that leaks `/etc/machine-id` (or `/proc/sys/kernel/random/boot_id`) + MAC + username/module path
- From an error traceback that reveals the filesystem paths needed
- From the known `get_machine_id()` algorithm (compute PIN locally with the same inputs)

Then execute `import os; os.system('id')` (or a benign proof) in the console. Treat an exposed debugger without PIN enforcement as direct RCE.

### Session Forgery

Flask sessions are `itsdangerous` signed cookies. With the key (leaked in source, `.env`, or weak/brute-forced), forge:

```
flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin'}" --secret 'the-secret'
```

Even without the key, decode the cookie to find forgeable claims when the app trusts them (e.g., `is_admin` stored client-side).

### Server-Side Template Injection

`render_template_string(user_input)` is direct SSTI:

```
{{7*7}}
{{config}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

Also test template *name* injection (`render_template(user_input)` with path traversal) and context-attribute abuse when only some values are user-controlled. See `ssti` for the full escape set.

### Path Traversal / File Disclosure

- `send_file(user_input)` / `send_from_directory` with user-controlled paths
- `secure_filename` misuse (it strips, but double-encoding or NUL bytes occasionally slip through)
- `/static` misconfig serving `.env`, backups, or source maps

### Deserialization

- `pickle.loads` on user data (cookie, API body) -> RCE with a crafted pickle
- `yaml.load` (PyYAML unsafe mode) -> RCE
- Flask-RESTful/Flask-RESTX endpoints that deserialize JSON into models (mass assignment)

### Auth Flaws

- `before_request` checks that can be skipped via `@app.route` ordering or blueprint prefixes
- Session user IDs not tied to a server-side record (client-trusted identity)
- Missing `Secure`/`HttpOnly`/`SameSite` on session cookies
- Login rate limiting absent (see `weak_password_detection`)

### Host Header / Redirect Abuse

- Password reset/email links built from `request.host`/`request.url_root` -> host-header poisoning (see `header_injection`)
- `next`/`redirect` params with open redirects

## Advanced Techniques

- **PIN derivation**: gather `/etc/machine-id` (or boot_id) + MAC address + `modname` ("flask.app") + username, then reproduce the Werkzeug algorithm (public implementations exist) and log into `/console`
- **SECRET_KEY brute force**: short/wordlist keys via `flask-unsign --unsign --wordlist ...`
- **SSTI -> config exfil**: `{{config}}` leaks `SECRET_KEY` even when RCE fails
- **Mass assignment**: JSON bodies with `admin`/`role` fields when models are updated from request data
- **SQLAlchemy injection**: string-built `filter()`/raw `text()` with user input
- **File upload -> code exec**: extension whitelist bypass, `.py` in static, overwriting templates (template path traversal + upload)

## Testing Methodology

1. Fingerprint Flask/Werkzeug and check debug status
2. Decode session; test `flask-unsign` against common/leaked secrets
3. Probe `/console` and try PIN derivation when reachable
4. Fuzz `render_template_string`/template-name inputs with `{{7*7}}` first
5. Test `send_file`/uploads/static for traversal
6. Audit auth/session handling; test host-header and redirect sinks
7. Check deserialization endpoints (pickle/yaml) with minimal proofs

## Validation

1. SSTI: show `{{7*7}}` -> `49`, then a benign builtin read (`os.getcwd()` or `config['SECRET_KEY']`)
2. Session forgery: log in as another user with a signed cookie, non-destructively
3. Debugger: execute a benign command (`os.getpid()`/`id`) and show output; note that console access equals RCE
4. Traversal: read a real file with the exact payload

## False Positives

- Debugger page loads but PIN required and no leak path - note the exposure, not RCE
- Session decodes to claims the server ignores (client-side trust missing)
- `{{7*7}}` rendered by a client-side template engine, not Jinja (check response origin)
- `send_file` normalizes `..` and rejects traversal
- `secure_filename` cleans uploads - extension tricks fail

## Impact

- Direct RCE via debugger console or pickle/unsafe-yaml
- RCE/secret theft via SSTI
- Account takeover via session forgery with leaked/weak SECRET_KEY
- Data exposure via traversal and misconfigured static

## Pro Tips

1. `{{config}}` before RCE - leaking `SECRET_KEY` is already a finding and enables session forgery
2. Decode every Flask session cookie; client-side identity claims are a classic bug
3. Debug mode is RCE-by-default once the PIN is derivable; prioritize `/console` when present
4. `render_template_string` is the #1 Flask RCE; grep source for it in whitebox mode
5. Pair with `ssti`, `command_injection`, `insecure_deserialization`, and `header_injection` skills

## Summary

Flask security is a few primitives deep: the session secret, the debugger, Jinja, and file/deserialization sinks. Decode and forge sessions, chase `SECRET_KEY` and debug PIN, probe template rendering, and validate traversal/deserialization with minimal proofs.
