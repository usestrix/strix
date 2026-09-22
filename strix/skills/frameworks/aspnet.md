---
name: aspnet
description: ASP.NET/IIS security testing covering ViewState deserialization RCE, IIS misconfiguration, Razor SSTI, and .NET gadget-chain deserialization
---

# ASP.NET / IIS

Classic ASP.NET Web Forms carries a uniquely dangerous default: `__VIEWSTATE` is server-side-deserialized on every postback. When the validation/encryption key material is known or missing (`EnableViewStateMac=false`, a leaked `machineKey`, or a predictable auto-generated key on a load-balanced farm), that's unauthenticated RCE via `ObjectStateFormatter`/`LosFormatter` gadget chains — not a theoretical bug class, a routinely-exploited one. ASP.NET Core apps trade this for different problems: over-exposed Swagger/OData surfaces and Jackson-equivalent JSON deserialization gadgets.

## Attack Surface

**Web Forms (.aspx, legacy but still common in enterprise)**
- `__VIEWSTATE`, `__EVENTVALIDATION`, `__VIEWSTATEGENERATOR` hidden fields on every page
- `web.config` — `machineKey`, `<compilation debug="true">`, `<customErrors mode="Off">`
- IIS-hosted, often behind ASP.NET Membership/Forms Authentication

**ASP.NET Core / MVC / Web API**
- Middleware pipeline, model binding, Razor Pages/MVC views
- `Microsoft.AspNetCore.OData`, Swashbuckle/Swagger (`/swagger/v1/swagger.json`)
- Identity/JWT bearer auth, SignalR hubs

**IIS-specific**
- Short-filename (8.3) disclosure via `~` enumeration
- `web.config`/`applicationHost.config` exposure, WebDAV misconfig, handler mappings

## Reconnaissance

**Version/config fingerprint**
```
curl -I https://target/  # X-AspNet-Version, X-Powered-By, X-AspNetMvc-Version headers (often present unless stripped)
GET /web.config             # should 403; if not, direct config leak including connection strings
GET /Web.config.bak /web.config~ /web.config.old
```

**Debug/custom-errors exposure**
```
GET /nonexistent.aspx
```
`customErrors mode="Off"` (or `RemoteOnly` viewed locally) leaks the full Yellow Screen of Death — stack trace, file paths, sometimes the ViewState MAC validation key in exception detail on very old frameworks.

**Swagger/OData discovery (Core)**
```
GET /swagger/v1/swagger.json
GET /swagger/index.html
GET /odata/$metadata
```
Map every endpoint and note which ones lack `[Authorize]` — ASP.NET Core route attributes are easy to miss on a new controller action, and Swagger enumerates the full surface including internal/admin-only-by-obscurity routes.

**IIS short-name enumeration**
```
GET /somepa~1.asp
```
`~1`-style responses (400 vs 404 depending on IIS version/patch) leak 8.3 short filenames, revealing hidden files/directories predictable enough to brute-force the full name.

## Key Vulnerabilities

### ViewState deserialization RCE

The core chain: `__VIEWSTATE` is Base64 + (optionally) HMAC-signed + encrypted `ObjectStateFormatter`/`LosFormatter` serialized data. If you can produce a validly-MAC'd payload — because `EnableViewStateMac=false`, the `machineKey` leaked (debug page, `web.config` exposure, or a known-weak auto-generated key on IIS/ASP.NET < 4.5 without `AutoGenerateKeys` disabled cluster-wide), or a MAC-bypass framework bug applies — a `ysoserial.net` gadget chain deserializes into RCE on postback.
```
# with recovered/known machineKey material:
ysoserial.net -p ViewState -g TypeConfuseDelegate -c "whoami" \
  --validationalg="SHA1" --validationkey="<KEY>" \
  --generatorlink="<VIEWSTATEGENERATOR value from the page>" \
  --apppath="/" --path="/vulnerable.aspx"
```
Submit the resulting `__VIEWSTATE` value as a postback and observe command execution. `EnableViewStateMac=false` alone (no key needed) is the fastest win — check for it directly by tampering the ViewState and seeing if the page still processes instead of throwing a MAC-validation error.

### IIS misconfiguration

- Short-name enumeration → hidden admin/backup file discovery
- `web.config` exposed directly (misconfigured handler mapping, extension-less request routing bug) leaking connection strings, `machineKey`, and `customErrors` overrides
- WebDAV enabled with weak auth — `PROPFIND`/`PUT` for file upload/directory listing bypass
- Handler mapping misconfig allowing `.aspx` execution from an upload directory intended to serve static files only

### Windows Auth / NTLM over HTTP

IIS with Windows Authentication (`IWA`/Negotiate) enabled sends NTLM challenge-response over HTTP — capture and relay to internal services the same way as any NTLM relay target (cross-reference `active_directory` skill's coercion/relay section); also check for HTTP-exposed Windows Auth endpoints accepting downgraded NTLMv1.

### Razor SSTI

```csharp
// Vulnerable: user input compiled as a Razor template
RazorEngine.Razor.Parse(userControlledTemplate, model);
```
Rare in default MVC (views are compiled at build time, not runtime), but present in "email template editor" / "report builder" features that use `RazorEngine`/`RazorLight` for runtime compilation. Payload: `@System.Diagnostics.Process.Start("cmd.exe","/c whoami")` or equivalent — full RCE since Razor compiles to real C#.

### .NET deserialization gadget chains

Beyond ViewState: any endpoint that calls `BinaryFormatter.Deserialize`, `ObjectStateFormatter`, `LosFormatter`, `NetDataContractSerializer`, or `Json.NET` with `TypeNameHandling != None` on attacker-controlled input is a gadget-chain candidate. `ysoserial.net` covers all of these formatters with the same gadget catalog (`TypeConfuseDelegate`, `ActivitySurrogateSelector`, `ObjectDataProvider`, etc.) — the formatter choice just changes the `-f` flag.

### Swagger/OData over-exposure (Core)

- Swagger UI reachable in production without auth exposes the entire internal API surface, including admin/debug controllers not linked from the frontend
- OData `$filter`/`$expand`/`$select` query injection into EF Core — malformed `$filter` expressions triggering verbose EF error pages that leak schema, or `$expand` traversing relationships the API author didn't intend to expose (an OData-flavored IDOR)

## Testing Methodology

1. **Fingerprint stack** — Web Forms vs Core, IIS version, `customErrors`/debug state.
2. **ViewState check** — tamper a byte and resubmit; MAC-validation error means it's enforced, silent processing means `EnableViewStateMac=false` (immediate RCE candidate).
3. **Config exposure sweep** — `web.config` variants, short-name enumeration, backup extensions (`.bak`, `.old`, `~`).
4. **Swagger/OData enumeration (Core)** — full endpoint map, cross-check each against actual `[Authorize]` behavior with an unauthenticated request.
5. **Deserialization surface (white-box)** — grep for `BinaryFormatter`, `NetDataContractSerializer`, `TypeNameHandling.All/Auto` in decompiled/source code.
6. **NTLM/Windows Auth check** — capture challenge-response if IWA enabled, evaluate relay targets per `active_directory` skill.

## Validation

1. ViewState RCE: show the tampered/forged `__VIEWSTATE` accepted and command output returned or received out-of-band.
2. Config/short-name disclosure: show the actual leaked content (connection string, `machineKey`, hidden filename) resolved to a real accessible resource.
3. Swagger-exposed unauthorized endpoint: show the same request succeeding unauthenticated and failing once the missing `[Authorize]` is simulated (e.g., compare against a sibling authorized endpoint's behavior).

## False Positives

- ViewState tampering consistently throws `MAC validation failed` — MAC is enforced and the key wasn't recoverable; not exploitable without the key.
- `customErrors mode="RemoteOn­ly"` and you're testing remotely as intended — the framework is behaving correctly, this isn't a debug-exposure finding.
- Swagger UI present but every listed operation independently enforces `[Authorize]` server-side (confirmed via unauthenticated request, not just attribute presence in decompiled code).

## Impact

- Unauthenticated RCE via ViewState/BinaryFormatter/NetDataContractSerializer gadget chains.
- Full config/connection-string disclosure via `web.config` exposure or debug pages.
- API surface bypass via undocumented/unauthenticated Swagger/OData-exposed admin endpoints.
- NTLM credential relay to internal AD infrastructure via Windows Auth-enabled endpoints.

## Pro Tips

1. Test the ViewState MAC first — it's a two-request check (tamper, resubmit) that immediately tells you whether the highest-impact bug class is even reachable.
2. `ysoserial.net` needs the exact formatter and, for ViewState, the exact `__VIEWSTATEGENERATOR` and app path — get these from the real page, don't guess.
3. Decompiled `web.config` or leaked `machineKey` values are directly reusable across every page in the same app pool — one leak compromises the whole app.
4. Pair with `insecure_deserialization` for the generic deserialization methodology and `active_directory` when Windows Auth exposes an NTLM relay path.

## Summary

ASP.NET testing splits along the Web Forms / Core line: Web Forms lives or dies on ViewState MAC enforcement and `machineKey` secrecy (recover either and you likely have RCE via `ysoserial.net`), while Core apps fail more often on scope — Swagger/OData surfaces exposing endpoints that were never meant to be public, or JSON deserialization left in permissive `TypeNameHandling` mode. Fingerprint which one you're facing before choosing an attack path.
