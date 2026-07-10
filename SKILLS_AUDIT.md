# Skills Audit — WebSkills corpus vs. built-in Strix skills

**Date:** 2026-07-10
**WebSkills corpus:** `/home/amr07/.claude/skills` — 47 skills (each a `SKILL.md` + reference files; 292 `.md` total, but 221 of those belong to three knowledge-base skills, so the meaningful unit is the 47 skills).
**Strix built-in skills:** `/home/amr07/strix/strix/skills` — 53 skill files across 9 categories (cloud, coordination, custom, frameworks, protocols, scan_modes, technologies, tooling, vulnerabilities).

**Comparison method (be honest about depth):** each WebSkill was compared to the Strix inventory at the level of YAML `description`, section headers, and known scope — not a full line-by-line body diff. Classifications reflect *scope and structural* overlap. Before acting on any "Partially covered" delta or "Gap" port, spot-check the actual body of the specific file.

**Classification key:**
- **Fully covered** — Strix already covers this as well or better; skip it.
- **Partially covered** — overlaps an existing Strix skill but carries a real, nameable delta (extra techniques, bypass tables, chaining, feature-specific patterns); merge just the delta later.
- **Gap** — no meaningful Strix equivalent; candidate to port as a new skill (or, for KB/data assets and out-of-scope domains, flagged as *not* a simple skill port).

---

## Comparison table

| WebSkills file | Topic | Matching Strix skill (path, or "none") | Classification | Notes |
|---|---|---|---|---|
| 2fa-test | 2FA/MFA/OTP setup, bypass, disable flows | none (partial: `vulnerabilities/authentication_jwt.md`) | **Gap** | Strix has JWT/OIDC token testing but no 2FA/MFA *flow* methodology (secret rotation, resend/verify rate limits, disable-2FA, backup codes). Deep, in-domain. High-value port. |
| api-test | OWASP API Top 10 hunting workflow | `vulnerabilities/idor.md`, `broken_function_level_authorization.md`, `mass_assignment.md`, `business_logic.md`, `ssrf.md` | **Partially covered** | Strix covers the individual API vuln classes (often better, as discrete skills). Delta = the unified API *recon + inventory + methodology* wrapper (Swagger/GraphQL discovery, shadow/zombie APIs). Merge the recon/workflow layer. |
| bac-test | Broken access control aggregator (IDOR/BOLA/BFLA/mass-assignment) | `vulnerabilities/idor.md`, `broken_function_level_authorization.md`, `mass_assignment.md` | **Partially covered** | Strix splits BAC into three strong discrete skills. This is an aggregator/reference-map; delta = the consolidated IDOR bypass-variant checklist. Merge any bypass variants Strix's idor.md lacks. |
| bb-methodology | Hunter mindset + 5-phase non-linear workflow + session discipline | `scan_modes/{deep,standard,quick}.md`, `coordination/root_agent.md` | **Partially covered** | Strix's scan_modes + root_agent are the orchestration/methodology layer for an autonomous agent. Delta = human-hunter mindset (developer-psychology, anomaly-driven What-If). Portable only as philosophy notes, not workflow. |
| bug-bounty | Master index/workflow across all vuln classes | `coordination/root_agent.md` + `scan_modes/*` + whole skill tree | **Fully covered** | This is a master index; Strix's agent architecture (root_agent + scan_modes dispatching discrete skills) replaces the need for a hand-written master index. Skip. |
| cicd-security | CI/CD pipeline attacks (Actions injection, secret exfil, runner poisoning, OIDC, supply chain) | none | **Gap** | Zero Strix coverage. Deep, specific, in-domain (many targets expose public CI). **Top port candidate.** |
| combined-security-test | Money/checkout logic + tech-stack misconfig fingerprinting + localization apps | `vulnerabilities/business_logic.md`, `race_conditions.md`, `frameworks/*`, `information_disclosure.md` | **Partially covered** | Overlaps business_logic/race and frameworks. Strong deltas: money-flow specifics (rounding, currency arbitrage, voucher abuse), and tech-stack misconfig fingerprints Strix lacks (Symfony, Laravel, Spring Boot actuator, Rails, many SaaS misconfigs). Merge the misconfig + money deltas. |
| command-injection-test | OS command injection | `vulnerabilities/rce.md` | **Fully covered** | Strix rce.md covers command injection as a primary channel. Only possible delta = extra Unix/Windows payloads → fold into `security-arsenal` port if kept, else skip. |
| cors-test | CORS misconfiguration | `vulnerabilities/csrf.md` (folds in CORS) | **Partially covered** | Strix csrf.md explicitly covers CORS misconfig. Delta = dedicated origin-reflection/regex-bypass variants. Merge bypass variants into csrf.md. |
| crlf-test | CRLF injection / response splitting | `vulnerabilities/header_injection.md` | **Fully covered** | header_injection.md explicitly covers CRLF/response splitting. Skip (fold any payload delta into header_injection). |
| csrf-test | CSRF token bypass / SameSite | `vulnerabilities/csrf.md` | **Fully covered** | Dedicated, thorough Strix skill (token bypass, SameSite, CORS, state-change abuse). Skip. |
| cve-intel | 23k-CVE greppable knowledge base | none (`tooling/nuclei.md` for CVE scanning) | **Gap (data asset)** | No Strix equivalent, but this is a *data engine*, not a methodology skill. Do **not** port as a `SKILL.md` — it needs integration work if wanted at all. Strix leans on nuclei for CVE detection. |
| file-upload | Upload extension/content-type bypass | `vulnerabilities/insecure_file_uploads.md` | **Fully covered** | Strix skill covers extension bypass, content-type, path traversal. Minor payload-table delta at most. Skip. |
| function-abuse-test | Account-function flows (change password/email, rate limits) | partial: `vulnerabilities/business_logic.md` | **Gap** | Strix has no account-management-flow skill. Feature-specific patterns (current-password checks, confirmation logic). Overlaps business_logic generically. Port as part of a consolidated feature-flows skill. |
| graphql-audit | GraphQL hunting + tooling automation | `protocols/graphql.md` | **Partially covered** | Strix graphql.md covers introspection, resolver injection, batching, authz bypass. Delta = clairvoyance/field-suggestion enumeration + tool automation (graphw00f, gqlmap, graphql-cop). Merge the tooling + clairvoyance delta. |
| graphql-test | GraphQL navigation/dedup meta-file | `protocols/graphql.md` | **Fully covered** | This is a navigation/cross-reference stub over GraphQL content; Strix graphql.md is the real coverage. Skip. |
| hackerone-kb | HackerOne disclosed-report intelligence engine (129 files + query bin) | none | **Gap (data/infra asset)** | No Strix equivalent and genuinely high-value, but it is a KB + query engine, not a skill file. Do **not** port as a `SKILL.md`; if wanted, it's a separate integration. |
| idor-403-bypass | IDOR + 403/401 bypass chaining | `vulnerabilities/idor.md` | **Partially covered** | IDOR itself is covered by idor.md. Delta = the 403/401 bypass techniques (header/method/encoding/path tricks) and how they chain into IDOR — Strix has no 403-bypass skill. Merge the 403-bypass matrix. |
| improper-authentication-testing | JWT fast-path + SAML fast-path | `vulnerabilities/authentication_jwt.md` | **Partially covered** | JWT/OIDC covered by authentication_jwt.md. Delta = **SAML** (not covered anywhere in Strix). Port the SAML section as a new skill or add to authentication_jwt. |
| invite-feature-test | Invitation-flow bugs (token leak, IDOR, role escalation) | partial: `idor.md`, `mass_assignment.md`, `business_logic.md` | **Gap** | Strix has no feature-flow skills. Feature-oriented methodology that chains generic classes per invite flow. Port as part of a consolidated feature-flows skill. |
| json-request-test | JSON request manipulation / content-type shape tricks | partial: `mass_assignment.md` | **Partially covered** | Small technique file; folds into mass_assignment/API testing (shape variants, content-type swaps). Merge any distinct tricks; likely no standalone need. |
| lfi-test | LFI/path traversal payloads | `vulnerabilities/path_traversal_lfi_rfi.md` | **Fully covered** | Dedicated Strix skill. At most a payload/wordlist delta. Skip. |
| meme-coin-audit | Meme-coin/token rug-pull (Solana SPL, Token-2022) | none | **Gap (out of scope)** | Web3/token domain — outside Strix's web/cloud-pentest core. Port only if deliberately expanding Strix's scope. Low priority for this fork. |
| messaging-feature-test | Messaging-flow bugs (injection, IDOR) | partial: `idor.md`, `xss.md` | **Gap** | Feature-flow methodology, no Strix equivalent. Port as part of a consolidated feature-flows skill. |
| methodology-techniques | 61k-chunk exploit/methodology KB (ExploitDB/Metasploit/WSTG/RFC/…) | none (Strix uses discrete `tooling/*` skills) | **Gap (data asset)** | Reference corpus, not a methodology skill. Do **not** port as a `SKILL.md`; separate integration if wanted. |
| money-related-features-test | Payment/refund/cart/pricing abuse | `vulnerabilities/business_logic.md` | **Partially covered** | business_logic.md is the natural home. Delta = money-specific patterns (refund abuse, cart/wishlist, currency/quantity manipulation). Merge deltas into business_logic. |
| oauth-misconfigurations-testing | OAuth/OIDC misconfig + ATO technique set | `protocols/oauth.md` | **Partially covered** | Strix oauth.md covers redirect/token/PKCE/client misconfig. Delta = broader ATO technique breadth (nOAuth, forced account linking, host/referer injection, IdP tricks). Merge the extra ATO techniques. |
| open-redirect-test | Open redirect bypass + chains | `vulnerabilities/open_redirect.md` | **Fully covered** | Strix open_redirect covers phishing/OAuth-theft/allowlist bypass. Minor delta = redirect→XSS/SSRF chain notes. Fold if kept; otherwise skip. |
| recon | Full web recon methodology (dorking, JS secrets, WAF/origin, big-scope org) | `tooling/{subfinder,httpx,katana,naabu,nmap,ffuf,nuclei}.md`, `scan_modes/*` | **Partially covered** | Strix has the tool-syntax skills + scan_mode recon phases. Delta = methodology orchestration, dorking, origin-IP discovery, big-scope org strategy. Merge the strategy layer. |
| registration-takeover-test | Signup/registration ATO (email-param manip, dup registration) | partial: `business_logic.md` | **Gap** | Registration-flow ATO methodology; no Strix equivalent. Port as part of a consolidated feature-flows skill. |
| report-writing | BB report writing (H1/Bugcrowd/Intigriti/Immunefi, CVSS) | none | **Gap (domain-specific)** | Strix generates its own reports; this is human bug-bounty-submission craft. Port only if you want BB-submission output from the fork. Limited portability. |
| reset-password-test | Password-reset ATO (host-header poisoning, IDN, token issues) | partial: `header_injection.md` | **Gap** | header_injection covers host-header confusion generically; reset-flow chaining is not in Strix. Port as part of a consolidated feature-flows skill. |
| security-arsenal | Consolidated payloads/bypass tables/gf patterns/always-rejected list | payloads embedded across each `vulnerabilities/*` skill | **Partially covered** | Strix distributes payloads per-vuln-skill (arguably cleaner). Delta = the always-rejected-bug list + gf pattern names + conditionally-valid-with-chain table. Merge those reference tables where useful. |
| session-fixation-test | Session fixation methodology | none | **Gap** | Strix has no session-management skill. Small but genuine gap, in-domain. Reasonable port. |
| sqli-test | SQL injection | `vulnerabilities/sql_injection.md` + `tooling/sqlmap.md` | **Fully covered** | Strix sql_injection (union/blind/error/ORM + per-DBMS primitives) + sqlmap skill are strong. Skip. |
| ssrf-test | SSRF reference map + IP bypass tables | `vulnerabilities/ssrf.md` | **Partially covered** | Strix ssrf.md is thorough (AWS/GCP/Azure metadata, internal services, protocol smuggling). Delta = consolidated IP-bypass table (decimal/octal/hex/IPv6/rebinding variants). Merge the bypass table if richer than Strix's. |
| triage-validation | 7-Question Gate + validation gates + always-rejected list + CVSS | `coordination/source_aware_whitebox.md` (validation guardrails), `scan_modes/*` validation phases | **Partially covered** | Strix has validation guardrails in its coordination layer. Delta = BB-submission N/A-avoidance gate + always-rejected list. Merge the gate as a checklist if keeping BB-submission workflow. |
| web-cache-vulnerabilities | Web cache poisoning + deception | partial: `header_injection.md` (mentions cache poisoning) | **Partially covered** | header_injection touches cache poisoning via headers. Delta = dedicated cache-deception + keyed/unkeyed-input methodology. Consider porting the deception half as a delta or small new skill. |
| web2-recon | Web2 recon pipeline + continuous monitoring | `tooling/*`, `scan_modes/*` | **Partially covered** | Overlaps recon tooling. Delta = continuous monitoring (new-subdomain/JS-change/GitHub-commit watch) + JS secret analysis workflow. Merge the monitoring workflow. |
| web2-vuln-classes | 24-bug-class reference | discrete `vulnerabilities/*` skills (24 of them) | **Fully covered** | Strix's 24 discrete vulnerability skills cover these individually and in more depth. This is a summary reference. Skip. |
| web3-audit | Smart-contract audit (10 DeFi bug classes, Foundry PoC) | none | **Gap (out of scope)** | Web3 domain, outside Strix's web/cloud core. Port only to expand scope. Low priority for this fork. |
| websockets-iis-test | WebSockets hacking + IIS hacking | none | **Gap** | Neither WebSocket nor IIS is covered by any Strix skill. In-domain, deep. **Strong port candidate.** |
| writeup-techniques | 15.4k-writeup distilled playbooks + raw corpus | none | **Gap (data asset)** | Reference corpus, not a skill file. Do **not** port as a `SKILL.md`; separate integration if wanted. |
| xss-html-injection-selfxss-bypass | XSS + HTML injection + self-XSS escalation | `vulnerabilities/xss.md` | **Fully covered** | Strix xss.md covers reflected/stored/DOM + CSP bypass. Minor delta = self-XSS→stored escalation angle. Fold if kept; otherwise skip. |
| xxe-test | XXE / external entity injection | `vulnerabilities/xxe.md` | **Fully covered** | Dedicated Strix skill (file disclosure, SSRF via XML, error-based). Skip. |
| credential-attack | Password spray pipeline (wordlist/breach/osint/spray) | none | **Gap (adjacent domain)** | Strix is app-vuln focused; no credential-spray tooling. In-scope for offensive work but a different capability class. Medium priority. |
| mobile-pentest | Android/iOS app pentest (runtime-first, decompile) | none | **Gap (out of scope)** | Mobile domain, outside Strix's web/cloud core. Port only to expand scope. Low priority for this fork. |

---

## Summary

**Total WebSkills audited:** 47

| Classification | Count | Files |
|---|---|---|
| **Fully covered** (skip) | 12 | bug-bounty, command-injection-test, crlf-test, csrf-test, file-upload, graphql-test, lfi-test, open-redirect-test, sqli-test, web2-vuln-classes, xss-html-injection-selfxss-bypass, xxe-test |
| **Partially covered** (merge delta) | 17 | api-test, bac-test, bb-methodology, combined-security-test, cors-test, graphql-audit, idor-403-bypass, improper-authentication-testing, json-request-test, money-related-features-test, oauth-misconfigurations-testing, recon, security-arsenal, ssrf-test, triage-validation, web-cache-vulnerabilities, web2-recon |
| **Gap** (port candidate) | 18 | 2fa-test, cicd-security, cve-intel, function-abuse-test, hackerone-kb, invite-feature-test, meme-coin-audit, messaging-feature-test, methodology-techniques, registration-takeover-test, report-writing, reset-password-test, session-fixation-test, web3-audit, websockets-iis-test, writeup-techniques, credential-attack, mobile-pentest |

### The core web vuln classes are largely redundant
12 of your files (and most of the 17 partials) map onto Strix skills that are as good or better — Strix maintains discrete, dedicated skills for XSS, SQLi, SSRF, XXE, CSRF, IDOR, LFI/traversal, open redirect, file upload, command-injection/RCE, CRLF/header-injection. Your equivalents are mostly payload/bypass reference maps; the only thing worth salvaging from them is specific bypass-table or chaining deltas, merged into the existing Strix files.

### Highest-value Gaps to port first (in-domain, deep, no Strix equivalent)
Ranked by depth × relevance to Strix's web/cloud-pentest core:

1. **cicd-security** — CI/CD pipeline attacks. Zero Strix coverage, very deep, and many targets expose public CI. Clear #1.
2. **websockets-iis-test** — WebSockets + IIS. Two whole surfaces Strix doesn't touch.
3. **2fa-test** — 2FA/MFA flow methodology. Strix only has JWT tokens; the flow bugs (setup, bypass, disable) are a real gap.
4. **A consolidated "feature-flow" skill** built from `invite-feature-test` + `messaging-feature-test` + `registration-takeover-test` + `reset-password-test` + `function-abuse-test`. Individually these overlap generic classes, but together they encode feature-oriented testing (chaining classes per product feature) that Strix's vuln-class-oriented skills lack. Port as **one** new skill, not five.
5. **session-fixation-test** — small but genuine, in-domain gap.

### Gaps that are NOT simple skill ports (handle separately or defer)
- **Data/KB assets** — `hackerone-kb`, `cve-intel`, `methodology-techniques`, `writeup-techniques`. These are corpora + query engines (221 of the 292 corpus files). They are high-value but require integration work, not a `SKILL.md` drop-in. Do not port as skills.
- **Out-of-scope domains** — `web3-audit`, `meme-coin-audit`, `mobile-pentest` (and to a lesser extent `credential-attack`, `report-writing`). Outside Strix's web/cloud-pentest core. Port only if you deliberately want to widen the fork's scope.

### Reverse gaps (what Strix has that your corpus lacks — for awareness)
Strix brings skills you have **no** equivalent for and should keep as-is: `nosql_injection`, `prototype_pollution`, `insecure_deserialization`, `http_request_smuggling`, `mass_assignment` (dedicated), `subdomain_takeover` (dedicated), `information_disclosure`, `llm_prompt_injection`, all **cloud** skills (aws/gcp/kubernetes), all **technology** skills (auth0/firebase/supabase), all **framework** skills (django/fastapi/nestjs/nextjs), and the **tooling** syntax skills. Don't overwrite these.

---

*Audit only — no skill files were created, edited, or ported; no application code touched; the `strix` tool was not run. Await go-ahead on which items to act on.*
