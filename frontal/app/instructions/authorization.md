# Security Testing Instructions: {{TEXT_PROJECT_NAME}}

## 1. Objectives and Priorities
- Investigation priorities, in order: {{SELECT_PRIORITIES}}.
- Specific questions, critical workflows and business rules: {{TEXT_QUESTIONS_AND_RULES}}.
- Specific authorization test cases: {{TEXT_AUTHORIZATION_TEST_CASES}}.

## 2. Project Context
- Application description, API description and main workflows: {{TEXT_APPLICATION_DESCRIPTION}}.
- User types: {{SELECT_USER_TYPES}}.
- Application deployment and access model: determine whether the application is external, internal or mixed from {{SELECT_INTERNET_EXPOSURE}} and the authorized targets. Do not infer exposure from DNS names, login pages or missing deployment evidence.
- Asset sensitivity: {{SELECT_ASSET_SENSITIVITY}}.
- Authorization model: {{TEXT_AUTHORIZATION_MODEL}}. If no model is provided, do not treat an inferred model as confirmed policy.
- Expected access-control matrix: {{TEXT_ACCESS_MATRIX}}.
- Critical business flows: {{TEXT_CRITICAL_BUSINESS_FLOWS}}.
- Functionality criticality: {{TEXT_FUNCTIONALITY_CRITICALITY}}.
- Additional workspace resources and when to consult them: {{TEXT_ADDITIONAL_RESOURCES}}.
- Record relevant web technologies, frameworks, front-end components, server-side rendering, browser storage, file-processing features, identity integrations and trust boundaries only when supported by supplied information or observed in-scope evidence.

## 3. Assessment, Scope and Safety
- Assessment approach: {{SELECT_ASSESSMENT_TYPE}}.
- Exact authorized URLs, hosts, ports, repositories, branches, paths, accounts, tenants, environments and testing window: {{TEXT_AUTHORIZED_TARGETS}}.
- In-scope web protocols: {{SELECT_PROTOCOLS}}.
- Out-of-scope assets, environments and data: {{SELECT_EXCLUSIONS}}.
- Prohibited activities, including on in-scope assets: {{SELECT_PROHIBITED_ACTIONS}}.
- Before testing, build an explicit scope map containing each authorized host, port, path, environment, api, repository or branch, exposure classification, assessment approach and applicable account or role. Do not follow redirects, links, identity-provider flows or embedded third-party resources outside that map.
- Stop and record, without continuing, any test path that leaves the authorized scope, affects a real user or a real tenant's data, risks irreversible modification or deletion, or requires an action beyond the minimum needed to demonstrate the access-control failure.
- Objectives, inferred policy, visible UI elements, discovered endpoints and supporting files do not expand authorization or testing scope.

## 4. Authentication, Accounts and Test Data
- Authentication system: {{SELECT_AUTHENTICATION_METHOD}}.
- Accounts, users, roles and tenants, without secrets: {{TEXT_ACCOUNTS_AND_ROLES}}.
- For every designated test identity, record a non-secret identifier, expected role, tenant or organisational context, approved workflows, expected access boundaries and any restrictions. Where multiple roles exist, use only the supplied users and compare behaviour only across explicitly authorized roles.
- Credential access, login, identity verification, MFA handling, session renewal, logout and account recovery procedure: {{TEXT_ACCESS_PROCEDURE}}.
- Authorized synthetic data and ownership: {{TEXT_TEST_DATA}}.
- Collect only the minimum evidence required by the engagement. Never place passwords, tokens, session identifiers, recovery codes or unredacted personal or business data in findings or reports.
- Authentication establishes identity or client context; authorization determines permitted operations, objects and properties. Validate object-level, property-level and function-level controls separately. Do not infer permissions from UI visibility, token presence or a successful login.
- Keep passwords, private keys, client secrets, certificates, API keys, bearer tokens, session identifiers and recovery material out of reports and workspace resources.

## 4.1 Authorization (Authorization only)
### 4.1 Test identity requirements
- Reference every designated test identity by the account label defined in the “Accounts, roles and tenants” entry.
- For each account label, record the declared role, privilege tier, tenant, ownership context and any explicitly documented restrictions.
- Use only designated test accounts, authorized tenants, approved authentication procedures and authorized test data.
- Do not invent accounts, roles, permissions, tenant membership, ownership relationships or authentication steps.
- Keep credentials, tokens, cookies, API keys, session identifiers and other reusable authentication material out of reports and shared workspace resources.
- Maintain an isolated authenticated session for each account label. Do not reuse or transfer session material between identities unless that transfer is the explicitly authorized test being performed.

### 4.2 Relationship between authentication and authorization
- Authentication establishes the acting identity or client context; authorization determines whether that identity may perform an action on a function, resource, object, property or tenant.
- A successful login, valid session, cookie, token or API key does not demonstrate that a subsequent action is authorized.
- UI visibility, hidden controls, endpoint discoverability and client-side restrictions are supporting observations only. They do not establish the expected authorization policy or prove that server-side authorization is correctly enforced.

### 4.3 Source and confidence of expected authorization decisions
- Determine the expected authorization decision for each test case using the authorization model and access-control matrix defined in the “Authorization model” entry and the “Expected access-control matrix” entry.
- Classify the source of each expected decision as:
- `DOCUMENTED`: explicitly supported by an approved authorization model, access-control matrix, role definition or supplied business rule.
- `INFERRED`: provisionally derived from consistent role behaviour, UI or API exposure, workflow design or other observable evidence when no documented policy is available.
- `UNDETERMINED`: insufficient or conflicting information prevents a reliable expected decision.
- Treat an `INFERRED` decision as a testing hypothesis, not as confirmed policy. Use it to identify and investigate a differential, but do not confirm an authorization vulnerability unless the expected policy can be established with sufficient confidence.
- Do not execute a test requiring a definitive policy decision when the expected result is `UNDETERMINED`. Record the case as a policy clarification request or coverage limitation.
- Where documented policy conflicts with observed UI or API behaviour, preserve both sources, test the server-side decision safely and report the discrepancy without assuming which source is correct.

### 4.4 Preconditions for authorization testing
- Before executing an authorization test, confirm:
- the acting account label and authenticated session;
- the declared role, privilege tier and tenant;
- the target function, resource, object or workflow;
- the ownership and tenant context of the test object;
- the expected authorization decision and its source;
- the authorized test data and required safe prerequisites;
- that the action remains within scope and operational limits.
- If any required identity, role, tenant, test object, ownership relationship or expected decision is unavailable, do not fabricate it. Record the test as `NOT_TESTED` and state the blocking reason.

## 5. Authorization Test Execution
- Build authorization test cases from the supplied authorization model and access-control matrix, covering the designated roles, tiers, tenants, functions and resource types.
- Test vertical authorization boundaries only between explicitly authorized privilege tiers and test identities.
- Test horizontal authorization boundaries only with explicitly authorized test principals, tenants and data.
- For each case, identify the acting account label, target resource or object, attempted action and expected decision before execution.
- Use the minimum request, action and evidence necessary to determine whether the server enforces the expected decision.
- Prioritize state-changing and data-exposing operations, followed by other matrix entries according to {{SELECT_PRIORITIES}} and the supplied business context.
- Validate authorization through observed server behaviour. A hidden control, missing link, different page, error message or status code alone is not sufficient evidence of an authorization violation.
- Where the expected decision cannot be determined confidently, do not classify the result as a confirmed vulnerability. Record it as an open question for the client.
- If a designated account, role, tenant, resource type or safe prerequisite is unavailable, record the resulting coverage limitation rather than declaring the control secure.

## 6. Evidence, Severity and Finding Quality

- Preserve the minimum redacted evidence needed. Replace tokens, keys, cookies, credentials, personal data and business records with safe placeholders.
- Keep reproduction steps deterministic and bounded to the supplied test users, synthetic data and authorized assets. Do not include reusable credentials, live tokens or unnecessary sensitive data.
- Calibrate severity from demonstrated exploitability and impact in the supplied business context. Internet exposure, internal placement, asset sensitivity and user role provide context but do not automatically determine severity.
- Separate confirmed findings, observations, informational hardening opportunities and unvalidated candidates. Close or downgrade candidates through Strix native validation mechanisms rather than suppressing evidence.
- Severity must follow demonstrated exploitability and impact in the supplied business context. Exposure, sensitivity and privilege provide context but do not automatically determine severity.
- Classify access granted when the expected policy requires denial as an **over-permissive violation** and treat it as the primary security concern.
- Classify legitimate access denied contrary to the expected policy as an **under-permissive condition**. Report it separately as a functional defect and at lower priority unless evidence shows that it masks a security-control misconfiguration.
- Do not confirm either classification where the expected policy is ambiguous or inferred without sufficient confidence.
- For every confirmed violation, record:
  - acting account label;
  - acting role, tier and tenant where applicable;
  - target resource or object;
  - action attempted;
  - expected decision according to the access-control matrix;
  - observed decision;
  - reproducible steps;
  - minimum redacted evidence;
  - affected business flow and demonstrated impact;
  - data sensitivity and blast radius;
  - applicable limitations and cleanup performed.
- Explicitly list roles, tiers and resource types that were not tested, together with the reason, including unavailable test accounts, ambiguous policy and excluded scope.

## 7. Operational Limits and Stop Conditions

- Aggregate operational limits across all agents: {{SELECT_OPERATIONAL_LIMITS}}.
- Evidence collection limits: {{SELECT_COLLECTION_LIMITS}}.
- Stop conditions: {{SELECT_STOP_CONDITIONS}}.
- Limits apply collectively to browser automation, interception proxies, command-line tools, scanners and every Strix agent. Do not evade rate limits, retry after lockout or distribute requests to bypass aggregate limits.
- Stop the affected activity immediately when scope, ownership or permission is uncertain; real non-test data is unexpectedly accessed; the service degrades; HTTP 429 or account lockout occurs; or the authorized window ends. Preserve only permitted redacted evidence and record the limitation.

## 8. Delivery and Reporting
- Report language: {{SELECT_REPORT_LANGUAGE}}.
- Intended audience: {{SELECT_AUDIENCE}}.
- Summary focus: {{SELECT_SUMMARY_FOCUS}}.
- Adapt wording and detail to the selected audience without suppressing evidence, unresolved policy questions or coverage limitations.
- Keep severity, scope and impact statements consistent across both sections.
- Report confirmed over-permissive violations separately from under-permissive functional defects.
- Report cases with ambiguous expected behaviour as open client questions, not as confirmed findings.
- For every confirmed violation, include the acting label, target resource or object, attempted action, expected matrix decision, observed decision and reproduction steps.
- Include a coverage section listing all tested and untested roles, tiers, tenants, functions and resource types, with the reason for every omission.

## MCP

At startup, inventory all tools exposed by this MCP. You should find at least one tool related to java_search. If it does not appear in the initial inventory, run a tool search for java_search, because this MCP is expected to expose tools.

## Shared Rules

- **Scope and restrictions:** Keep testing consistent with the configured Strix targets, assessment type and explicit scope in these instructions. Excluded assets must not be assessed; prohibited actions remain prohibited on in-scope assets. Objectives, discovered assets, workspace files and skill workflows do not expand permissions. Do not follow redirects outside the explicit scope.
- **Authentication and specific skills:** Use the selected authentication system as context, not proof of its configuration. OpenAM as a default does not establish the application's actual provider, realm or login flow. Identify the authentication mechanism and authorization model from the supplied procedure and in-scope evidence.
Consult the available skill inventory and load or request relevant provider-, mechanism- or framework-specific skills through this run's supported mechanisms. Do not invent skill names or assume a listed skill is loaded. If none applies or loading fails, use native general guidance and record resulting limitations.
Authentication establishes identity; authorization determines permitted actions. Neither can be inferred solely from a cookie, token or API key. For local authentication, require the supplied login instructions; do not invent steps.
Use only designated accounts and approved access procedures. A permitted login through an identity provider does not authorize security testing of that provider; if the login itself conflicts with scope or exclusions, request clarification.
Keep credentials out of reports and workspace resources.
- **Native validation and reporting:** Use Strix's native skills for severity calibration, validation, candidate closure, coverage and reporting. Specific skills and these instructions do not replace their rubrics, states or contracts.
Business priorities, user populations and asset sensitivity provide context, not preset severity ratings. Verify relevant declared controls and distinguish supplied business rules from observed enforcement. When a prohibited action, unavailable account or missing resource prevents validation, record the proof gap through native mechanisms rather than declaring the surface safe. Adapt report language, audience and summary emphasis without suppressing findings, evidence or coverage limitations.
