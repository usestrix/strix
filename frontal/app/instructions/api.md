# Security Testing Instructions: {{TEXT_PROJECT_NAME}}

## 1. Objectives and Priorities
- Investigation priorities, in order: {{SELECT_PRIORITIES}}.
- Specific questions, critical workflows and business rules: {{TEXT_QUESTIONS_AND_RULES}}.
- Specific authorization test cases: {{TEXT_AUTHORIZATION_TEST_CASES}}.

## 2. Project Context
- Application description, API description and main workflows: {{TEXT_APPLICATION_DESCRIPTION}}.
- API style or interface type: {{SELECT_API_TYPE}}.
  - `other` — another explicitly described API style: {{TEXT_OTHER_API_TYPE}}.
- User types: {{SELECT_USER_TYPES}}.
- Application deployment and access model: determine whether the application is external, internal or mixed from {{SELECT_INTERNET_EXPOSURE}} and the authorized targets. Do not infer exposure from DNS names, login pages or missing deployment evidence.
- Asset sensitivity: {{SELECT_ASSET_SENSITIVITY}}.
- Environments and lifecycle status, including development, test, staging, production, deprecated and shadow versions: {{TEXT_API_ENVIRONMENTS_AND_VERSIONS}}.
- Trust boundaries, upstream and downstream services, gateways and third-party integrations: {{TEXT_API_DEPENDENCIES}}.
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
- API contract or machine-readable definition: {{TEXT_API_DEFINITION}}. Supply the applicable artifact where available, such as OpenAPI/Swagger JSON or YAML for HTTP APIs, GraphQL SDL or introspection result, WSDL/XSD for SOAP, `.proto` descriptors for gRPC, or an equivalent message contract for WebSocket or custom interfaces.
- Valid-request corpus: {{TEXT_VALID_REQUESTS_JSON}}. Supply a sanitized JSON file or equivalent structured collection containing representative valid requests for each authorized operation, including method or operation name, path or target, required headers, parameters, body or message, expected role, expected successful response class and any required sequencing. Exclude reusable secrets and real sensitive records.
- Client collection and environment: {{TEXT_API_CLIENT_COLLECTION}}. Where available, supply an approved Postman/Bruno/Insomnia collection, cURL examples or equivalent, plus non-secret environment variables and base URLs.
- Endpoint and operation inventory: {{TEXT_ENDPOINT_INVENTORY}}. Identify active and deprecated versions, administrative operations, batch functions, asynchronous jobs, webhooks, callbacks and undocumented but authorized interfaces.
- Authentication and authorization design: {{TEXT_AUTHORIZATION_MODEL}}.
- Accounts, clients, roles and tenants, without secrets: {{TEXT_ACCOUNTS_AND_ROLES}}.
- Credential and token access procedure: {{TEXT_ACCESS_PROCEDURE}}.
- Authorized synthetic data, object identifiers and ownership: {{TEXT_TEST_DATA}}.
- Expected responses and error model: {{TEXT_EXPECTED_RESPONSES}}.
- Business-flow and sequencing rules: {{TEXT_API_WORKFLOWS}}.
- Traffic, quota and safety limits: {{SELECT_OPERATIONAL_LIMITS}}.
- Evidence handling and collection limits: {{SELECT_COLLECTION_LIMITS}}.
- Owner and escalation contacts, approved test window and stop authority: {{TEXT_ENGAGEMENT_CONTACTS}}.

## 5. API Security Test Execution
- Establish coverage against the OWASP API Security Top 10 2023 categories relevant to the selected objectives and observed surface:
  - `API1:2023` Broken Object Level Authorization.
  - `API2:2023` Broken Authentication.
  - `API3:2023` Broken Object Property Level Authorization.
  - `API4:2023` Unrestricted Resource Consumption.
  - `API5:2023` Broken Function Level Authorization.
  - `API6:2023` Unrestricted Access to Sensitive Business Flows.
  - `API7:2023` Server Side Request Forgery.
  - `API8:2023` Security Misconfiguration.
  - `API9:2023` Improper Inventory Management.
  - `API10:2023` Unsafe Consumption of APIs.
- OWASP API Top 10 references provide traceability and risk context; they do not prove that a category was tested or that a finding is confirmed.
- For black-box testing, begin with the supplied valid-request corpus and normal authorized workflows. Mutate one relevant element at a time and perform targeted, minimally invasive validation within operational limits.
- For white-box testing, trace authentication, authorization, object and property access, input validation, serialization, business rules, outbound requests, secrets, error handling, resource controls, logging, API inventory, gateway policies and reachable dependencies within the authorized source scope.
- For combined testing, use source and contract review to form hypotheses and live requests to validate observable impact. Distinguish contract evidence, source evidence, runtime evidence and unvalidated hypotheses.
- Apply type-specific analysis only to selected API types:
  - REST: validate methods, resource and object identifiers, parameters, content types, status handling, versioning, pagination, filtering and mass-assignment or excessive-data behaviours.
  - GraphQL: validate allowed queries, mutations and subscriptions; field- and object-level authorization; aliases, fragments, batching, depth and complexity controls; and schema exposure only where authorized.
  - SOAP: validate operation authorization, XML parsing and schema enforcement, message-level security, attachments and transport assumptions without invoking out-of-scope services.
  - gRPC: validate service and method authorization, metadata, message-field controls, streaming limits, reflection exposure and transport security only where selected and authorized.
  - WebSocket: validate handshake authentication, origin controls where applicable, channel or topic authorization, message schemas, state transitions and connection or message limits.
- Do not treat scanner output, schema differences, source patterns or version matches as confirmed vulnerabilities. Validate findings with reproducible evidence while respecting prohibited actions and stop conditions.
- Do not conduct denial-of-service, load, brute-force, credential-stuffing, destructive, bulk-extraction or real-world side-effect testing unless explicitly authorized; default prohibitions remain in force.

## 6. Evidence, Severity and Finding Quality

- Preserve the minimum redacted evidence needed. Replace tokens, keys, cookies, credentials, personal data and business records with safe placeholders.
- Keep reproduction steps deterministic and bounded to the supplied test users, synthetic data and authorized assets. Do not include reusable credentials, live tokens or unnecessary sensitive data.
- Calibrate severity from demonstrated exploitability and impact in the supplied business context. Internet exposure, internal placement, asset sensitivity and user role provide context but do not automatically determine severity.
- Separate confirmed findings, observations, informational hardening opportunities and unvalidated candidates. Close or downgrade candidates through Strix native validation mechanisms rather than suppressing evidence.
- Severity must follow demonstrated exploitability and impact in the supplied business context. Exposure, sensitivity and privilege provide context but do not automatically determine severity.
- For each validated finding, record: title; affected asset and workflow; assessment approach; tester role or unauthenticated state; preconditions; concise reproduction steps; observed result; expected secure behaviour; minimally sufficient redacted evidence; technical root cause when established; impact in the context of an external, internal or mixed application; affected users, roles or assets; applicable OWASP API Security Top 10 2023 reference; severity rationale; remediation; and validation limitations.

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
