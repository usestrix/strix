# Security Testing Instructions: {{TEXT_PROJECT_NAME}}

## 1. Objectives and Priorities
- Investigation priorities, in order: {{SELECT_PRIORITIES}}.
- Specific questions, critical workflows and business rules: {{TEXT_QUESTIONS_AND_RULES}}.
- Specific authorization test cases: {{TEXT_AUTHORIZATION_TEST_CASES}}.

Perform only differential authorization testing that adds coverage beyond Strix's standard web/API assessment. Compare observable authorization surfaces between supplied identities and validate discrepancies at route, input, and multi-step workflow level.

Do not repeat generic vulnerability discovery already performed by Strix, including broad endpoint discovery, ordinary IDOR/BOLA checks, generic broken function-level authorization, standard vertical/horizontal privilege escalation, anonymous-versus-authenticated checks, HTTP method tampering, mass assignment, JWT/session testing, injection testing, or general business-logic testing. Reuse existing Strix reconnaissance and traffic whenever available.

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

## Preconditions and required inputs
- Execute only against an explicitly authorized target and test tenants/accounts.
- Obtain at least two account labels:
  - `HIGH_PRIVILEGE`: the account with the broader expected permission set.
  - `LOW_PRIVILEGE`: the account with the narrower expected permission set.
- If available, also obtain two same-role accounts for ownership-bound comparisons, but do not run generic IDOR tests already covered by Strix.
- Load the engagement's authentication instructions and create a separate reusable authenticated session for every account.
- Keep cookies, tokens, browser state, proxy history, and derived artifacts strictly separated by account label.
- Obtain the expected role/permission model when documented. If it is unavailable, infer only a provisional model from observable behaviour and mark it as `INFERRED`.
- Reuse prior Strix reconnaissance results. Perform additional discovery only where needed to build a complete per-profile comparison.

## Differential coverage gate
Before executing a test, check Strix notes, findings, proxy history, and delegated-agent output.

Run a case only when all conditions are true:
1. It compares two profiles, two authorization states, or two stages of the same protected workflow.
2. The exact comparison has not already been executed with evidence.
3. The case targets a concrete authorization differential, not general application/API vulnerability discovery.
4. The expected result can be obtained from documented policy or a clearly labelled provisional model.

If the case is already covered, reference the existing evidence and skip execution.

## Phase 1: Build the HIGH_PRIVILEGE authorization baseline
Authenticate as `HIGH_PRIVILEGE` and create a normalized inventory from browser traffic, proxy history, application responses, downloaded client code, source maps when exposed, API descriptions when already available, and low-rate targeted content discovery limited to the authorised application.

Record every reachable feature as a baseline entry containing:
- canonical route or operation;
- HTTP method, GraphQL operation, RPC method, WebSocket message type, or equivalent transport action;
- route source: navigation, response link, client code, API description, observed request, or targeted discovery;
- input surface: path, query, body, header, cookie, multipart field, GraphQL variable, or message field;
- parameter name, type/shape, required/optional status, and security-relevant semantics;
- object ownership or tenant-binding fields, if present;
- prerequisite state;
- response status and stable response fingerprint;
- state change or side effect;
- workflow identifier and step number, if part of a multi-step process.

Normalize equivalent routes so volatile IDs, timestamps, pagination values, and cache-busting values do not create false differences.

### Multi-step workflow capture
For each privileged process requiring multiple requests, save a replayable state machine:
- workflow name and business purpose;
- ordered steps and transitions;
- prerequisite created objects or server-side state;
- per-step endpoint, method, parameters, tokens, nonces, and identifiers;
- which values are session-bound, user-bound, tenant-bound, object-bound, or single-use;
- expected allowed roles at each step;
- cancellation and rollback path;
- evidence proving whether each step changed server-side state.

Do not classify ordinary single-request CRUD operations as multi-step workflows.

## Phase 2: Build the LOW_PRIVILEGE authorization baseline
Authenticate independently as `LOW_PRIVILEGE`. Repeat the same inventory procedure, using the same normalization rules and comparable navigation depth.

Do not seed the low-privilege inventory solely from the high-privilege route list. First capture what the low-privilege profile exposes naturally; afterwards use the high-privilege baseline only for controlled differential probes.

Record low-privilege routes, operations, parameters, prerequisites, response fingerprints, and workflows in the same schema.

## Phase 3: Compute differential candidates
Create these comparison sets:
- `HIGH_ONLY_ROUTE`: present for `HIGH_PRIVILEGE`, absent from the natural `LOW_PRIVILEGE` surface.
- `SHARED_ROUTE_DIFFERENT_OPERATION`: same route or feature but different permitted methods, mutations, RPC actions, or message types.
- `SHARED_OPERATION_DIFFERENT_INPUT`: same operation but privileged-only parameters or accepted fields differ.
- `HIGH_ONLY_WORKFLOW`: workflow exposed only to `HIGH_PRIVILEGE`.
- `WORKFLOW_STEP_DIFFERENCE`: same workflow but role-specific steps, transitions, approvals, or completion actions differ.
- `RESPONSE_SCOPE_DIFFERENCE`: same operation returns a broader field set, object set, tenant scope, or export scope for one profile.

Exclude cosmetic UI differences unless they map to a server-enforced route, operation, parameter, response scope, or workflow transition.

## Phase 4: Execute only differential authorization probes

### A. High-only routes and operations
For each `HIGH_ONLY_ROUTE` or `SHARED_ROUTE_DIFFERENT_OPERATION`:
1. Replay the minimal high-privilege request unchanged in structure but under the isolated low-privilege session.
2. Replace account-bound or tenant-bound test-object references only with safe objects created for the low-privilege account where required to distinguish missing prerequisites from missing authorization.
3. Compare status, response body fingerprint, returned data scope, side effects, and resulting server state.
4. Treat redirects, generic success pages, queued jobs, asynchronous acknowledgements, and HTTP `200` responses as inconclusive until the resulting state is verified.

Confirm a violation only if the low-privilege identity completes a server-side action or receives data that the expected model denies.

### B. Differential parameter acceptance
For each `SHARED_OPERATION_DIFFERENT_INPUT`:
1. Establish the low-privilege request accepted by the server.
2. Add one privileged-only parameter or field at a time, preserving the low-privilege session.
3. Test both explicit privileged values and structurally valid neutral values.
4. Verify whether the server ignores, rejects, stores, acts on, or later exposes the supplied field.
5. Check nested objects, arrays, duplicate keys, alternative content types, GraphQL variables, and server-side defaults only when they concern the identified privileged-only field.

Do not perform broad mass-assignment discovery. Restrict testing to parameters proven to differ between the two profile inventories.

### C. Multi-step workflow boundary testing
For each `HIGH_ONLY_WORKFLOW` or `WORKFLOW_STEP_DIFFERENCE`, use safe test objects and test the following differential conditions:
- Start the privileged workflow as `LOW_PRIVILEGE`.
- Invoke an intermediate step without completing the initial step.
- Invoke the final step without completing earlier mandatory steps.
- Skip approval, review, confirmation, payment, ownership-verification, or entitlement-establishment steps when present.
- Reorder two adjacent protected steps.
- Replay a valid intermediate or final request after cancellation, completion, downgrade, or logout where the application is expected to invalidate it.
- Start with `HIGH_PRIVILEGE`, then continue an intermediate or final step with `LOW_PRIVILEGE` using only the minimum transferred workflow reference necessary for the comparison.
- Start with `LOW_PRIVILEGE`, then attempt to reach a privileged continuation or completion transition directly.
- Reuse a workflow reference across authorised test tenants only when both tenants are in scope and isolated test data is used.

For every probe, verify server-side state before and after. A hidden button, inaccessible page, client-side error, or different response code alone is not proof.

### D. Authorization change propagation
Run only when role downgrade, permission removal, account deactivation, group removal, or tenant reassignment can be performed safely with test identities.

Compare authorization before and after the change across:
- the existing browser session;
- existing API tokens;
- refreshed tokens;
- a newly authenticated session;
- in-progress privileged workflows;
- queued or background operations already created by the identity.

Record the exact control-plane change and observable enforcement point. Report continued access only when policy requires immediate revocation or the accepted revocation delay has elapsed. If timing policy is unknown, report the result as an open question rather than a confirmed vulnerability.

### E. Cross-transport enforcement drift
Run only for a feature observed through more than one transport, such as UI-backed REST, GraphQL, RPC, WebSocket, mobile API, or background job submission.

Compare the same subject-action-resource decision across transports using both profiles. Report only inconsistent server-side authorization enforcement. Do not repeat generic transport or endpoint discovery.

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

Finish only when:
- both profile baselines use the same normalization and comparable coverage;
- all differential candidate sets have been triaged;
- every executed case has an expected decision and evidence;
- duplicate/default Strix tests are explicitly skipped rather than rerun;
- all safe test-state changes are cleaned up;
- the final report separates confirmed security violations, functional denials, policy gaps, duplicates, and untested coverage.

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

Maintain a differential matrix with one row per canonical operation:
- feature/workflow;
- canonical route or operation;
- parameters or step;
- `HIGH_PRIVILEGE` observed decision;
- `LOW_PRIVILEGE` observed decision;
- expected decision and source (`DOCUMENTED` or `INFERRED`);
- test status;
- evidence references;
- security impact.

For every confirmed issue, include:
- acting account label and expected privilege tier;
- target resource, owner, tenant, and workflow state;
- exact differential that generated the candidate;
- minimal sanitized requests and relevant responses;
- expected and observed server decisions;
- proof of returned data or server-side state change;
- prerequisites and reproducible steps;
- whether the case is route-, operation-, parameter-, workflow-, revocation-, or transport-specific;
- blast radius and affected role combinations;
- cleanup performed.

List all untested profiles, routes, parameters, workflows, and transitions with the blocking reason. Keep ambiguous expected behaviour out of confirmed findings.

### Decision rules
Classify outcomes as:
- `CONFIRMED_OVER_PERMISSIVE`: access or action succeeded contrary to documented policy.
- `CONFIRMED_UNDER_PERMISSIVE`: expected legitimate access was denied; report separately as a functional authorization defect.
- `POTENTIAL_POLICY_GAP`: profiles differ, but expected access is undocumented or ambiguous.
- `NOT_EXPLOITABLE`: response differed but no unauthorised data or state change occurred.
- `DUPLICATE_SKIPPED`: Strix already executed the equivalent case with sufficient evidence.
- `NOT_TESTED`: blocked by missing account, prerequisite, safe test data, scope, or operational limit.

Do not infer authorization failure from status codes alone. Prefer verified data disclosure, durable state change, or successful protected transition.

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
