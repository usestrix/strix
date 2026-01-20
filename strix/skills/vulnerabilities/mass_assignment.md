# MASS ASSIGNMENT

## Critical

Mass assignment binds client-supplied fields directly into models/DTOs without field-level allowlists. It commonly leads to privilege escalation, ownership changes, and unauthorized state transitions in modern APIs and GraphQL.

## Scope

- REST/JSON, GraphQL inputs, form-encoded and multipart bodies
- Model binding in controllers/resolvers; ORM create/update helpers
- Writable nested relations, sparse/patch updates, bulk endpoints

## Methodology

1. Identify create/update endpoints and GraphQL mutations. Capture full server responses to observe returned fields.
2. Build a candidate list of sensitive attributes per resource: role/isAdmin/permissions, ownerId/accountId/tenantId, status/state, plan/price, limits/quotas, feature flags, verification flags, balance/credits.
3. Inject candidates alongside legitimate updates across transports and encodings; compare before/after state and diffs across roles.
4. Repeat with nested objects, arrays, and alternative shapes (dot/bracket notation, duplicate keys) and in batch operations.

## Discovery Techniques

### Surface Map

- Controllers with automatic binding (e.g., request.json → model); GraphQL input types mirroring models; admin/staff tools exposed via API
- OpenAPI/GraphQL schemas: uncover hidden fields or enums; SDKs often reveal writable fields
- Client bundles and mobile apps: inspect forms and mutation payloads for field names

### Parameter Strategies

- Flat fields: isAdmin, role, roles[], permissions[], status, plan, tier, premium, verified, emailVerified
- Ownership/tenancy: userId, ownerId, accountId, organizationId, tenantId, workspaceId
- Limits/quotas: usageLimit, seatCount, maxProjects, creditBalance
- Feature flags/gates: features, flags, betaAccess, allowImpersonation
- Billing: price, amount, currency, prorate, nextInvoice, trialEnd

### Shape Variants

- Alternate shapes: arrays vs scalars; nested JSON; objects under unexpected keys
- Dot/bracket paths: profile.role, profile[role], settings[roles][]
- Duplicate keys and precedence: {"role":"user","role":"admin"}
- Sparse/patch formats: JSON Patch/JSON Merge Patch; try adding forbidden paths or replacing protected fields

### Encodings And Channels

- Content-types: application/json, application/x-www-form-urlencoded, multipart/form-data, text/plain (JSON via server coercion)
- GraphQL: add suspicious fields to input objects; overfetch response to detect changes
- Batch/bulk: arrays of objects; verify per-item allowlists not skipped

### Exploitation Techniques

#### Privilege Escalation

- Set role/isAdmin/permissions during signup/profile update; toggle admin/staff flags where exposed

#### Ownership Takeover

- Change ownerId/accountId/tenantId to seize resources; move objects across users/tenants

#### Feature Gate Bypass

- Enable premium/beta/feature flags via flags/features fields; raise limits/seatCount/quotas

#### Billing And Entitlements

- Modify plan/price/prorate/trialEnd or creditBalance; bypass server recomputation

#### Nested And Relation Writes

- Writable nested serializers or ORM relations allow creating or linking related objects beyond caller’s scope (e.g., attach to another user’s org)

#### Advanced Techniques

##### GraphQL Specific

- Field-level authz missing on input types: attempt forbidden fields in mutation inputs; combine with aliasing/batching to compare effects
- Use fragments to overfetch changed fields immediately after mutation

##### Orm Framework Edges

- Rails: strong parameters misconfig or deep nesting via accepts_nested_attributes_for
- Laravel: $fillable/$guarded misuses; guarded=[] opens all; casts mutating hidden fields
- Django REST Framework: writable nested serializer, read_only/extra_kwargs gaps, partial updates
- Mongoose/Prisma: schema paths not filtered; select:false doesn’t prevent writes; upsert defaults

##### Parser And Validator Gaps

- Validators run post-bind and do not cover extra fields; unknown fields silently dropped in response but persisted underneath
- Inconsistent allowlists between mobile/web/gateway; alt encodings bypass validation pipeline

##### Bypass Techniques

###### Content Type Switching

- Switch JSON ↔ form-encoded ↔ multipart ↔ text/plain; some code paths only validate one

###### Key Path Variants

- Dot/bracket/object re-shaping to reach nested fields through different binders

###### Batch Paths

- Per-item checks skipped in bulk operations; insert a single malicious object within a large batch

###### Race And Reorder

- Race two updates: first sets forbidden field, second normalizes; final state may retain forbidden change

###### Validation

1. Show a minimal request where adding a sensitive field changes persisted state for a non-privileged caller.
2. Provide before/after evidence (response body, subsequent GET, or GraphQL query) proving the forbidden attribute value.
3. Demonstrate consistency across at least two encodings or channels.
4. For nested/bulk, show that protected fields are written within child objects or array elements.
5. Quantify impact (e.g., role flip, cross-tenant move, quota increase) and reproducibility.

###### False Positives

- Server recomputes derived fields (plan/price/role) ignoring client input
- Fields marked read-only and enforced consistently across encodings
- Only UI-side changes with no persisted effect

###### Impact

- Privilege escalation and admin feature access
- Cross-tenant or cross-account resource takeover
- Financial/billing manipulation and quota abuse
- Policy/approval bypass by toggling verification or status flags

###### Pro Tips

1. Build a sensitive-field dictionary per resource and fuzz systematically.
2. Always try alternate shapes and encodings; many validators are shape/CT-specific.
3. For GraphQL, diff the resource immediately after mutation; effects are often visible even if the mutation returns filtered fields.
4. Inspect SDKs/mobile apps for hidden field names and nested write examples.
5. Prefer minimal PoCs that prove durable state changes; avoid UI-only effects.

###### Mitigations

- Enforce server-side allowlists per operation and role; deny unknown fields by default
- Separate input DTOs from domain models; map explicitly
- Recompute derived fields (role/plan/owner) from trusted context; ignore client values
- Lock nested writes to owned resources; validate foreign keys against caller scope
- For GraphQL, use input types that expose only permitted fields and enforce resolver-level checks

###### Remember

Mass assignment is eliminated by explicit mapping and per-field authorization. Treat every client-supplied attribute—especially nested or batch inputs—as untrusted until validated against an allowlist and caller scope.
