---
name: edge-cases
description: Edge case testing for caching races, partial failures, boundary conditions, and eventual consistency exploitation
category: vulnerabilities
tags: [caching, race-condition, partial-failure, edge-case]
cwe: 362
---

# Edge Cases

Edge case vulnerabilities arise at system boundaries: cache coherence gaps, partial failure states, retry storms, and consistency windows between distributed components. These bugs rarely appear in unit tests and require adversarial timing, ordering, and failure injection to surface.

## Attack Surface

**Caching Layers**
- CDN / reverse proxy (Cloudflare, Fastly, Varnish, nginx)
- Application cache (Redis, Memcached, in-process)
- Database query cache
- DNS cache and TTL manipulation
- Browser and service worker caches

**Distributed State**
- Eventual consistency windows between replicas
- Cross-region replication lag
- Message queue delivery guarantees (at-least-once, at-most-once)
- Saga/compensation patterns in microservices

**Failure Boundaries**
- Partial success in multi-step operations
- Timeout and retry behavior
- Circuit breaker states (closed, open, half-open)
- Graceful degradation and fallback paths

**Boundary Conditions**
- Integer overflow/underflow at limits
- Pagination cursors at collection boundaries
- Time zone transitions, DST, leap seconds
- Unicode normalization and encoding edge cases

## High-Value Targets

- Authenticated CDN content served from shared cache without identity keys
- Payment flows with partial capture/refund states
- Inventory systems with reservation and release logic
- Session stores with replication lag between regions
- Rate limiters using distributed counters
- Background job queues with retry and dead-letter handling
- Search indexes with delayed consistency from primary stores

## Reconnaissance

### Cache Behavior Mapping

- Identify caching headers: Cache-Control, Vary, ETag, Age, X-Cache, X-Cache-Hit, CF-Cache-Status
- Determine cache key composition: what headers, cookies, and query parameters are included
- Test Vary header completeness: does it include Authorization, Cookie, Accept-Language?
- Check for cache partitioning: do authenticated and unauthenticated requests share cache entries?
- Map TTL values and revalidation behavior (stale-while-revalidate, stale-if-error)

### Consistency Model Discovery

- Identify which data stores use eventual consistency vs strong consistency
- Map replication topology: primary/replica, multi-region, active-active
- Determine read-after-write guarantees per endpoint
- Check if reads are pinned to the write region or load-balanced across replicas
- Look for consistency-related headers or query parameters (consistency=strong, read_preference)

### Failure Mode Enumeration

- Identify multi-step operations and their atomicity guarantees
- Map retry policies: fixed, exponential backoff, jitter, max attempts
- Check for idempotency key support and scope
- Identify circuit breaker implementations and their state thresholds
- Look for graceful degradation paths that weaken security controls

## Key Vulnerabilities

### Cache Poisoning Races

- **TOCTOU on CDN**: Inject a poisoned response (e.g., admin=true, elevated role) into the cache during the window between authentication check and response caching; subsequent users receive the poisoned cached response
- **Cache key confusion**: Exploit differences in how the cache and origin parse URLs, headers, or query parameters to serve one user's cached response to another
- **Vary header omission**: Origin returns user-specific content but Vary header does not include Authorization or Cookie; CDN caches and serves across identities
- **Web cache deception**: Trick caching layer into storing authenticated response at a public path (e.g., /account/profile.css) by appending cacheable extensions
- **Cache parameter cloaking**: Use unkeyed query parameters, headers, or cookies to influence response content while the cache key remains identical
- **Host header poisoning**: Inject alternate Host header values to generate cached responses with attacker-controlled links or redirects
- **Response splitting**: Inject headers that cause the cache to store a crafted response for a different URL

### Partial Failure Exploitation

- **Half-committed transactions**: In multi-service workflows (payment + inventory + notification), one service commits while another fails; exploit the inconsistent state before compensation runs
- **Orphaned resources**: Failed creation leaves allocated resources (IDs, reservations, storage objects) that can be claimed or referenced
- **Retry amplification**: Trigger timeouts to force retries that cause duplicate side effects (double charges, double credits, duplicate emails)
- **Compensation race**: Execute the compensation/rollback path before the original operation completes, leaving the system in a state that allows both the original action and its reversal to succeed
- **Dead letter exploitation**: Messages in dead-letter queues may be reprocessed with stale context, outdated authorization, or bypassed validation
- **Partial batch results**: Batch operations returning mixed success/failure per item; exploit items that succeeded before the batch was rolled back

### Eventual Consistency Windows

- **Read-your-writes violation**: Write to primary (e.g., revoke permission), immediately read from replica that has not replicated yet; stale read allows continued access
- **Cross-region stale reads**: In multi-region deployments, act in a lagging region before a security-critical write propagates (role revocation, account disable, password change)
- **Search index lag**: Item deleted or access revoked but still discoverable and accessible via search or listing endpoints backed by a delayed index
- **Counter drift**: Distributed rate limit counters or quota trackers that diverge across nodes; burst requests across multiple nodes before counters converge

### Boundary Condition Abuse

- **Integer boundaries**: Quantity, price, or balance fields at INT_MAX/INT_MIN; overflow to negative or zero
- **Pagination edge cases**: Cursor-based pagination allowing access to items beyond authorization scope when cursor encodes raw IDs; off-by-one at page boundaries exposing extra records
- **Time boundary exploitation**: Exploit midnight UTC rollovers, DST transitions, or month-end boundaries where time-based access controls, quotas, or rate limits reset
- **Encoding differentials**: Unicode normalization (NFC vs NFD), case folding, and homoglyph abuse causing different systems to interpret the same identifier differently (e.g., user lookup vs permission check)
- **Floating point boundaries**: Currency calculations at precision limits producing rounding errors that accumulate across transactions
- **Empty and null states**: Empty arrays, null values, missing fields, and zero-length strings bypassing validation that only checks for presence

### Graceful Degradation Weaknesses

- **Fallback path bypass**: When a dependency (auth service, rate limiter, WAF) is unavailable, the fallback allows requests through without full validation
- **Circuit breaker open state**: While the circuit breaker is open, requests may be routed to a degraded path that skips authorization or logging
- **Feature flag defaults**: Feature flags defaulting to enabled when the flag service is unreachable, exposing gated functionality
- **Cache stampede**: Force cache expiry on a hot key; the thundering herd of requests to the origin may overwhelm the backend and trigger degraded responses

### Stale State and Revocation Gaps

- **Token revocation lag**: Access tokens remain valid until expiry even after revocation event; long-lived tokens with no revocation check
- **Permission cache staleness**: Role or permission changes not reflected until cache TTL expires; act within the stale window
- **DNS rebinding**: Manipulate DNS TTL to point a validated hostname to an internal IP after the initial security check

## Bypass Techniques

- Timing manipulation: slow down requests (large payloads, keep-alive abuse) to widen race windows
- Regional routing: target specific regions or replicas known to lag behind the primary
- Header injection to influence cache behavior (X-Forwarded-Host, X-Original-URL)
- Trigger dependency failures (connection exhaustion, timeout injection) to force degraded paths
- Replay stale pagination cursors or continuation tokens after access revocation

## Testing Methodology

1. **Map caching layers** - Identify all caches (CDN, app, DB), their key composition, TTLs, and Vary headers
2. **Test cache isolation** - Verify authenticated content is not served cross-user; strip cookies, swap tokens, check ETags
3. **Probe consistency** - Write then immediately read from different paths/regions; measure replication lag
4. **Inject failures** - Simulate partial failures in multi-step operations; check for orphaned or inconsistent state
5. **Test boundaries** - Exercise integer limits, pagination edges, time boundaries, and encoding variants
6. **Force degradation** - Exhaust dependencies to trigger fallback paths; verify security controls remain enforced
7. **Measure revocation** - Change permissions/roles and measure how long stale access persists across all layers

## Validation

1. Show cross-user cache serving: two different authenticated users receiving each other's cached responses
2. Demonstrate partial failure leaving exploitable state (e.g., payment captured but order not created, allowing re-order)
3. Prove stale read after security-critical write (permission revocation still allowing access via replica)
4. Show boundary condition causing invariant violation (integer overflow, pagination leak, time-boundary quota reset)
5. Demonstrate degraded path bypassing security control that is enforced in the normal path
6. All findings must show durable state change or information disclosure, not just transient anomalies

## False Positives

- Intentional stale-while-revalidate behavior documented in architecture with acceptable staleness window
- Eventual consistency windows within documented SLA that do not affect security-critical state
- Cache serving public content (truly non-personalized) to multiple users as designed
- Graceful degradation with explicit fail-closed behavior on security-critical paths
- Pagination showing slightly stale counts due to known replica lag without access control implications

## Impact

- Cross-user data exposure via cache poisoning or confusion
- Financial loss from partial failure exploitation (double-spend, orphaned charges)
- Unauthorized access during consistency windows after revocation events
- Denial of service via cache stampede or retry storm amplification
- Policy bypass when security controls degrade under failure conditions

## Pro Tips

1. Cache bugs are most impactful on CDNs; start by mapping cache key composition and Vary headers
2. For consistency bugs, identify the replication topology first; then target the lagging component
3. Partial failures are easiest to trigger in payment and inventory flows; these have the highest business impact
4. Test revocation effectiveness by measuring the actual window between revocation and enforcement
5. Degrade one dependency at a time and check if security controls still hold
6. Integer boundary bugs are often in quantity, price, and balance fields; try MAX_INT, 0, -1, and overflow values
7. Time-boundary bugs cluster around midnight UTC, month-end, and DST transitions
8. Cache deception works best when the origin and CDN disagree on what constitutes a static resource
9. Use correlation IDs and timestamps in all test requests to prove ordering and causality
10. Document the exact timing window required to reproduce; edge cases must be repeatable to be actionable

## Summary

Edge cases exploit the gaps between components that each work correctly in isolation but fail under adversarial timing, ordering, or partial failure. Security must hold at every cache boundary, consistency window, failure mode, and numeric limit in the system.
