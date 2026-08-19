---
name: payment_gateways
description: Payment integration security testing covering webhook signature validation, amount/currency manipulation, idempotency and race abuse, refunds, and client-side trust
---

# Payment Gateways

Payment integrations (Stripe, PayPal, Braintree, Adyen, Square, Razorpay, etc.) are where business logic meets money, and the classic bugs are beautifully simple: a webhook that trusts unsigned events, an amount read from the client, an idempotency key that can be replayed, or a race that double-spends a coupon. These are usually integration bugs rather than gateway bugs - the gateway itself is fine, but the app's trust decisions around it are not.

## Attack Surface

- Webhook endpoints: `/webhooks/stripe`, `/paypal/webhook`, `/api/payments/hooks` - every payment event a merchant app consumes
- Checkout/payment APIs: create-intent, confirm, capture, authorize, refund, dispute/chargeback handlers
- Client-side pricing: amounts, currencies, quantities, tax, coupon codes computed or trusted in the browser
- Idempotency: keys for intents/orders, retry semantics, webhook dedup
- Order/transaction state machines: pending -> paid -> fulfilled transitions and their triggers
- Refunds/disputes: who can trigger them, can they exceed the charge, can they be replayed
- Subscriptions/renewals: proration, cancellation timing, upgrade/downgrade math
- Discounts/referrals/rewards: stacking, negative amounts, repeated application
- Wallet/balance features: credits, points, gift cards, escrow

## Reconnaissance

1. **Map the money flows** - checkout, webhook, refund, subscription; record the exact API calls and events for each (proxy/agent-browser + caido)
2. **Fingerprint the gateway stack** from headers, endpoints, SDK version strings, and webhook paths
3. **Capture a real webhook event** - trigger a small payment/refund and intercept the callback; note headers (`Stripe-Signature`, `PayPal-Transmission-*`, `Braintree-Signature`), body schema, and how the app validates
4. **Document idempotency semantics** - which keys exist, how the app dedups, and what happens on replay
5. **Source-aware**: grep for `construct_event`, `verify_signature`, `Webhook`, `webhook_secret`, `amount`, `currency`, `idempotency`, `refund`, `chargeback`

## Key Vulnerabilities

### Missing/Weak Webhook Signature Validation

**Stripe**: the `Stripe-Signature` header is `t=<timestamp>,v1=<hmac>`, where the HMAC-SHA256 is over `<timestamp>.<raw_body>` with the webhook secret. Test:

- Replay a captured event with the signature stripped - accepted?
- Replay with a *different* timestamp and recomputed signature from a body you control (requires the secret, so first hunt for secret leaks)
- Tolerance window: does the app check `t` against the current time? A wide/absent window allows old-event replay
- Raw-body handling: if the app parses the body before verification (JSON re-serialization), signature checks fail closed for everyone - but if the app verifies a *stringified* body or skips verification on parse errors, forging becomes possible

**PayPal**: webhook headers `PayPal-Transmission-Id`, `PayPal-Transmission-Time`, `PayPal-Transmission-Sig`, `PayPal-Cert-Url`, `PayPal-Auth-Algo`; verification requires fetching the cert URL + CRC32 of the body. Common failures: cert URL not validated (SSRF), signature verification skipped, webhook ID not checked.

**Braintree**: `Braintree-Signature` + `Braintree-Payload` (HMAC-SHA256 hex); apps often verify with a stale/leaked key or skip the check.

**Adyen**: `Adyen-Signature` HMAC over specific fields with a configured key.

For every gateway: if signature verification is missing or bypassable, an attacker can forge `payment_intent.succeeded`, `payment.sale.completed`, `checkout.session.completed`, or refund events and trigger fulfillment without paying.

### Amount/Currency Manipulation

- Amount taken from client request (body/param) instead of the gateway's payment intent
- Integer vs decimal confusion: Stripe uses minor units (cents) - `1.5` vs `150`, negative amounts, `-1` refunds, huge values
- Currency mismatch: pay in a cheap currency, fulfillment priced in another; `amount_currency` not validated against the intent
- Quantity/price math: client-supplied unit price, tax, or discount applied server-side without revalidation
- Gift card/credit flows: applying credits after a discount, negative balances, fractional credits

### Idempotency Key Abuse

- Reusing an idempotency key for a different amount -> gateway returns the *original* result (if key collision is possible per-account)
- Webhook replay without dedup: the same `payment_intent.succeeded` delivered twice (attacker resends the raw HTTP request) -> double fulfillment, double credits, double reward
- Retry loops: app-level retries re-trigger side effects (email, inventory, credits)

### Race Conditions

- Concurrent webhooks + balance reads: `balance = balance - amount` read-then-write races allow overspend (see `race_conditions`)
- Concurrent coupon application or wallet top-up -> double discount / double credit
- Checkout race: two sessions capturing the same discount code or limited stock
- Refund race: refund initiated while capture in flight -> negative balance / double refund

### Refund/Dispute Abuse

- Refund endpoint callable by users with arbitrary amounts (refund more than charged, refund others' transactions)
- Refund events trusted to re-credit balances without verifying the original charge
- Dispute handler that credits without evidence, or dispute events forgeable via weak webhook validation
- Chargeback/refund replay -> repeated credits

### Client-Side Trust

- Amounts, currency, or plan IDs stored in hidden form fields / JS state and trusted on the server
- Price fields editable in the browser before submission
- Coupon codes applied client-side with server only receiving the discounted total
- Client-generated payment-intent amounts that the server never cross-checks against the cart

## Advanced Techniques

- **Webhook secret hunt**: secrets in `.env`, source, logs, admin panels, or client-side bundles; then forge a full event signature
- **Event-type confusion**: some apps switch on `event.type` but ignore `livemode`/`data.object` status; test `payment_intent.succeeded` vs `payment_intent.payment_failed` handlers for missing state checks
- **Currency/format fuzz**: `amount=0`, `amount=-1`, `amount=1e9`, float `1.005`, string `"150"`, extra precision - diff the app's response
- **Two-account differential**: the same coupon/idempotency key/cart across two accounts often behaves differently
- **Clock manipulation**: test time-window checks in subscription/coupon logic by manipulating `created_at` in requests (if trusted)

## Testing Methodology

1. Map flows and capture real webhook events + signatures
2. Replay events: unmodified (dedup?), signature stripped, stale timestamp
3. Test amount/currency validation across create/confirm/capture/refund
4. Fuzz idempotency keys and retry behavior
5. Run concurrency tests on credits/balance/coupon flows
6. Audit refund/dispute authorization (who can call, for what amounts)
7. Hunt webhook secrets in configs/source/logs

## Validation

1. Webhook: show an accepted forged/replayed event and its server-side effect (credits added, order fulfilled) with exact request/response pairs
2. Amount: create an order at a manipulated price and show the server accepted it
3. Race: demonstrate double credit/fulfillment with concurrent requests (repeatable, not a one-off)
4. Refund: unauthorized refund succeeds (two-account proof)
5. Keep proofs non-destructive: use sandbox/test mode, tiny amounts, or reversible credits

## False Positives

- Webhook rejects forged signatures (verification working) - no finding
- Amount validated against the gateway intent server-side (client price ignored)
- Idempotency key collisions blocked by per-key/per-account binding
- Race attempts produce no observable double-effect (server serializes correctly)
- Refund endpoint requires admin/role checks and ownership validation
- Sandbox/test-mode events accepted but production livemode enforced (`livemode:false` rejected or flagged)

## Impact

- Free goods/services via forged payment events or amount manipulation
- Direct financial loss via refund abuse and double credits
- Data exposure of payment/PII data in logs and responses
- Reputation/regulatory fallout (PCI, chargebacks, fraud)

## Pro Tips

1. Webhook signature validation is the #1 payment bug - replay stripped/stale/forged events first
2. Always test in test mode with tiny amounts; financial validation should never be destructive
3. Capture a real signed webhook to learn the exact validation flow and body shape
4. Check `livemode`/state fields in event handlers, not just event type
5. Pair with `race_conditions`, `business_logic`, `information_disclosure`, and `weak_password_detection` skills

## Summary

Payment flaws are trust-boundary bugs: the app trusts unsigned webhooks, client prices, weak idempotency, or unguarded refunds. Capture real events, replay and forge them, revalidate amounts server-side, race the money paths, and prove each with minimal, reversible impact.
