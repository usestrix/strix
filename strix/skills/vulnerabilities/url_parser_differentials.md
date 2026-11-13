---
name: url-parser-differentials
description: URL parser differential testing for redirects, callbacks, allowlists, signed URLs, routing, and server-side fetches
---

# URL Parser Differentials

A URL may look safe to a validator but mean something different to its final consumer. Test redirects, callbacks, server-side fetches, signed URLs, proxies, and routers when decoding, normalization, reconstruction, or reparsing happens after a security decision.

## Core Principle

Follow the same value from input to effect:

```text
request bytes -> application value -> validator interpretation
              -> emitted URL -> final consumer interpretation
```

Start with a working allowed URL and a rejected external URL. Record actual request bytes, application value, validator result, emitted URL, and final destination. Unintended client encoding invalidates the comparison.

## Bounded Compound Matrix

Use a controlled receiver and the real allowlisted URL. Generate this matrix exactly; it makes `@`, `#`, `?`, `/`, or `\` structural at different decoding depths.

```python
from itertools import product
from urllib.parse import quote, unquote


def enc(value, depth):
    for _ in range(depth):
        value = quote(value, safe="")
    return value


def url_diff_rows(receiver_origin, allowlisted_uri):
    assert "://" in receiver_origin and "://" in allowlisted_uri
    tail = allowlisted_uri.split("://", 1)[1]
    rows = []
    for left, right, ld, rd in product(("#", "?", "/", "\\"), ("@",), range(3), range(3)):
        application_value = receiver_origin + enc(left, ld) + enc(right, rd) + tail
        raw_query_value = quote(application_value, safe="")
        assert unquote(raw_query_value) == application_value
        rows.append((left, right, ld, rd, application_value, raw_query_value))
    assert len(rows) == len({row[:4] for row in rows}) == 36
    return rows
```

`application_value` is what the application should receive. Give it to clients that serialize parameters. When constructing a raw query, use `raw_query_value`. Do not encode both ways or collapse these representations.

Do not replace the bounded matrix with random mutations or hostname enumeration. Do not close this class until all 36 candidates were observed on the wire and every accepted candidate was checked by the real late consumer.

## Execution and Closure

1. Map each component that receives, validates, rebuilds, or consumes the URL.
2. Run the baseline, rejected control, and all 36 rows. Verify every row in captured traffic.
3. Record intended value, wire bytes, framework value when observable, validation result, and emitted URL.
4. Pass every accepted output to the real browser, fetcher, webhook client, proxy, or router.
5. Prove permitted impact through authorized code redemption, delivery, fetch, signed action, or route access.

A valid finding shows exact request bytes, both interpretations, the security-relevant destination change, and paired controls. For browsers, record the final address and receiver evidence; fragments are not sent in HTTP requests. For OAuth, redeem the authorized synthetic code. For SSRF, prove the server-side destination.

Different decoding alone is not a finding. Rule it out when every layer reaches the same security-relevant origin and path, the client created the difference, or no sensitive data or protected action crosses the boundary. If the late consumer is unavailable, record the missing evidence instead of marking the class safe.

## Reporting

Report the smallest transformation chain, depth coverage, late-consumer result, and proven impact. Do not name a parser without source or version evidence.

Use authorized receivers and synthetic data. Keep testing bounded; resource-exhaustion and oversized-input probes require separate authorization.
