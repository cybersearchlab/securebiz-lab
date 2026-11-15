# ZAP DAST Reports

This directory contains the OWASP ZAP baseline scan reports for the SecureBiz Lab API,
**before** and **after** the security headers middleware was added.

## Files

- `zap-report.html` / `zap-report.json`: initial scan (before middleware).
- `zap-report-after.html` / `zap-report-after.json`: re-scan (after middleware).
- `README.md`: this file.

## Scan details

### Initial scan (before middleware)

- Target: http://securebiz-api:8000 (Docker network `securebiz-lab_default`)
- Date: 2026-11-15
- Result: FAIL-NEW: 0, WARN-NEW: 3, PASS: 65

| Rule | Risk | Confidence | Description |
|---|---|---|---|
| 10021 | Low | Medium | X-Content-Type-Options Header Missing |
| 90004 | Low | Medium | Cross-Origin-Resource-Policy Header Missing or Invalid |
| 10049 | Informational | Medium | Storable and Cacheable Content |

### Re-scan (after middleware)

- Target: http://securebiz-api:8000
- Date: 2026-11-15
- Result: FAIL-NEW: 0, WARN-NEW: 1, PASS: 67

| Rule | Risk | Confidence | Description |
|---|---|---|---|
| 10049 | Informational | Medium | Non-Storable Content |

## Resolution

The security headers middleware in `app/main.py` adds the following headers
to HTTP responses:

    X-Content-Type-Options: nosniff
    Cross-Origin-Resource-Policy: same-origin
    Cache-Control: no-store, no-cache, must-revalidate, private
    Pragma: no-cache
    Expires: 0

Observed behavior:

- The five headers are present on `/`, `/health` (HTTP 200) and on `/robots.txt`,
  `/sitemap.xml` (HTTP 404), verified with `curl -D -`.
- Responses in the 5xx class are expected to be covered by the same middleware
  by construction (the middleware calls `call_next` before adding headers, so any
  response produced by the application or by an exception handler goes through it).
  The 5xx path has not been exercised end-to-end in this audit and is not claimed
  as verified.
- 2 of the 3 initial ZAP alerts were resolved:
  * [10021] X-Content-Type-Options Header Missing -> PASS.
  * [90004] Cross-Origin-Resource-Policy Header Missing -> PASS.
- The 3rd alert, [10049], is informational and has changed direction:
  * Before: "Storable and Cacheable Content" (the response could be cached).
  * After:  "Non-Storable Content" (the response is not cacheable, because of `no-store`).
  This is not a new vulnerability. It is the expected consequence of the
  `Cache-Control: no-store` policy.

## Remaining finding

**10049 Non-Storable Content** (Informational, Medium confidence) is accepted.

The `no-store` policy is the correct choice for an API that handles JWTs,
session cookies, and multi-tenant data. Performance is a secondary concern
in this lab context. No cache directive was relaxed to satisfy the scanner.

If future work requires caching on specific non-sensitive routes, a conditional
middleware should be introduced (e.g., `no-store` on `/auth/*` and `/users/*`,
`public, max-age=60` on `/health` and `/`). This is out of scope for the current
audit and would require a separate review.

## Reproducing the scan

From the repository root, with the API running:

    docker run --rm --network securebiz-lab_default -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://securebiz-api:8000 -r zap-report.html -J zap-report.json

## Limitations

- ZAP baseline is a passive + minimal-active scan. It does not attempt full exploitation
  (e.g., SQL injection, XSS with payloads).
- For a full assessment before production, run `zap-full-scan.py` or an authenticated scan.
- No FAIL-level alert was detected in either scan.