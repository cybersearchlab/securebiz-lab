# ZAP DAST Reports

This directory contains the OWASP ZAP baseline scan reports for the SecureBiz Lab API.

## Files

- `zap-report.html`: human-readable report (open in a browser).
- `zap-report.json`: machine-readable report (for parsing).

## Scan details

- Tool: OWASP ZAP (zap-baseline.py)
- Image: ghcr.io/zaproxy/zaproxy:stable
- Target: http://securebiz-api:8000 (Docker network `securebiz-lab_default`)
- Date: 2026-11-15
- Result: FAIL-NEW: 0, WARN-NEW: 3, PASS: 65

## Findings (before security headers middleware)

| Rule | Risk | Confidence | Description |
|---|---|---|---|
| 10021 | Low | Medium | X-Content-Type-Options Header Missing |
| 90004 | Low | Medium | Cross-Origin-Resource-Policy Header Missing or Invalid |
| 10049 | Informational | Medium | Storable and Cacheable Content |

None of these findings are HIGH or CRITICAL. No FAIL-level alert was detected.

These findings will be addressed by a security headers middleware in `app/main.py`. The middleware has not yet been tested; this README will be updated after the re-scan.

## Reproducing the scan

From the repository root, with the API running:

    docker run --rm --network securebiz-lab_default -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://securebiz-api:8000 -r zap-report.html -J zap-report.json

## Limitations

- ZAP baseline is a passive + minimal-active scan. It does not attempt full exploitation (e.g., SQL injection, XSS with payloads).
- For a full assessment before production, run zap-full-scan.py or an authenticated scan.