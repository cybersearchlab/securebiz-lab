# Security Remediation Plan & Evidence

This document records the security controls applied to SecureBiz-Lab during the
DevSecOps phase. It follows a fixed structure for each tool: Assessment,
Findings, Remediation, Post-Remediation Verification, and Limitations.

Tools covered: OWASP ZAP (DAST), Gitleaks (secret scanning), Trivy (IaC and
image scanning), Bandit (Python SAST), and pip-audit (dependency scanning).

---

## OWASP ZAP — Dynamic Application Security Testing

### Assessment
OWASP ZAP Baseline was used to perform passive security testing against the SecureBiz-Lab API.
- Target: `http://securebiz-api:8000`
- Assessment date: 15 November 2026
- Scan type: ZAP Baseline (passive scanning with minimal active checks)
- Evidence: Initial and post-remediation HTML and JSON reports.

### Initial findings
The initial scan, performed before the security headers middleware was introduced, reported:

| ZAP rule | Risk | Finding |
|---|---|---|
| 90004 | Low (Medium confidence) | Cross-Origin-Resource-Policy Header Missing or Invalid |
| 10021 | Low (Medium confidence) | X-Content-Type-Options Header Missing |
| 10049 | Informational (Medium confidence) | Storable and Cacheable Content |

The initial report contained three distinct alerts, with no FAIL-level alerts.

### Remediation
A security headers middleware was introduced in `app/main.py` to apply the following response headers:
- `X-Content-Type-Options: nosniff`
- `Cross-Origin-Resource-Policy: same-origin`
- `Cache-Control: no-store, no-cache, must-revalidate, private`
- `Pragma: no-cache`
- `Expires: 0`

### Post-remediation verification
The subsequent ZAP scan confirmed that both missing-header findings were resolved:
- Rule 10021: no longer reported.
- Rule 90004: no longer reported.
- Rule 10049: reported as **Non-Storable Content** (Informational, Medium confidence).

The remaining informational alert is the expected consequence of the `Cache-Control: no-store` policy. It is accepted rather than weakened, because preventing storage of sensitive API responses takes priority over satisfying this informational scanner rule.

### Limitations
ZAP Baseline is not a comprehensive penetration test. It does not establish the absence of exploitable SQL injection, cross-site scripting, authentication bypasses, or other vulnerabilities requiring deeper active or authenticated testing.

### Evidence files
- `docs/07-operations/zap-reports/zap-report.json`
- `docs/07-operations/zap-reports/zap-report-after.json`
- `docs/07-operations/zap-reports/README.md`

---

## Gitleaks — Secret Scanning (SAST)

### Assessment
Gitleaks was used to perform static analysis of the repository to detect hardcoded secrets.
- Tool: Gitleaks (Docker image `zricethezav/gitleaks:latest`)
- Target: Local repository (current working tree)
- Configuration: `.gitleaks.toml` (custom allowlist)

### Historical findings
During the initial development phase, Gitleaks was executed against the repository. It raised flags on files located in the `.venv/` directory (specifically license index files containing strings matching `generic-api-key`). After manual review, these were confirmed as **false positives** (Python library metadata, not actual secrets). The `.env` file, which contains sensitive environment variables, was correctly excluded from Git tracking via `.gitignore`.

### Remediation applied
A `.gitleaks.toml` configuration file was created to prevent future false positives and keep scans fast and clean. It includes an allowlist for:
- `.venv/` (local Python environment, library metadata)
- `.env` (local secrets, never committed)
- `docs/` and `CHANGELOG.md` (containing test UUIDs, not real secrets)

### Post-remediation verification
A fresh Gitleaks scan was executed against the current repository state using the custom configuration.
- Result: `INF no leaks found` (exit code 0)
- Scanned: ~1.01 MB in 713 ms

![Gitleaks scan showing no leaks found](docs/07-rapports/captures/gitleaks-clean.png)

### Limitations
This scan used `--no-git` (current working tree only). It confirms that no secrets are currently exposed in the tracked files, but it does not perform a full Git history scan. A history scan is recommended before open-sourcing the repository.

---

## Trivy — IaC and Image Configuration Scanning

### Assessment
Trivy was used to scan the Dockerfiles for misconfigurations, and the built Docker image for OS-level and Python-level vulnerabilities.
- Tool: Trivy v0.74.0
- Target: `Dockerfile`, `postgres/Dockerfile`, and `securebiz-lab-api:latest`
- Severity filter: HIGH, CRITICAL

### Findings

**1. IaC (Dockerfile) Misconfigurations:**
Two known findings were identified and justified as accepted for the lab environment:

| ID | File | Reason for acceptance |
|---|---|---|
| DS-0002 | `postgres/Dockerfile` | The official PostgreSQL entrypoint performs setup as root, then drops to UID 999 for the server. Runtime verification performed 2026-11-14. |
| DS-0013 | `postgres/Dockerfile` | Working-directory change is required to compile `pgsodium`. |

Both are documented with statements in `.trivyignore.yaml`.

**2. Docker Image Vulnerabilities:**
The image scan detected **47 HIGH-severity vulnerabilities** in the Debian 13.7 base OS layer (e.g. `util-linux`, `libacl1`, `libncursesw6`, `libsqlite3-0`, `libsystemd0`, `perl-base`). The Python application layer (site-packages) returned **0 vulnerabilities across all installed packages**, confirming that the pip, certifi, msgpack, setuptools, and urllib3 updates successfully resolved the application-level CVEs.

**No fixed version is available** in the Debian `trixie` repository for any of the 47 remaining CVEs. The Trivy report shows an empty "Fixed Version" column for every entry, and the `Status` field is either `affected` or `fix_deferred`.

### Remediation applied
- `.trivyignore.yaml` created with per-rule justifications and file scoping.
- Dockerfile updated to force-upgrade vulnerable Python dependencies (`pip`, `certifi`, `msgpack`, `setuptools`, `urllib3`) and run `pip check`.
- Dockerfile updated to run `apt-get update && apt-get upgrade -y` immediately after `FROM`, ensuring the image always incorporates the latest available Debian security patches at build time. This reduced the OS-level CVE count from 48 to 47; the remaining 47 are blocked on upstream Debian fixes.

### Post-remediation verification
- **IaC Scan:** `0` HIGH/CRITICAL misconfigurations remain. Exit code: 0.
- **Image Scan:** 47 HIGH CVEs remain, all in Debian OS packages with **no upstream patch available**.

![Trivy image scan showing 0 Python vulnerabilities and 47 Debian OS CVEs](docs/07-rapports/captures/trivy-image.png)

### Evidence files
- `docs/07-operations/trivy-image-report.json`

### Limitations
The 47 remaining CVEs cannot be resolved by changes to this repository. They require upstream Debian security updates to `trixie`. They will be automatically resolved on the next rebuild once Debian publishes the patched packages, because the Dockerfile already includes `apt-get upgrade`.

---

## Bandit — Python Static Analysis (SAST)

### Assessment
Bandit scans the Python source for common security anti-patterns.
- Tool: Bandit (running on Python 3.13.7)
- Target: `app/` and `scripts/`
- Output: JSON and text reports

### Findings
A total of **9 Low-severity issues** were identified. There were **0 Medium** and **0 High** severity issues.

| Rule | Location | Finding |
|---|---|---|
| B105 | `app/core/jwt.py:127` | Possible hardcoded password: `'access'` (False positive: this is the JWT `token_type` string). |
| B105 | `app/core/vault.py:239` | Possible hardcoded password: `'secret/data/securebiz/jwt'` (False positive: this is a Vault API path). |
| B105 | `scripts/provision_user.py:88` | Possible hardcoded password: `'db_password'` (False positive: this is a Vault JSON key name). |
| B105 | `scripts/set_provisioner_password.py:74` | Possible hardcoded password: `'db_password'` (False positive: Vault JSON key name). |
| B110 | `app/services/refresh.py` (x5) | Try, Except, Pass detected in database rollback logic. (Intentional safe-fail to prevent crashes during connection teardown). |

### Remediation applied
No code changes were required. The B105 findings are false positives triggered by keyword detection (e.g., identifying the word "access" as a password). The B110 findings represent intentional `try/except` blocks designed to safely close or roll back database connections without masking the primary exception.

### Post-remediation verification
The code was scanned and the 9 Low-severity findings were manually reviewed and accepted as safe.

### Evidence files
- `docs/07-operations/bandit-report.json`

---

## pip-audit — Dependency Vulnerability Scanning

### Assessment
pip-audit checks the installed Python dependency set against known vulnerability databases (OSV / PyPI advisory data).
- Tool: pip-audit
- Target: `requirements.txt`

### Findings
**No known vulnerabilities found.**

### Remediation applied
The Dockerfile was previously updated to pin and upgrade known vulnerable packages (`certifi`, `msgpack`, `setuptools`, `urllib3`).

### Post-remediation verification
pip-audit successfully parsed the dependency tree and confirmed that all pinned packages in `requirements.txt` are free of known CVEs.

![pip-audit scan showing no known vulnerabilities found](docs/07-rapports/captures/pip-audit-clean.png)

### Evidence files
- `docs/07-operations/pip-audit-report.json`

---

## Consolidated Residual Risks

1. **Trivy Image OS CVEs:** 47 HIGH-severity CVEs remain in the Debian 13.7 base image. The `Fixed Version` column is empty for every entry, and the `Status` field is `affected` or `fix_deferred`. These require upstream Debian patches to `trixie` and cannot be resolved within this repository. They will be automatically resolved on the next rebuild once Debian publishes the fixes, because the Dockerfile already runs `apt-get upgrade`.
2. **ZAP Baseline Scope:** ZAP Baseline is not a penetration test. No claim is made about SQL injection, XSS, auth bypass, or authenticated testing.
3. **Gitleaks History:** Only the working tree was scanned (`--no-git`). A full Git history scan is recommended before open-sourcing.
4. **Bandit False Positives:** The 9 Low-severity findings are accepted as safe, but remain flagged by the tool.
5. **Bandit Medium/High:** Zero Medium and zero High findings were detected, which is the desired state.