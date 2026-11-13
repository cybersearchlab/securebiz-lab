# Priority 9 — Test Coverage and state_check Extension: Validation Report

> Document status: v0.5.1 — 2026-11-13
> Commits: 1cf9ac2, 5a47261, dd4be83, 986f913, dc022c0

## 1. Objective

Complete Priority 9:
- Add unit tests for JWT, refresh, auth routes, provisioning.
- Extend state_check.py to cover auth_session, get_user_status,
  credentials, provisioner role.
- Execute isolation tests in the container.

## 2. Test files added

| File | Tests | Location | Result |
|---|---|---|---|
| test_jwt.py | 38 | Host | 38/38 |
| test_refresh.py | 31 | Host | 31/31 |
| test_auth_routes.py | 18 | Host | 18/18 |
| test_provision_user.py | 11 | Host | 11/11 |
| test_isolation.py | 4 | Container | 4/4 |
| conftest.py | — | Host | n/a |

Total: 102 tests (98 host + 4 container).

## 3. state_check.py v4

- 10 checks (was 6).
- 16 records (5 env + 11 DB/Vault).
- All OK, 0 FAIL, 0 WARN.
- Exit code: 0.

## 4. Key findings

- Vault Ed25519 key regenerated on container restart (dev mode inmem).
  Manual resync: `ccc071be...` → `757147f3...`.
- `tests/test_isolation.py` requires container (VAULT_ADDR, db:5432).
- `conftest.py` must set VAULT_TOKEN before vault.py import.

## 5. Known limitations

- Mocked DB tests do not validate PostgreSQL concurrency, RLS, constraints.
- `state_check.py` read-only except `check_full_flow` (install + rollback).
- `EXPECTED_PUBKEY_HEX` removed; dynamic read used.

## 6. References

- Commits: 1cf9ac2, 5a47261, dd4be83, 986f913, dc022c0.
- `docs/08-handover/handover.md` v14.2.