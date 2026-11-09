# API-Guard: Current Plan (read this first)

Last updated 2026-11-09. Planning context for any agent picking up work on this repo.

## What it is
A deterministic API **authorization** scanner. It logs in as several test identities, creates real data as one user, then probes it as another, and confirms leaks by diffing response bodies. Today it detects **BOLA (OWASP API1)** only, and only against the bundled demo target.

## Product decisions (settled)
- **Shape:** self-hosted **CLI** is the core. A **GitHub Action** wraps the CLI (runs in the user's CI, scans their API started there or a staging URL). The existing React **dashboard** is the visual layer over the same results. **No hosted web app** for now (abuse risk, credential storage, sandboxing).
- **Positioning:** best-in-class multi-identity authorization testing, not a generic ZAP/Burp replacement. No injection scanning.
- **Principles:** scanner stays deterministic (no LLM decides a finding); safe by default (allowlisted hosts, mutations off, request budget); honest benchmark numbers.

## Published package
- PyPI: **`apiguard-cli`** 0.1.0 (Apache-2.0). Command `apiguard`, import `apiguard`.
- Package source: `backend/apiguard/` (renamed from `backend/app/`). Build config: `pyproject.toml` at repo root. Bundled demo profiles: `backend/apiguard/targets/`.
- `apiguard`/`api-guard` names are blocked on PyPI by an abandoned 2019 package. Every new release needs a version bump (PyPI files are immutable).
- Windows Smart App Control blocks pip's unsigned `apiguard.exe`; use `python -m apiguard.engine.cli scan` until `__main__.py` exists.

## Build order (six steps)
1. **Configurable target + auth profiles**: scan any API from a YAML profile. *(next)*
2. **BFLA (API5)**: normal user calls admin-only operations; reuse Setup -> Control -> Probe with an admin identity.
3. **BOPLA (API3)**: mass assignment (send `role`, `owner_id`, `is_admin`) and excessive data exposure (diff returned fields).
4. **Broken authentication (API2)**: replay with no token, expired token, tampered JWT (`alg: none`).
5. **Passive misconfiguration (API8) + inventory (API9)** checks on traffic already sent.
6. **GitHub Action + SARIF export** + PR comment; exit code fails the build on a confirmed finding.

Later: SSRF (needs a callback listener). Skipped: API4 load testing, API6, API10.

## Step 1: what is still hardcoded (verified in code)
- `engine/cli.py`: always calls `reset_db()` + `update_target_config(...)` (mutates the demo); in-process ASGI fallback to the demo app; health check on `/api/health`; `SafeExecutor(allowed_hosts={"127.0.0.1","localhost"}, total_budget=30)`; identities named `user_a`/`user_b`; no meaningful exit code.
- `engine/target.py`: `load_operations` silently falls back to the demo spec when `spec_path` is missing.
- `engine/auth.py`: login response keys `token` and `user_id` are hardcoded; no `${ENV}` secret expansion.
- `engine/inference.py`: `resource_type="Project"`, `owner_field="owner_id"`.
- `engine/planner.py`: create body `{"name": "Audit Benchmark Project", ...}`.
- `engine/scanner.py`: `resource_name` defaults to `"projects"`.

## Task prompts (run in order, one per session)

**Prompt 0: Windows-safe entry point (small, optional)**
> Add `backend/apiguard/__main__.py` so `python -m apiguard scan ...` runs `apiguard.engine.cli:main`. Update the README "Command line" section to show it as the Windows alternative. Run `pytest backend/tests`. Change nothing else.

**Prompt 1: CLI scans any API safely**
> Make `apiguard scan --profile <file.yaml>` work against a real API. Extend `TargetProfile` (don't replace it).
> 1. Run `reset_db()`/`update_target_config()` only for the bundled demo profile.
> 2. Use the in-process ASGI fallback only for the demo; otherwise exit with a clear error if unreachable.
> 3. Drop the `/api/health` check for non-demo profiles.
> 4. Add `allowed_hosts: list[str]` and `request_budget: int = 30` to `TargetProfile`; refuse to scan if `base_url`'s host is not allowed. Loopback allowed by default; never allow-all by default.
> 5. Add `owner`/`attacker` identity names (default `user_a`/`user_b`); fail clearly if missing.
> 6. Exit codes: 0 no findings, 1 confirmed findings, 2 config/connection error.
> 7. Missing `spec_path` errors clearly (demo fallback only for the demo).
> 8. `LoginConfig.token_path` / `user_id_path` (dotted, reuse `get_path`), defaults `token`/`user_id`.
> 9. Expand `${ENV_VAR}` in profile strings at load; error if unset.
> 10. Commented example profile at `backend/apiguard/targets/example.yaml`.
> Tests: a second non-demo FastAPI target ("orders", owner field `customer_id`, login returns `{"access_token", "uid"}`, deliberate BOLA on `GET /orders/{order_id}`) served on a real localhost socket like `test_integration.py`; assert the BOLA is found. Also test: disallowed host refused, missing `${VAR}` errors, exit codes 0/1/2. Existing tests must pass. Scanner stays deterministic; no frontend changes. Update README Known Limitations item 1.

*Status: Prompts 0 and 1 done (32 tests pass). Review found the issues fixed by Prompt 1b.*

**Prompt 1b: fix issues found in review of Prompt 1** (before Prompt 2)
> 1. **False all-clear (critical):** `TargetProfile.from_yaml` marks any file named `demo.yaml` as the demo. A user's own `demo.yaml` with an unreachable server and missing spec silently scans the bundled in-process demo and exits 0 ("0 CONFIRMED VULNERABILITIES"). Mark `is_demo` only when the resolved path equals the bundled `backend/apiguard/targets/demo.yaml` (compare resolved paths); never by file name. Drop `is_demo` as a user-settable YAML field. Add a test: a user `demo.yaml` in a temp dir with an unreachable `base_url` must exit 2.
> 2. **Dry run sends requests:** `--dry-run` prints "ZERO REQUESTS SENT" but `authenticate_all()` still POSTs logins. For dry runs skip login and build placeholder identities from the profile (name, role, identity_id), so a dry run sends nothing. Test it with a target on an unused port: dry run exits 0.
> 3. **Verifier keyword list:** `verifier.py SENSITIVE_KEY_SUBSTRINGS` only confirms leaks in fields whose names contain words like "budget"/"customer" ("customer" was added to make the orders test pass). Real APIs leaking `phone`, `address`, `salary` would be missed. Add optional `sensitive_fields: list[str]` per resource in `ResourceOverride` (extra substrings merged with the defaults) and document it in `example.yaml`. Remove "customer" from the global defaults and set it in the orders test profile instead. Keep the default list otherwise unchanged so the demo results don't move.
> 4. Remove `"testserver"` from the default `allowed_hosts` (loopback only); set it explicitly where tests need it.
> All tests must pass; benchmark numbers in README must not change.

**Prompt 2: remove demo assumptions in the engine** (after Prompt 1b passes)
> Derive resource type and owner field in `inference.py` from the graph and an optional `owner_field` on `ResourceOverride` (default `owner_id`). In `planner.py` use the profile body override, else `build_body_from_schema` (follow `scanner.py`). Remove the `"projects"` default in `scanner.py` and skip resources with no producer. Extend the "orders" test target to prove a non-Project resource with a non-`owner_id` field is detected. All tests pass; don't change remediation templates or the frontend.

## Other references
- `README.md`: architecture, benchmarks, known limitations.
- `docs/ROADMAP.md`: long-range feature detail by phase.
- `graphify-out/GRAPH_REPORT.md`: code knowledge graph (core classes: `GraphGuidedScanner`, `OpenAPIParser`, `ResourceGraph`, `SafeExecutor`).
- Tests: `python -m pytest backend/tests` (27 passing as of 0.1.0).
