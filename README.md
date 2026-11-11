# APIGuard: API Authorization Scanner

Logs in as two users and proves whether one can reach the other's data, from your laptop or on every pull request.

<p align="center">
  <a href="https://pypi.org/project/apiguard-cli/"><img src="https://img.shields.io/pypi/v/apiguard-cli.svg?style=flat-square&color=blue" alt="PyPI version"></a>
  <a href="https://github.com/marketplace/actions/apiguard-ci-security-scanner"><img src="https://img.shields.io/badge/Marketplace-APIGuard-blueviolet?style=flat-square&logo=github" alt="GitHub Marketplace"></a>
  <a href="https://github.com/Soul-Ninja/APIGuard/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Soul-Ninja/APIGuard/ci.yml?branch=main&style=flat-square&label=CI" alt="CI Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License Apache-2.0"></a>
  <a href="https://soul-ninja.github.io/APIGuard/"><img src="https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-10b981?style=flat-square&logo=githubpages&logoColor=white" alt="Live Demo"></a>
  <a href="https://owasp.org/API-Security/editions/2023/en/0x11-t10/"><img src="https://img.shields.io/badge/OWASP-API%20Top%2010%202023-red.svg?style=flat-square" alt="OWASP API Top 10 2023"></a>
</p>

---

## 🎯 What It Finds

| Category | OWASP | What It Checks | Demo Target Example |
|---|:---:|---|---|
| **BOLA / IDOR** | API1:2023 | One user accesses another user's private object | `GET /projects/{id}/export` leaks victim's confidential billing data |
| **BOPLA** | API3:2023 | Mass assignment stores unauthorized properties; excessive exposure leaks hidden fields | `POST /projects` accepts injected `role="admin"`; `GET /projects/{id}` returns undocumented `password_hash` |
| **BFLA** | API5:2023 | A normal user executes an administrative function | `GET /admin/users` returns user roster without checking admin role |
| **Broken Auth** | API2:2023 | Endpoint accepts requests with missing, garbage, or tampered tokens | `GET /projects/{id}/summary` returns `200 OK` with no token or an `alg:none` JWT |
| **Misconfiguration & Inventory** | API8 / API9 | Passive analysis (0 extra requests) catches CORS wildcards, stack traces, version disclosures | `Access-Control-Allow-Origin: *` with credentials, Python traceback on `/summary`, `X-Powered-By: DemoAPI/1.4.2` |

---

## ⚡ Quick Start

### Path A: Try It Now (Built-In Vulnerable Target)

No setup or external target needed. Scans the bundled demo API in-process:

```bash
pip install apiguard-cli
python -m apiguard scan --showcase
```

> **Windows Note:** Run `python -m apiguard` instead of `apiguard` if Windows Smart App Control or your shell environment restricts direct `.exe` shim execution.

### Path B: Scan Your Own API

1. Create a minimal configuration profile (`apiguard.yaml`):

```yaml
base_url: "http://127.0.0.1:8000"
spec_path: "openapi.json"

login:
  path: "/auth/login"
  body_template:
    username: "{username}"
    password: "{password}"

identities:
  - name: "user_a"
    username: "alice@example.com"
    password: "${USER_A_PASSWORD}"
  - name: "user_b"
    username: "bob@example.com"
    password: "${USER_B_PASSWORD}"
```

2. Run the audit:

```bash
python -m apiguard scan --profile apiguard.yaml
```

Add `--mutations` to enable mutating tests (`PATCH`, `DELETE`), or `--dry-run` to inspect the planned sequence with zero requests sent.

---

## 🤖 GitHub Action

Run graph-guided authorization scans on every pull request with the official composite action:

```yaml
name: API Security Scan
on: [pull_request]

permissions:
  contents: read
  security-events: write      # Required to upload SARIF to GitHub Code Scanning
  pull-requests: write        # Required to post / update the PR comment summary

jobs:
  apiguard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start API
        run: |
          python -m uvicorn myapi.main:app --host 127.0.0.1 --port 8000 &
          sleep 3

      - name: Run APIGuard
        uses: Soul-Ninja/APIGuard@v1
        with:
          profile: "apiguard.yaml"
          fail-on: "high"
        env:
          USER_A_PASSWORD: ${{ secrets.USER_A_PASSWORD }}
          USER_B_PASSWORD: ${{ secrets.USER_B_PASSWORD }}
```

**What you get:**
1. **Failing check:** Exits with code 1 if confirmed vulnerabilities meet or exceed `--fail-on high`, preventing unauthorized data access from merging.
2. **SARIF alerts in Security > Code scanning:** Pinpointed to the exact path in your OpenAPI spec with persistent fingerprints that prevent alert churn across commits.
3. **One PR comment:** An idempotently updated markdown summary table with category counts, reproduction cURLs, and coverage metrics.

---

## 💡 Why It's Different

- **Two-Identity Differential Proof:** An issue is marked `CONFIRMED` only when the owner's genuine data appears in the attacker's response payload. `200 OK` alone is never enough: soft-200 error pages, empty collections, and shape mismatches are downgraded to `POTENTIAL` (exit code 0) so your build never breaks on false alarms.
- **Resource Dependency Graph:** Ingests standard OpenAPI 3.x specifications to build a Directed Acyclic Graph (DAG) connecting producers to consumers (`POST /projects` creates `{id}` $\to$ consumed by `GET /projects/{id}/export`). By propagating ownership rules along DAG edges, APIGuard reaches nested routes where isolated scanners fail—achieving **100% recall on indirect Defect B** where the baseline scored **0%**.
- **Safe by Default:** Enforces a strict loopback host allowlist (`127.0.0.1`, `localhost`), a hard request budget cap, locks mutating verbs behind `--mutations`, and masks all credentials and tokens with `<USER_A_TOKEN>`, `<USER_B_TOKEN>`, or `<ADMIN_TOKEN>` placeholders.

---

## 📊 Measured Benchmark Results

Every metric below was measured by running both scanners against the bundled demo target API (`http://127.0.0.1:8000/target`); requests are delivered in-process, and the integration tests run the same scanners over real sockets. Ground truth is loaded from `benchmarks/manifests/*.json` (never accessed by scanners during execution). The numbers come straight from [`benchmarks/results.json`](benchmarks/results.json).

| Test Variant | Target Description | Ground Truth | Baseline Recall | Baseline Reqs | APIGuard Recall | APIGuard Reqs | Avg ms / finding |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Variant A** | Direct BOLA on primary route (`GET /projects/{id}`) | 1 | 100% (1/1) | 7 | **100% (1/1)** | 15 | 16.6 ms |
| **Variant B** | Indirect BOLA on export (`GET /projects/{id}/export`) | 1 | **0% (0/1)** | 7 | **100% (1/1)** | 15 | 16.1 ms |
| **Variant C** | Mutation BOLA on update (`PATCH /projects/{id}`) | 1 | 100% (1/1) | 7 | **100% (1/1)** | 15 | 14.2 ms |
| **Variant All** | Compound multi-defect scenario (A + B + C) | 3 | 67% (2/3) | 7 | **100% (3/3)** | 19 | 7.2 ms |
| **Variant Secure** | Fully patched target + verifier traps | 0 | n/a (0 FP) | 7 | **n/a (0 FP)** | 13 | n/a |
| **Variant BFLA** | Function-level privilege escalation (`GET /admin/users`) | 1 | **0% (0/1)** | 7 | **100% (1/1)** | 15 | 14.3 ms |
| **Variant BOPLA** | Property-level violations (mass assignment & exposure) | 2 | **0% (0/2)** | 7 | **100% (2/2)** | 17 | 9.7 ms |
| **Variant AUTH** | Broken authentication (`GET /projects/{id}/summary`) | 1 | **0% (0/1)** | 7 | **100% (1/1)** | 21 | 17.2 ms |
| **Variant MISCONFIG** | Security misconfiguration (CORS, traceback, version disclosure) | 3 | **0% (0/3)** | 7 | **100% (3/3)** | 13 | 5.1 ms |

> **Note on Hygiene & Passive Findings:** In `Variant MISCONFIG`, APIGuard confirms 100% (3/3) of the ground-truth misconfigurations and also reports hygiene findings (missing `X-Content-Type-Options: nosniff`, missing `no-store` `Cache-Control` on authenticated sensitive data, and undocumented HTTP status codes) with **zero extra network requests**. Hygiene findings are listed under `not_scored` in the variant manifest, so they are printed but excluded from recall and precision. Passive findings are reported as CONFIRMED (observed facts) with exit code 0 by default; use `--fail-on low` or `--fail-on medium` to enforce them in CI/CD gates.

### 🔬 Controlled Ablation Study

- **Graph Scanner with Propagation OFF:** the scanner stops after the main read route and never tests the nested routes, so it misses the indirect defect (**0% recall**, 0 of 1, 6 requests).
- **Oracle Baseline (Hand-Tagged Rules on Every Route):** Matches APIGuard at 100% recall (9 requests vs 15), but requires a human to write a security rule for every route in advance.

**How to read these numbers:**
- The target and the answer key are ours, showing the method works on a controlled case rather than real-world accuracy across arbitrary targets.
- APIGuard sends **more** requests than the rules-only baseline (15 vs 7 on single-defect variants) because it autonomously maps and tests the nested routes.
- "Avg ms / finding" is total scan time divided by findings, not time to the first finding.

---

## 🌐 Dashboard & Live Hosted Demo

👉 **[Launch APIGuard Live Demo (GitHub Pages)](https://soul-ninja.github.io/APIGuard/)**

Try APIGuard directly in your browser with zero installation:
- ⚡ **Interactive Dependency DAG:** Explore operation and resource dependencies with Dagre auto-layout.
- 🎯 **Real-Time Audit Replay:** Click **"RUN EXECUTION AUDIT"** to watch live SSE event propagation and node transitions.
- 🧪 **Showcase Mode:** Click **"Showcase: all 5 checks"** in the toolbar to activate BOLA, BFLA, BOPLA, AUTH, and MISCONFIG simultaneously.
- 🔍 **Differential Inspector:** Inspect leaked victim attributes side-by-side with reproduction cURL commands.
- 📄 **Executive Audit Report Export:** Download formatted Markdown (`.md`) or printable HTML pentest reports.
- 📊 **Empirical Benchmark Panel:** Review measured recall, precision, and ablation comparison tables.

> **Note:** The hosted demo replays genuine engine runs recorded by [`scripts/record_demo.py`](scripts/record_demo.py). Custom OpenAPI schema ingestion and live model calls require running the engine locally.

### Demo Screenshots

| Screen | Description |
|---|---|
| ![Graph Idle](docs/screenshots/01_graph_idle.png) | **React Flow DAG:** Operation and Identifier nodes with Dagre auto-layout, under the pixel-art banner. |
| ![Dry Run Preview](docs/screenshots/02_dry_run_table.png) | **Dry-Run Mode:** Planned multi-identity sequence table without sending any traffic. |
| ![Live SSE Scan](docs/screenshots/05_graph_after_scan.png) | **Real-Time Audit:** Streaming console, live SSE event propagation, and red vulnerability badges. |
| ![Differential Finding Detail](docs/screenshots/06_finding_detail.png) | **Differential Inspector:** Multi-category response diffs, leaked fields, and sanitized repro cURLs. |
| ![Empirical Benchmarks](docs/screenshots/03_benchmark_panel.png) | **Benchmark & Ablations:** 100% recall vs 0% baseline on Defect B, with ablation proofs. |
| ![AI Remediation](docs/screenshots/07_ai_remediation.png) | **AI Remediation Engine:** Side-by-side $v_1$ vs $v_2$ prompt iteration and pytest test suite. |
| ![Target Patched & Re-scanned](docs/screenshots/09_after_fix_secure.png) | **Automated Fix Verification:** After reference patch is applied, re-scan proves 0 confirmed leaks and green nodes. |

---

## 🛠️ System Architecture & Technology Stack

```
                     ┌──────────────────────────────────────────────┐
                     │           React Flow + Vite UI               │
                     │  (Dagre DAG, Live SSE Console, Diff View)    │
                     └──────────────────────┬───────────────────────┘
                                            │ REST / SSE Stream
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             APIGuard Backend Engine                              │
│                                                                                  │
│   ┌─────────────────────┐   ┌─────────────────────┐   ┌──────────────────────┐   │
│   │   OpenAPI Parser    ├──►│ Resource Graph DAG  ├──►│  Policy & Confidence │   │
│   │ (openapi-validator) │   │ (Nodes, Typed Edges)│   │  (Heuristic Scoring) │   │
│   └─────────────────────┘   └──────────┬──────────┘   └──────────▲───────────┘   │
│                                        │                         │               │
│                                        ▼                         │               │
│   ┌─────────────────────┐   ┌─────────────────────┐   ┌──────────┴───────────┐   │
│   │ Safe HTTP Executor  │◄──┤     TestPlanner     │◄──┤  Inference Engine    │   │
│   │ (Budget, Allowlist) │   │ (Setup/Ctrl/Probe)  │   │ (DAG Rule Propagate) │   │
│   └──────────┬──────────┘   └─────────────────────┘   └──────────────────────┘   │
│              │ HTTP calls                                                        │
└──────────────┼───────────────────────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                       Vulnerable Multi-Tenant Target API                         │
│                    (Seed data, Trap endpoints, /auth/login)                      │
│                                                                                  │
│    Defect A (BOLA Read)           Defect B (BOLA Export)   Defect C (BOLA Patch) │
│    Defect BFLA (Admin Check)      Defect BOPLA (Inject)    Defect Auth (Tamper)  │
│    Defect Misconfig (CORS/Error)  Patched Mode (Reference Remediation)          │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Technologies Used
- **Backend Scanner:** Python 3.12, FastAPI, Pydantic v2, `aiosqlite` (WAL-mode SQLite), `openapi-spec-validator`, `httpx` (async ASGI/HTTP client), `pytest`, `pytest-asyncio`.
- **Frontend Dashboard:** React 19, Vite, TypeScript, Tailwind CSS v4, `@xyflow/react` (React Flow), `dagre` (graph layout), `lucide-react`, Press Start 2P and VT323 pixel fonts.
- **AI Remediation:** LLM via OpenRouter or Gemini (whichever is configured), with SQLite caching and automatic deterministic offline template fallback.

---

## ⚖️ Safety & Architectural Guarantees

| Category | Status | Details |
|---|:---:|---|
| **Real Engine Execution** | **Real** | Real HTTP requests handled by the real target application. Delivered in-process (ASGI) in benchmarks and dashboard, and over real sockets in integration tests and CLI. |
| **Deterministic Scanner** | **100% Real** | The scanner engine makes **zero LLM calls**. Graph traversal, policy evaluation, and differential verification are completely deterministic. |
| **AI Remediation Engine** | **Supported / Offline Fallback** | LLM via OpenRouter or Gemini is used strictly for post-scan patch drafting ($v_1 \to v_2$). If no API key is provided, an offline deterministic template is badged. |
| **Safe by Default** | **Working** | Requests are strictly restricted to allowlisted loopback hosts (`127.0.0.1`, `localhost`). Mutating requests (`PATCH`/`DELETE`) are blocked unless explicitly toggled with `--mutations`. |
| **Git Commit History** | **Verified** | Clean, incremental commit history with 98 unit and integration tests passing at every stage. |

---

## 📑 Report Formats & CI Options

APIGuard produces three machine-readable and developer-friendly audit report formats:

1. **JSON Report (`--json PATH`):** Full audit dump containing tool version, target `base_url`, aggregate finding summaries (by category, status, and severity), complete OpenAPI coverage statistics (including skipped operations and reasons), and serialized findings.
2. **SARIF 2.1.0 Report (`--sarif PATH`):** Official OASIS SARIF 2.1.0 format compatible with **GitHub Code Scanning**, GitLab, and Azure DevOps. Maps rules to OWASP API Top 10 tags, reports strict `security-severity` scores (`9.5` Critical to `1.0` Info), pinpoints spec file locations, and computes persistent partial fingerprints (`apiguardFindingKey/v1`).
3. **Pull Request Markdown Summary (`--markdown PATH`):** Structured summary table starting with `<!-- apiguard-report -->` for idempotently updating existing PR comments. Includes status verdict, category counts, reproduction cURLs, and coverage metrics.

### Build Failure Thresholds (`--fail-on`)

The `--fail-on` flag controls CI exit codes based on finding severities:

| `--fail-on` Value | Description | Exit Code 1 Trigger Condition |
|:--- |:--- |:---|
| *(absent)* | Default APIGuard policy | Any `CONFIRMED` active vulnerability (`BOLA`, `BFLA`, `BOPLA`, or `AUTH`). Passive hygiene findings alone exit `0`. |
| `critical` | Critical-only gate | Any `CONFIRMED` finding of any category with severity `CRITICAL`. |
| `high` | Standard CI gate | Any `CONFIRMED` finding of any category with severity `CRITICAL` or `HIGH`. |
| `medium` | Strict posture | Any `CONFIRMED` finding with severity $\ge$ `MEDIUM` (e.g., active leaks, CORS with credentials, verbose errors). |
| `low` | Full hygiene gate | Any `CONFIRMED` finding with severity $\ge$ `LOW` (including missing headers, version disclosures, and cache policies). |
| `info` | Total enforcement | Any `CONFIRMED` finding including `INFO` (undocumented status codes). |
| `none` | Audit mode | Never exits with code `1` (always `0` upon successful scan completion). |

> **Notes on Exit Codes:**
> - `POTENTIAL` findings (`Needs review`) never trigger build failure (`exit 1`) regardless of `--fail-on`.
> - Configuration or target connection errors exit with code `2`. When exit code `2` occurs, no partial report files are written.

---

## 🎨 Design: Paper & Grace

The dashboard uses a light pixel theme: cream paper with a faint grid, chunky black pixel type with a lime shadow, and gold and moss accents. All the scenery (ruins, a resting knight, a golden tree, a thin golden ring) lives in the banner at the top, so the working panels stay plain and easy to read. The chevron in the toolbar hides the banner to give the panels more room (the choice is remembered; the banner starts open).

Scrolling down turns the banner into the logo: the scenery fades, and the big pixel title shrinks and glides into the toolbar's top-left corner while the buttons slide over to make room (on screens at least 1240px wide; narrower ones just scroll the banner away). Scrolling back up reverses it, and clicking the logo returns to the top. For visitors who prefer reduced motion the logo simply fades in.

The banner is alive: mist drifts over the ruins and water, the floating islands bob, motes of light rise from the spires, golden leaves fall from the tree, birds circle the ruins, arch lights flicker, and the ring quickens while an audit runs. None of it animates when the visitor prefers reduced motion, and the light and birds pause while the banner is off screen.

- The wordmark is an SVG drawn from code, with moss, vines (that sway) and flowers: [`PixelTitle.tsx`](frontend/src/components/PixelTitle.tsx), built from [`pixelTitleData.ts`](frontend/src/components/pixelTitleData.ts).
- The title-to-logo scroll effect is [`BrandDock.tsx`](frontend/src/components/BrandDock.tsx): scroll progress goes into CSS variables, nothing re-renders while scrolling.
- The scenery is cut from fine pixel art: `python scripts/make_hero_art.py --src <reference-banner>` rebuilds `frontend/src/assets/hero/`.
- The light, leaves and birds are drawn on a canvas by [`heroLights.ts`](frontend/src/components/heroLights.ts); scene coordinates live in [`heroScene.ts`](frontend/src/components/heroScene.ts).
- The page scrolls over the graph and the report: the graph zooms with Ctrl + scroll (or +/- buttons), and the report grows instead of scrolling inside itself.
- Colours are Tailwind tokens re-mapped in [`index.css`](frontend/src/index.css), so existing utility classes keep their meaning on the light background.

---

## 📁 Codebase Architecture & Key Files

```
APIGuard/
├── backend/
│   ├── apiguard/              # Python package (pip install apiguard-cli)
│   │   ├── main.py                # FastAPI server, REST routes, showcase toggle & SSE live stream
│   │   ├── db.py                  # Async SQLite persistence (WAL mode)
│   │   ├── engine/                # Core scanner & security analysis engine
│   │   │   ├── cli.py             # CLI parser (scan, --showcase, --fail-on, --sarif, --json)
│   │   │   ├── spec.py            # OpenAPI 3.x schema ingestion & parameter mapping
│   │   │   ├── graph.py           # Resource Dependency DAG builder (nodes & typed edges)
│   │   │   ├── auth.py            # Dynamic multi-identity token & session management
│   │   │   ├── planner.py         # Test sequence planner (Setup -> Control -> Probe)
│   │   │   ├── executor.py        # Safe HTTP executor (budget caps, localhost allowlist)
│   │   │   ├── inference.py       # DAG policy inference & propagation engine
│   │   │   ├── verifier.py        # Differential payload comparison (BOLA confirmation)
│   │   │   ├── reports.py         # SARIF 2.1.0, JSON, and PR markdown generator
│   │   │   ├── remediation.py     # AI surgical patch generator (v1 vs v2 context)
│   │   │   └── models.py          # Pydantic v2 data models & schemas
│   │   └── target/                # Sandbox multi-tenant API with 6 defect toggles
│   │       ├── app.py             # Vulnerable FastAPI target application
│   │       ├── config.py          # Dynamic defect configuration (showcase & patch mode)
│   │       └── data.py            # In-memory tenant data stores & database resets
│   └── tests/                     # Test suite (98 unit & integration tests)
├── frontend/                      # React 19 + TypeScript + Vite + Tailwind CSS v4
│   ├── src/
│   │   ├── components/            # HeroBanner, PixelTitle, GraphView, AuditReportModal, FindingDetail
│   │   ├── hooks/                 # useGraph, useScan (real-time SSE streaming)
│   │   ├── demo/                  # Demo-mode client + recorded fixtures (hosted replay)
│   │   ├── assets/hero/           # Pixel-art scenery, floating islands, mist and water
│   │   └── App.tsx                # Main security dashboard with showcase button
│   ├── package.json
│   └── vite.config.ts
├── benchmarks/                    # Ground truth manifests and empirical benchmark data
├── docs/                          # Architectural docs, screenshots, and demo script
├── scripts/                       # record_demo.py (hosted demo data), make_hero_art.py (banner art)
├── action.yml                     # GitHub Actions composite action definition
└── start.bat                      # One-click Windows startup runner
```

---

## 🗺️ Roadmap (Future Scope)

Planned, not shipped. Full detail in [`docs/ROADMAP.md`](docs/ROADMAP.md).

1. **Make it real:** analyze a GitHub repository from its link, configurable target, auth profiles (Bearer, API key, OAuth2), body-based and compound identifiers, spec-less discovery from HAR captures.
2. **Detect more:** safe cross-tenant write and delete verification, ID guessability scoring, automated rate-limit resilience testing.
3. **Smarter graph reasoning:** per-edge probabilistic propagation, request-budget optimiser, randomized benchmark targets.
4. **Developer workflow:** pull-request autofix application bot, bidirectional issue tracker sync.
5. **Platform:** multi-workspace management, team scan history, compliance framework mapping (SOC 2, ISO 27001), plugin SDK.

---

## ⚠️ Known Limitations

1. **Target configuration:** the CLI scans any API configured via `--profile <file.yaml>`. Profiles define `base_url`, OpenAPI spec path, host allowlist, request budget, and multi-identity login or static auth headers with `${ENV_VAR}` secret expansion. Resource types and ownership rules are dynamically derived from the OpenAPI dependency graph and profile overrides (`owner_field`, `sensitive_fields`).
2. **Identifier scope:** the prototype extracts runtime resource identifiers primarily from path parameters (`{project_id}`); nested body-based compound keys are planned for upcoming releases.
3. **Propagation scope:** once the main read route is seen to be owner-only, every other operation that takes an ID is tested. Propagated rules attach a hypothesis and confidence to each result; they do not yet narrow the set of routes tested.
4. **Safe mutation gate:** mutating HTTP verbs are turned off by default to protect target data integrity. The setup step still creates one test record per scan and leaves it behind.
5. **Dry run is a preview:** it lists a setup, control and probe step per route. The live scan reuses one created record, so it sends fewer requests.
6. **Benchmark scope:** measured on our own target with our own answer key, against a baseline that only tests routes it has a rule for.
7. **Hosted demo is a replay:** the GitHub Pages build replays recorded runs; importing a spec and calling a live model need the local backend.
8. **BFLA detection scope:** Broken Function Level Authorization (OWASP API5) verifies admin privilege boundaries for operations flagged via `admin_operations` patterns, `/admin` path segments, or the `admin` OpenAPI tag. An admin identity executes control calls while the attacker executes probes. Admin routes with path parameters resolve IDs harvested earlier in the scan; unharvested parameters are skipped (`needs path parameter {name}`) without false-secure reporting, and failed admin controls are recorded as skips with HTTP status. A probe is only CONFIRMED when returning 2xx with a non-empty payload structurally matching the admin control response; soft-200 error payloads, empty collections, or divergent shapes are classified as POTENTIAL (confidence ≤ 0.5, exit code 0). Real credential tokens are never exposed in reproduction artifacts, using `<USER_B_TOKEN>` placeholders.
9. **BOPLA detection scope:** Broken Object Property Level Authorization (OWASP API3) operates in two complementary modes. Part A (active mass assignment) injects unauthorized properties (`role`, `is_admin`, and resource `owner_field`) into object creation and mutation requests. A finding is CONFIRMED if the read-back response contains the injected property with the assigned value and that property is not documented as writable in the OpenAPI schema; if the server echoes the property in the creation response without persistence, it is classified as POTENTIAL (confidence ≤ 0.5). PATCH/PUT property injections follow the `--mutations` safety gate. Part B (passive excessive data exposure) inspects all 2xx JSON responses for undocumented properties matching sensitive patterns (`password`, `hash`, `secret`, `token`, etc.), confirming leaks with masked previews (`***`) and zero additional network requests. Operations lacking documented response schemas are recorded as coverage skips rather than false positives. Real credential tokens are never exposed in reproduction artifacts, using `<USER_A_TOKEN>` and `<USER_B_TOKEN>` placeholders.
10. **Broken Authentication detection scope:** Broken Authentication (OWASP API2) tests operations where the owner control call succeeded, replaying the exact request under four deterministic tampering strategies: missing authorization headers, invalid/garbage tokens, JWT header manipulation (the `alg:none` bypass with stripped signature and signature alteration), and expired tokens if configured in the profile (`expired_token`). Operations marked public in the OpenAPI specification (`security: []` or no security requirement defined) and operations lacking a successful owner control call are recorded as coverage skips. A finding is CONFIRMED only when the tampered request returns 2xx and the response payload structurally matches the owner's control response; 2xx responses with error-looking bodies, empty payloads, or divergent structures are classified as POTENTIAL (confidence ≤ 0.5, exit code 0). Rate-limiting and credential brute-force attacks are intentionally excluded as out-of-scope load tests. Real and forged token values are never exposed in reproduction artifacts, using token descriptions and standard `<GARBAGE_TOKEN>`, `<ALG_NONE_JWT>`, `<ALTERED_SIGNATURE_JWT>`, and `<EXPIRED_TOKEN>` placeholders.
11. **Passive security checks scope:** Security misconfigurations (OWASP API8) and API inventory checks (OWASP API9) operate strictly passively on HTTP responses already captured during the active scan phases, sending **zero additional network requests**. CORS checks inspect observed wildcard origin with credentials; they do not forge custom `Origin` request headers. Verbose error detection flags stack traces and SQL errors with token-masked previews (`***`). Version disclosures inspect `Server` and `X-Powered-By` headers. Security header hygiene flags missing `nosniff` on JSON and missing `no-store`/`private` `Cache-Control` on responses carrying authenticated sensitive data. Inventory checks flag deprecated endpoints answering 2xx and undocumented HTTP status codes. Passive checks are reported as CONFIRMED (observed facts) with exit code 0 by default; use `--fail-on low` or `--fail-on medium` to enforce them in CI/CD gates.
