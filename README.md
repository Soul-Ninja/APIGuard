# APIGuard: Graph-Guided API Authorization & BOLA Detection Engine

<p align="center">
  <a href="https://code-breaker-ctrl.github.io/APIGuard/"><img src="https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-10b981?style=flat-square&logo=githubpages&logoColor=white" alt="Live Demo"></a>
  <img src="https://img.shields.io/badge/Python-3.12-3776AB.svg?logo=python&logoColor=white&style=flat-square" alt="Python 3.12">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white&style=flat-square" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-19-61DAFB.svg?logo=react&logoColor=black&style=flat-square" alt="React 19">
  <img src="https://img.shields.io/badge/TypeScript-5.x-3178C6.svg?logo=typescript&logoColor=white&style=flat-square" alt="TypeScript">
  <img src="https://img.shields.io/badge/OWASP-API%20%231%20BOLA-red.svg?style=flat-square" alt="OWASP API #1">
</p>

> **"The Vulnerability That Hides in Plain Sight — Made Visible."**  

---

## ⚡ Executive Summary

Broken Object Level Authorization (**BOLA / IDOR — OWASP API #1**) is the most pervasive and dangerous vulnerability in modern cloud APIs. It does not crash servers, trigger alerts, or return HTTP 500 errors. Instead, it quietly returns **HTTP 200 OK**, leaking sensitive tenant data to unauthorized actors.

Most DAST scanners test endpoints in isolation: they fuzz parameters, receive `401 Unauthorized` or `404 Not Found`, and mistakenly declare the API secure.

**APIGuard** replaces isolated fuzzing with a **Resource Dependency Directed Acyclic Graph (DAG)**:
1. **Schema & DAG Ingestion:** Ingests standard OpenAPI 3.x specifications without custom invented keys, mapping relationships between producer and consumer operations (`POST /projects` creates `{project_id}` $\to$ consumed by `GET /projects/{project_id}`).
2. **Dynamic Multi-Identity State Harvest:** Automatically authenticates as **User A (Owner)** to create genuine state and harvest live resource IDs.
3. **Graph-Guided Policy Inference & Propagation:** Observes authorization enforcement on parent endpoints and propagates candidate ownership policies along DAG edges to adjacent/nested endpoints (e.g., `GET /projects/{project_id}/export`).
4. **Differential Payload Verification:** Probes the endpoint using **User B's (Attacker's)** credentials. Rather than blindly trusting status codes, it performs differential analysis on response bodies, confirming BOLA only when private owner-linked fields are leaked.
5. **AI-Driven Surgical Remediation:** Bridges detection to remediation with context-infused prompting. Shows side-by-side comparisons of naive prompts ($v_1$) vs graph-guided prompts ($v_2$), generating draft FastAPI patches and pytest tests for a developer to review.
6. **Executive Audit Report Export:** Instantly exports comprehensive security assessment reports in GitHub-Flavored Markdown (`.md`) or printable HTML (save as PDF from the browser print dialog), detailing affected routes, leaked tenant attributes, and cURL repro commands.

---

## 🌐 Live Hosted Demo

👉 **[Launch APIGuard Live Demo (GitHub Pages)](https://code-breaker-ctrl.github.io/APIGuard/)**

Try APIGuard directly in your browser with zero installation:
- ⚡ **Interactive Dependency DAG:** Explore operation and resource dependencies with Dagre auto-layout.
- 🎯 **Real-Time Audit Replay:** Click **"RUN EXECUTION AUDIT"** to watch live SSE event propagation and node transitions.
- 🔍 **Differential Inspector:** Inspect leaked victim attributes side-by-side with reproduction cURL commands.
- 📄 **Executive Audit Report Export:** Download formatted Markdown (`.md`) or printable HTML pentest reports.
- 📊 **Empirical Benchmark Panel:** Review measured recall, precision, and ablation comparison tables.



> **Note:** The hosted demo replays genuine engine runs captured by [`scripts/record_demo.py`](scripts/record_demo.py). Custom OpenAPI schema ingestion and live model calls require running the backend locally (see *Setup & Quick Start* below).



---

## 📸 Demo Screenshots (Real Captured Execution)

| Screen | Description |
|---|---|
| ![Graph Idle](docs/screenshots/01_graph_idle.png) | **React Flow DAG:** Operation and Identifier nodes with Dagre auto-layout, under the pixel-art banner. |
| ![Dry Run Preview](docs/screenshots/02_dry_run_table.png) | **Dry-Run Mode:** Planned multi-identity sequence table without sending any traffic. |
| ![Live SSE Scan](docs/screenshots/05_graph_after_scan.png) | **Real-Time Audit:** Streaming console, live SSE event propagation, and red BOLA badge. |
| ![Differential Finding Detail](docs/screenshots/06_finding_detail.png) | **Differential Inspector:** Aman vs Taaran response diff, leaked fields in red, and repro cURL. |
| ![Empirical Benchmarks](docs/screenshots/03_benchmark_panel.png) | **Benchmark & Ablations:** 100% recall vs 0% baseline on Defect B, with ablation proofs. |
| ![AI Remediation](docs/screenshots/07_ai_remediation.png) | **AI Remediation Engine:** Side-by-side $v_1$ vs $v_2$ prompt iteration and pytest test suite. |
| ![Target Patched & Re-scanned](docs/screenshots/09_after_fix_secure.png) | **Automated Fix Verification:** After reference patch is applied, re-scan proves 0 confirmed leaks and green nodes. |

---

## 📊 Measured Benchmark Results

Every metric below was measured by running both scanners against the bundled demo target API (`http://127.0.0.1:8000/target`); requests are delivered in-process, and the integration tests run the same scanners over real sockets. Ground truth is loaded from `benchmarks/manifests/*.json` (never accessed by scanners during execution). The numbers come straight from [`benchmarks/results.json`](benchmarks/results.json).

| Test Variant | Target Description | Ground Truth | Baseline Recall | Baseline Reqs | APIGuard Recall | APIGuard Reqs | Avg ms / finding |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Variant A** | Direct BOLA on primary route (`GET /projects/{id}`) | 1 | 100% (1/1) | 7 | **100% (1/1)** | 15 | 8.3 ms |
| **Variant B** | Indirect BOLA on export (`GET /projects/{id}/export`) | 1 | **0% (0/1)** | 7 | **100% (1/1)** | 15 | 6.5 ms |
| **Variant C** | Mutation BOLA on update (`PATCH /projects/{id}`) | 1 | 100% (1/1) | 7 | **100% (1/1)** | 15 | 11.8 ms |
| **Variant All** | Compound multi-defect scenario (A + B + C) | 3 | 67% (2/3) | 7 | **100% (3/3)** | 19 | 5.4 ms |
| **Variant Secure** | Fully patched target + verifier traps | 0 | n/a (0 FP) | 7 | **n/a (0 FP)** | 13 | n/a |

### 🔬 Controlled Ablation Study

- **Graph Scanner with Propagation OFF:** the scanner stops after the main read route and never tests the nested routes, so it misses the indirect defect (0 of 1, 6 requests).
- **Oracle Baseline (Hand-Tagged Rules on Every Route):** Matches APIGuard at 100% recall (9 requests vs 15), but requires a human to write a security rule for every route in advance.

**How to read these numbers**
- The target and the answer key are ours, so this shows the method works on a controlled case, not real-world accuracy.
- APIGuard sends **more** requests than the rules-only baseline (15 vs 7 on single-defect variants) because it also tests the nested routes. It finds more; it is not cheaper.
- The baseline only tests routes it was given a rule for. There is no brute-force "test every route with two users" baseline yet.
- "Avg ms / finding" is total scan time divided by findings, not time to the first finding.

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
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Technologies Used
- **Backend:** Python 3.12, FastAPI, Pydantic v2, `aiosqlite` (WAL-mode SQLite), `openapi-spec-validator`, `httpx` (async ASGI/HTTP client), `pytest`, `pytest-asyncio`.
- **Frontend:** React 19, Vite, TypeScript, Tailwind CSS v4 (custom light pixel theme), `@xyflow/react` (React Flow), `dagre` (graph layout), `lucide-react`, with the Press Start 2P and VT323 pixel fonts.
- **AI Remediation:** LLM via OpenRouter or Gemini (whichever is configured), with SQLite caching and automatic deterministic offline template fallback.

### Reused Open-Source Components & Attributions
- `@xyflow/react` & `dagre`: Interactive node-edge visualization and hierarchical DAG layout.
- `openapi-spec-validator`: Strict schema validation against official OpenAPI 3.0/3.1 specs.
- `aiosqlite`: Async persistence for scans, real-time events, and deduplicated findings.

---

## ⚖️ Safety & Architectural Guarantees

| Category | Status | Details |
|---|:---:|---|
| **Real Engine Execution** | **Real** | Real HTTP requests handled by the real target application. The dashboard and benchmark deliver them in-process (ASGI); the integration tests and CLI use real network sockets. No timer-based mocks or hardcoded node arrays. |
| **Deterministic Scanner** | **100% Real** | The scanner engine makes **no LLM calls**. Graph traversal, policy evaluation, and differential verification are completely deterministic. |
| **AI Remediation Engine** | **Supported / Offline Fallback** | LLM via OpenRouter or Gemini (whichever is configured) is used strictly for post-scan surgical remediation ($v_1 \to v_2$). If no API key is provided, a deterministic offline template is badged. |
| **Safe by Default** | **Working** | Requests are strictly restricted to allowlisted loopback hosts (`127.0.0.1`). Mutating requests (`PATCH`/`DELETE`) are blocked unless explicitly toggled. Each scan still creates one test record on the target (the setup step). |
| **Git Commit History** | **Verified** | Clean, incremental commit history with tests passing at every stage. |

---

## 🎨 Design: Paper & Grace

The dashboard uses a light pixel theme: cream paper with a faint grid, chunky black pixel type with a lime shadow, and gold and moss accents. All the scenery (ruins, a resting knight, a golden tree, a thin golden ring) lives in the banner at the top, so the working panels stay plain and easy to read. The chevron in the toolbar hides the banner to give the panels more room (the choice is remembered; the banner starts open).

Scrolling down turns the banner into the logo: the scenery fades, and the big pixel title shrinks and glides into the toolbar's top-left corner while the buttons slide over to make room (on screens at least 1240px wide; narrower ones just scroll the banner away). Scrolling back up reverses it, and clicking the logo returns to the top. For visitors who prefer reduced motion the logo simply fades in.

The banner is alive: mist drifts over the ruins and water, the floating islands bob, motes of light rise from the spires, golden leaves fall from the tree, birds circle the ruins, arch lights flicker, and the ring quickens while an audit runs. None of it animates when the visitor prefers reduced motion, and the light and birds pause while the banner is off screen.

- The wordmark is an SVG drawn from code, with moss, vines (that sway) and flowers: [`PixelTitle.tsx`](frontend/src/components/PixelTitle.tsx), built from [`pixelTitleData.ts`](frontend/src/components/pixelTitleData.ts).
- The title-to-logo scroll effect is [`BrandDock.tsx`](frontend/src/components/BrandDock.tsx): scroll progress goes into CSS variables, nothing re-renders while scrolling.
- The scenery is cut from fine pixel art, not redrawn: `pip install -r scripts/requirements.txt`, then `python scripts/make_hero_art.py --src <reference-banner>` rebuilds `frontend/src/assets/hero/` (add `--preview DIR` to check the result on the paper colour). The reference image is not stored in the repo.
- The light, leaves and birds are drawn on a canvas by [`heroLights.ts`](frontend/src/components/heroLights.ts); where things sit is in [`heroScene.ts`](frontend/src/components/heroScene.ts).
- The page scrolls over the graph and the report: the graph zooms with Ctrl + scroll (or the +/- buttons), and the report grows instead of scrolling inside itself.
- Colours are Tailwind tokens re-mapped in [`index.css`](frontend/src/index.css), so existing utility classes keep their meaning on the light background.

---

## 📁 Codebase Architecture & Key Files

```
APIGuard/
├── backend/
│   ├── apiguard/              # Python package (pip install apiguard-cli)
│   │   ├── main.py                # FastAPI server, REST routes & SSE live scan stream
│   │   ├── db.py                  # Async SQLite persistence (WAL mode)
│   │   ├── engine/                # Core scanner & security analysis engine
│   │   │   ├── spec.py            # OpenAPI 3.x schema ingestion & parameter mapping
│   │   │   ├── graph.py           # Resource Dependency DAG builder (nodes & typed edges)
│   │   │   ├── auth.py            # Dynamic multi-identity token & session management
│   │   │   ├── planner.py         # Test sequence planner (Setup -> Control -> Probe)
│   │   │   ├── executor.py        # Safe HTTP executor (budget caps, localhost allowlist)
│   │   │   ├── inference.py       # DAG policy inference & propagation engine
│   │   │   ├── verifier.py        # Differential payload comparison (BOLA confirmation)
│   │   │   ├── remediation.py     # AI surgical patch generator (v1 vs v2 context)
│   │   │   └── models.py          # Pydantic v2 data models & schemas
│   │   └── target/                # Sandbox multi-tenant API (Variants A, B, C, Secure)
│   ├── tests/                     # Test suite (22 unit & integration tests)
│   └── requirements.txt           # Backend dependencies
├── frontend/                      # React 19 + TypeScript + Vite + Tailwind CSS v4
│   ├── src/
│   │   ├── components/            # HeroBanner, PixelTitle, GraphView, AuditReportModal, FindingDetail, Modals
│   │   ├── hooks/                 # useGraph, useScan (real-time SSE streaming)
│   │   ├── demo/                  # Demo-mode client + recorded fixtures (hosted replay)
│   │   ├── assets/hero/           # Pixel-art scenery, floating islands, mist and water for the banner
│   │   └── App.tsx                # Main security dashboard
│   ├── package.json
│   └── vite.config.ts
├── benchmarks/                    # Ground truth manifests and empirical benchmark data
├── docs/                          # Architectural docs, screenshots, and demo script
├── scripts/                       # record_demo.py (hosted demo data), make_hero_art.py (banner art)
├── .github/workflows/pages.yml    # Deploys the hosted replay demo to GitHub Pages
└── start.bat                      # Alternative startup runner
```

---

## 🚀 Setup & Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/Code-Breaker-Ctrl/APIGuard.git
cd APIGuard
```

### 2. Quick Launch (Windows)
Double-click:
```bat
start.bat
```
This starts both the FastAPI backend (`http://127.0.0.1:8000`) and the Vite dashboard (`http://127.0.0.1:5173`) and automatically opens your default browser.

### 3. Manual Launch

#### 1. Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate | Unix: source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn apiguard.main:app --host 127.0.0.1 --port 8000 --reload
```
Run backend tests:
```bash
pytest backend/tests/ -v
```

#### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```
Open `http://127.0.0.1:5173` in your browser.

#### 3. Command line (optional)
```bash
pip install -e .          # from the repo root; installs the apiguard command
apiguard scan --dry-run   # print the plan, send nothing
apiguard scan             # run the scan (add --mutations for PATCH/DELETE)
apiguard scan --profile backend/apiguard/targets/example.yaml  # scan any target API

# Windows alternative (if Smart App Control blocks apiguard.exe):
python -m apiguard scan --dry-run
python -m apiguard scan --profile backend/apiguard/targets/example.yaml
```


---

## 🗺️ Roadmap (Future Scope)

Planned, not shipped. Full detail in [`docs/ROADMAP.md`](docs/ROADMAP.md).

1. **Make it real:** analyze a GitHub repository from its link, configurable target, auth profiles (Bearer, API key, OAuth2), body-based and compound identifiers, spec-less discovery from HAR captures.
2. **Detect more:** BFLA (API5), mass assignment / BOPLA (API3), safe cross-tenant write and delete checks, ID guessability scoring.
3. **Smarter graph reasoning:** per-edge probabilistic propagation, a request-budget optimiser, a brute-force baseline, randomised benchmark targets.
4. **Developer workflow:** CI/CD gate, SARIF export, regression guard, a verified auto-fix loop and a pull-request bot.
5. **Platform:** workspaces and scan history, redacted evidence vault, compliance mapping, plugin SDK.

---

## ⚠️ Known Limitations
1. **Target configuration:** the CLI scans any API configured via `--profile <file.yaml>`. Profiles define `base_url`, OpenAPI spec path, host allowlist, request budget, and multi-identity login or static auth headers with `${ENV_VAR}` secret expansion. Resource types and ownership rules are dynamically derived from the OpenAPI dependency graph and profile overrides (`owner_field`, `sensitive_fields`).
2. **Identifier scope:** the prototype extracts runtime resource identifiers primarily from path parameters (`{project_id}`); nested body-based compound keys are planned for upcoming releases.
3. **Propagation scope:** once the main read route is seen to be owner-only, every other operation that takes an ID is tested. Propagated rules attach a hypothesis and confidence to each result; they do not yet narrow the set of routes tested.
4. **Safe mutation gate:** mutating HTTP verbs are turned off by default to protect target data integrity. The setup step still creates one test record per scan and leaves it behind.
5. **Dry run is a preview:** it lists a setup, control and probe step per route. The live scan reuses one created record, so it sends fewer requests.
6. **Benchmark scope:** measured on our own target with our own answer key, against a baseline that only tests routes it has a rule for.
7. **Hosted demo is a replay:** the GitHub Pages build replays recorded runs; importing a spec and calling a live model need the local backend.
