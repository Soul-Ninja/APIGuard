# APIGuard: Live Demo Script

> A short on-stage walkthrough.

## Before you start

1. Start the backend: `cd backend`, then `python -m uvicorn apiguard.main:app --host 127.0.0.1 --port 8000`.
2. Start the frontend: `cd frontend`, then `npm run dev` (or double-click `start.bat`).
3. Open `http://127.0.0.1:5173` and click the reset icon (circular arrow) so the target and history are clean.
4. Leave **Mutations** off for the first run.

**The screen:** the pixel-art banner sits on top (the chevron button in the toolbar hides it). Under it the toolbar has the `Dry run` and `Mutations` toggles, five icon buttons (guided demo, benchmarks, dry-run table, export report, reset) and the gold **BEGIN AUDIT** button. Left: the spec's identities and endpoints. Centre: the dependency graph. Right: the Event Stream above the Findings list.

> With **Dry run** on, the main button becomes **PREVIEW PLAN** and opens the plan table instead of sending traffic.

## The 3-minute walkthrough

### Act 1: The problem and the map (0:00 to 0:45)

- *"Most scanners test API routes one at a time. When a route returns 200, nobody is alerted and everything looks fine. This is BOLA, OWASP API #1: it doesn't crash anything, it quietly returns someone else's data."*
- Point at the graph. Blue boxes at the top are setup (login, create project). The gold key is the ID that creating a project produces. Below it are the routes that use the ID, and below those the routes nested under a project. Solid lines come from the OpenAPI file; dashed lines are inferred nesting.
- Edges: `POST /projects` **produces** `project_id`; `GET /projects/{id}` **consumes** it; `/export`, `/summary` and `/members` are **nested under** the project route.

### Act 2: Plan and run (0:45 to 1:45)

1. Click the chip icon (dry-run table): *"This previews the plan: create as the owner, read as the owner, read as the attacker. Nothing is sent. The live scan reuses one created record, so it sends fewer requests."* Close it.
2. Click **BEGIN AUDIT** and narrate the Event Stream:
   - `[AUTH]` logs in as Aman (owner) and Taaran (attacker).
   - `[SETUP]` Aman creates a project (HTTP 201) and we keep its real ID.
   - `[CONTROL_OWNER]` / `[PROBE_ADVERSARY]` on the main read route: owner gets 200, attacker gets 403. `[INFERENCE]` records the rule `owner_only`.
   - `[PROPAGATION]` hands that rule to the nested routes, and each is tested the same way.
3. On the graph: the main route turns **SAFE**, `/summary` shows **SAFE** too (it returned 200 with an empty body, so nothing leaked), `/members` shows **UNSURE** (the route isn't implemented, so even the owner gets 404), and `/export` turns red: **LEAK**.

### Act 3: Proof, fix and benchmark (1:45 to 3:00)

1. Click the finding. Left is the owner's response, right is the attacker's with the leaked fields highlighted (`owner_email`, `financial_payload.budget`, `financial_payload.billing`). Show the graph path (`getProjectById -> (NESTED_UNDER) -> exportProjectBilling`) and the reproduction cURL.
2. Click **AI Remediation**. A naive prompt (v1) is shown next to a prompt that includes the resource and the leaked field names (v2). Without an API key, the offline template is shown and labelled "not model output".
3. Click **Apply reference fix & re-scan**. This switches the demo target to its built-in patched mode (it does not run the AI's patch) and re-scans: one confirmed leak becomes zero.
4. Click the bar-chart icon (benchmarks): five variants, six planted bugs. APIGuard finds 6 of 6 with no false alarms on the patched variant; a baseline that only tests routes it has a rule for finds 4 of 6. Point out that APIGuard sends more requests, because it also tests the nested routes. The ablation shows that without the neighbour-testing stage the indirect bug is missed.

## Quick answers to common cross-questions

**Are these results real or simulated?**
Real HTTP requests, handled by the real target application code, with no mocked responses. In the dashboard and the benchmark the requests are delivered in-process (no network socket); the 22 automated tests include integration tests that start a real server on a real port and run the same scanner over it.

**How is this different from ZAP or Burp Suite?**
Those are general-purpose tools and they can test authorization, but you have to set it up (two logins, the rules, what counts as a violation). APIGuard automates the two-user workflow and uses the API's structure (which route creates the ID, which routes sit under it) to decide what to test next. We cover a gap rather than replace them.

**Why isn't the scanner an LLM?**
Detection has to be predictable and auditable: the same input gives the same result, and there are no hallucinated findings. The LLM (OpenRouter or Gemini, whichever is configured) is used only after a bug is proven, to draft a fix and a test. The model sees the route, method, resource type and leaked field names, never response bodies or tokens.

**How does the verifier avoid false positives?**
It doesn't trust a 200 on its own. It collects the owner's sensitive-looking values (email, billing, card, budget and so on) from the control response and confirms a leak only if those exact values appear in the attacker's response. An empty body, or a 404 for everyone, is never reported as a confirmed leak.

**What about APIs with multi-step dependencies?**
One level today: the scanner finds the route that creates the ID and creates one record. Deeper chains (A needs B needs C) are not built yet; if a prerequisite can't be created, the test is skipped or reported as inconclusive rather than guessed.

**Does it work on my API?**
Not yet. The scanner is wired to the bundled demo API; making the target address, login flow and create-request body configurable is the next milestone.

**Is it safe to run?**
There are guardrails: a host allowlist (loopback only), a request budget, a mutation gate that blocks PATCH and DELETE unless switched on, and secret redaction. It does create a test record on the target, so use it on test systems only.
