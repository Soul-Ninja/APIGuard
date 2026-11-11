"""
Records real APIGuard engine runs into frontend/src/demo/fixtures.json.

The hosted GitHub Pages demo has no Python backend, so it replays these
recordings. Nothing here is hand-written: every graph, event, finding and
benchmark number below comes from running the actual engine in-process.

Usage (from the repo root):
    python scripts/record_demo.py

Safe to run offline: LLM keys are blanked so remediation uses the offline
template, and a throwaway SQLite file is used instead of apiguard.db.
"""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

# Never call a live model or touch the developer's real database while recording.
os.environ["OPENROUTER_API_KEY"] = ""
os.environ["GEMINI_API_KEY"] = ""

import httpx  # noqa: E402

import apiguard.db as db  # noqa: E402

db.DB_PATH = str(Path(tempfile.mkdtemp()) / "record.db")

from apiguard.main import app, refresh_current_graph  # noqa: E402

OUT = ROOT / "frontend" / "src" / "demo" / "fixtures.json"
BENCHMARKS = ROOT / "benchmarks" / "results.json"


async def run_scan(client: httpx.AsyncClient, patched: bool, mutations: bool) -> dict:
    await client.post("/api/target/reset")
    if patched:
        await client.post("/api/target/patch", json={"patched": True})

    res = await client.post("/api/scan", json={"dry_run": False, "budget": 60, "enable_mutations": mutations})
    scan_id = res.json()["scan_id"]

    stream = await client.get(f"/api/scan/{scan_id}/events")
    events = [json.loads(line[6:]) for line in stream.text.splitlines() if line.startswith("data: ")]
    findings = (await client.get("/api/findings", params={"scan_id": scan_id})).json()
    return {"events": events, "findings": findings}


async def main() -> None:
    await db.init_db()
    refresh_current_graph()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        # Enable showcase mode so all defect checks are active
        await client.post("/api/target/showcase", json={"enabled": True})

        fixtures: dict = {
            "graph": (await client.get("/api/graph")).json(),
            "identities": (await client.get("/api/identities")).json(),
            "remediationStatus": (await client.get("/api/remediate/status")).json(),
            "benchmark": json.loads(BENCHMARKS.read_text(encoding="utf-8")),
            "dryRun": {},
            "scans": {},
        }

        for mutations in (False, True):
            dry = await client.post("/api/scan/dry-run", json={"dry_run": True, "budget": 60, "enable_mutations": mutations})
            fixtures["dryRun"][str(mutations).lower()] = dry.json()

        for patched in (False, True):
            for mutations in (False, True):
                key = f"{'patched' if patched else 'vulnerable'}_{'mut' if mutations else 'safe'}"
                fixtures["scans"][key] = await run_scan(client, patched, mutations)
                print(f"{key}: {len(fixtures['scans'][key]['events'])} events, {len(fixtures['scans'][key]['findings'])} findings")

        # Remediation for the BOLA finding
        bola_findings = [f for f in fixtures["scans"]["vulnerable_safe"]["findings"] if f.get("category") == "BOLA"]
        leak = bola_findings[0] if bola_findings else fixtures["scans"]["vulnerable_safe"]["findings"][0]
        rem = await client.post("/api/remediate", json={
            "finding_id": leak["id"],
            "endpoint": leak["endpoint"],
            "method": leak["method"],
            "resource_type": leak["resource_type"],
            "diff_fields": leak["diff_fields"],
            "hypothesis": leak["hypothesis"],
        })
        fixtures["remediation"] = rem.json()

        await client.post("/api/target/reset")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixtures, indent=1), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


asyncio.run(main())
