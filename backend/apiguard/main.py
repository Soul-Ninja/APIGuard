import asyncio
import json
import time
import uuid
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

from apiguard.engine.spec import OpenAPIParser, DEMO_SPEC_YAML
from apiguard.engine.graph import ResourceGraph
from apiguard.engine.executor import SafeExecutor
from apiguard.engine.scanner import GraphGuidedScanner
from apiguard.engine.planner import TestPlanner
from apiguard.engine.remediation import RemediationEngine
from apiguard.engine.benchmark import run_benchmark
from apiguard.engine.auth import AuthRegistry, DEFAULT_CREDENTIALS
from apiguard.engine.target import load_target_profile
from apiguard.engine.models import IdentityProfile, ScanEvent
from apiguard.target.app import target_app
from apiguard.target.data import reset_db
from apiguard.target.config import update_target_config, get_target_config
from apiguard.db import init_db, save_scan, save_scan_event, save_finding, get_findings, clear_db

current_spec_yaml = DEMO_SPEC_YAML
current_graph = ResourceGraph()

def refresh_current_graph():
    global current_graph
    parser = OpenAPIParser(current_spec_yaml)
    operations = parser.extract_operations()
    current_graph = ResourceGraph()
    current_graph.build_from_operations(operations)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    refresh_current_graph()
    yield

app = FastAPI(title="APIGuard Platform API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount vulnerable sample target API at /target
app.mount("/target", target_app)

# Active scan event streams
ACTIVE_EVENT_QUEUES: Dict[str, asyncio.Queue] = {}

@app.get("/api/health")
def health():
    cfg = get_target_config()
    return {
        "status": "healthy",
        "service": "APIGuard Engine",
        "target_mounted": True,
        "target_patched": cfg.patched_mode
    }

@app.post("/api/spec/import")
async def import_spec(file: Optional[UploadFile] = File(None), raw_spec: Optional[str] = Form(None)):
    global current_spec_yaml
    try:
        content = ""
        if file:
            content = (await file.read()).decode("utf-8")
        elif raw_spec:
            content = raw_spec
        else:
            content = DEMO_SPEC_YAML

        parser = OpenAPIParser(content)
        operations = parser.extract_operations()
        current_spec_yaml = content
        refresh_current_graph()
        return {
            "status": "success",
            "operations_count": len(operations),
            "nodes_count": len(current_graph.nodes),
            "edges_count": len(current_graph.edges)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid OpenAPI 3.x specification: {str(e)}")

@app.get("/api/graph")
def get_graph():
    return current_graph.to_dict()

class ScanTriggerInput(BaseModel):
    dry_run: bool = False
    budget: int = 30
    enable_mutations: bool = False
    target_profile: Optional[str] = "targets/demo.yaml"

@app.post("/api/scan")
async def trigger_scan(opts: ScanTriggerInput):
    if opts.dry_run:
        # A live scan always sends traffic. Previewing the plan is a separate, traffic-free endpoint.
        raise HTTPException(
            status_code=400,
            detail="dry_run is not supported on /api/scan; use POST /api/scan/dry-run to preview the plan without sending traffic",
        )
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    await save_scan(scan_id, "http://127.0.0.1:8000/target")
    queue = asyncio.Queue()
    ACTIVE_EVENT_QUEUES[scan_id] = queue

    # Run scan in background task
    asyncio.create_task(_execute_scan_task(scan_id, opts, queue))

    return {"scan_id": scan_id, "status": "initiated"}

@app.post("/api/scan/dry-run")
async def preview_dry_run(opts: ScanTriggerInput):
    parser = OpenAPIParser(current_spec_yaml)
    operations = parser.extract_operations()
    planner = TestPlanner(current_graph, base_url="http://127.0.0.1:8000/target")

    user_a, user_b = (IdentityProfile(**{k: DEFAULT_CREDENTIALS[n][k] for k in ("identity_id", "username", "password", "role")},
                                      token=f"[DRY_RUN_{n.upper()}_TOKEN]") for n in ("user_a", "user_b"))

    all_steps = []
    budget_allocated = opts.budget
    for op in operations:
        steps = planner.plan_audit_for_operation(op, user_a, user_b, enable_mutations=opts.enable_mutations)
        for s in steps:
            all_steps.append({
                "step_id": s.step_id,
                "operation_id": s.operation_id,
                "method": s.method,
                "url": s.url,
                "identity": s.identity_id,
                "purpose": s.purpose,
                "phase": "A" if s.purpose in ["setup", "control_owner"] else "B",
                "cleanup": s.cleanup,
                "headers": {"Authorization": "[REDACTED]"},
                "body_preview": s.json_body or {}
            })

    planned_steps = all_steps[:budget_allocated]
    return {
        "planned_steps": planned_steps,
        "total_planned": len(planned_steps),
        "total_budget": budget_allocated,
        "mutations_enabled": opts.enable_mutations,
        "budget_remaining": max(0, budget_allocated - len(planned_steps))
    }

def _ev(scan_id: str, event_type: str, message: str, phase: Optional[str] = None, **data) -> ScanEvent:
    return ScanEvent(event_id=f"ev_{uuid.uuid4().hex[:6]}", scan_id=scan_id, timestamp=time.time(),
                     event_type=event_type, phase=phase, message=message, data=data)

async def _execute_scan_task(scan_id: str, opts: ScanTriggerInput, queue: asyncio.Queue):
    async def emit(ev: ScanEvent):
        ev.scan_id = scan_id
        await queue.put(ev)
        await save_scan_event(ev)

    try:
        profile = load_target_profile(opts.target_profile or "targets/demo.yaml")
        operations = OpenAPIParser(current_spec_yaml).extract_operations()

        # in-process ASGI client talks to the mounted /target app without a socket
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
            identities = list((await AuthRegistry(profile).authenticate_all(client=client)).items())
            user_a = dict(identities).get("user_a") or identities[0][1]
            user_b = dict(identities).get("user_b") or identities[1][1]
            await emit(_ev(scan_id, "log", f"[AUTH] Successfully acquired dynamic tokens for User A ({user_a.username}) and User B ({user_b.username})", "A"))

            executor = SafeExecutor(allowed_hosts={"127.0.0.1", "localhost"}, total_budget=opts.budget, enable_mutations=opts.enable_mutations)
            scanner = GraphGuidedScanner(executor, profile.base_url, target_profile=profile)
            findings = await scanner.run_scan(operations=operations, user_a=user_a, user_b=user_b,
                                              enable_mutations=opts.enable_mutations, on_event=emit, client=client)
            for f in findings:
                await save_finding(scan_id, f)
            await emit(_ev(scan_id, "scan_completed", f"[DONE] Audit finished. {len(findings)} confirmed vulnerabilities recorded.", "C", findings_count=len(findings)))
    except Exception as e:
        await emit(_ev(scan_id, "error", f"[ERROR] Scan execution error: {e}"))
        await queue.put(_ev(scan_id, "scan_completed", "[DONE] Audit aborted due to an error.", "C", findings_count=0, aborted=True))
    finally:
        await queue.put(None)  # sentinel closes the SSE stream

@app.get("/api/scan/{scan_id}/events")
async def stream_scan_events(scan_id: str):
    queue = ACTIVE_EVENT_QUEUES.get(scan_id)
    if not queue:
        raise HTTPException(status_code=404, detail="Scan not found or expired")

    async def event_generator():
        while True:
            event = await queue.get()
            if event is None:
                break
            yield f"data: {json.dumps(event.model_dump())}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/findings")
async def list_findings(scan_id: Optional[str] = None):
    return await get_findings(scan_id=scan_id)

@app.get("/api/identities")
async def get_identities():
    return [
        {
            "key": key,
            "identity_id": creds["identity_id"],
            "username": creds["username"],
            "role": creds["role"],
            "token": "[REDACTED]"
        }
        for key, creds in DEFAULT_CREDENTIALS.items()
    ]

@app.post("/api/target/reset")
async def reset_target():
    reset_db()
    await clear_db()
    ACTIVE_EVENT_QUEUES.clear()
    cfg = get_target_config()
    update_target_config(
        defect_a=cfg.defect_a,
        defect_b=cfg.defect_b,
        defect_c=cfg.defect_c,
        patched_mode=False
    )
    return {"status": "target_reset_success", "patched_mode": False}

@app.get("/api/target/status")
def get_target_status():
    cfg = get_target_config()
    return {
        "patched_mode": cfg.patched_mode,
        "defect_a": cfg.defect_a,
        "defect_b": cfg.defect_b,
        "defect_c": cfg.defect_c
    }

@app.get("/api/benchmark/latest")
async def get_latest_benchmark():
    """Stored benchmark results; does not re-run or reset the live target."""
    path = Path(__file__).resolve().parents[2] / "benchmarks" / "results.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="No benchmark results found. Run POST /api/benchmark/run first.")

@app.post("/api/benchmark/run")
async def execute_benchmark_run():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as asgi_client:
        return await run_benchmark("http://127.0.0.1:8000/target", client=asgi_client)

@app.post("/api/remediate")
async def remediate_vulnerability(payload: Dict[str, Any]):
    return await RemediationEngine().generate_remediation(payload)

@app.get("/api/remediate/status")
async def get_remediation_status():
    return await RemediationEngine().get_status()

@app.post("/api/remediate/test")
async def test_remediation_model():
    return await RemediationEngine().test_connection()

class TargetPatchInput(BaseModel):
    patched: bool = True

@app.post("/api/target/patch")
def apply_target_reference_patch(payload: Optional[TargetPatchInput] = None):
    patched = True if payload is None else payload.patched
    cfg = get_target_config()
    update_target_config(
        defect_a=cfg.defect_a,
        defect_b=cfg.defect_b,
        defect_c=cfg.defect_c,
        patched_mode=patched
    )
    return {
        "status": "target_patch_updated",
        "patched_mode": patched,
        "note": "Reference fix applied to demo target via patched_mode; model-generated patch is not auto-applied"
    }
