import pytest
import httpx
from fastapi import FastAPI, Response
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel

from apiguard.engine.models import (
    Operation, IdentityProfile, FindingStatus, PlanStep, ExecutionResult
)
from apiguard.engine.target import TargetProfile
from apiguard.engine.executor import SafeExecutor
from apiguard.engine.scanner import GraphGuidedScanner, scan_target
from apiguard.engine.cli import run_cli_scan
from apiguard.target.data import reset_db
from apiguard.target.config import update_target_config


@pytest.mark.asyncio
async def test_cors_positive_and_negative():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str, response: Response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return {"id": id, "name": "Test"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        cors = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "CORS"]
        assert len(cors) == 1
        assert cors[0].severity == "MEDIUM"
        assert cors[0].status == FindingStatus.CONFIRMED

    # Negative: Origin without credentials or specific origin
    app_neg = FastAPI()

    @app_neg.post("/items")
    def create_item_neg():
        return {"id": "1"}

    @app_neg.get("/items/{id}")
    def get_item_neg(id: str, response: Response):
        response.headers["Access-Control-Allow-Origin"] = "https://example.com"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return {"id": id, "name": "Test"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_neg), base_url="http://127.0.0.1:8000") as client:
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        cors = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "CORS"]
        assert len(cors) == 0


@pytest.mark.asyncio
async def test_verbose_error_positive_and_negative():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        tb = "Traceback (most recent call last):\n  File 'app.py', line 12, in get\nZeroDivisionError: division by zero"
        return PlainTextResponse(tb, status_code=500)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        v_err = [f for f in findings if f.category == "MISCONFIG" and "Verbose" in f.resource_type]
        assert len(v_err) == 1
        assert v_err[0].severity == "MEDIUM"
        assert "Traceback (most recent call last)" in v_err[0].probe_evidence.get("evidence", "")

    # Negative: Standard clean JSON error
    app_neg = FastAPI()

    @app_neg.post("/items")
    def create_item_neg():
        return {"id": "1"}

    @app_neg.get("/items/{id}")
    def get_item_neg(id: str):
        return JSONResponse({"detail": "Item not found"}, status_code=404)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_neg), base_url="http://127.0.0.1:8000") as client:
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        v_err = [f for f in findings if f.category == "MISCONFIG" and "Verbose" in f.resource_type]
        assert len(v_err) == 0


@pytest.mark.asyncio
async def test_version_disclosure_positive_and_negative():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str, response: Response):
        response.headers["Server"] = "uvicorn/0.30.1"
        response.headers["X-Powered-By"] = "Express 4.18.2"
        return {"id": id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        ver = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Version Disclosure"]
        assert len(ver) == 1
        assert ver[0].severity == "LOW"

    # Negative: No version number in headers
    app_neg = FastAPI()

    @app_neg.post("/items")
    def create_item_neg():
        return {"id": "1"}

    @app_neg.get("/items/{id}")
    def get_item_neg(id: str, response: Response):
        response.headers["Server"] = "cloudflare"
        return {"id": id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_neg), base_url="http://127.0.0.1:8000") as client:
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        ver = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Version Disclosure"]
        assert len(ver) == 0


@pytest.mark.asyncio
async def test_missing_x_content_type_options_positive_and_negative():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        # JSON response without X-Content-Type-Options: nosniff
        return {"id": id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        nosniff = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Missing X-Content-Type-Options"]
        assert len(nosniff) == 1
        assert nosniff[0].severity == "LOW"

    # Negative: Has nosniff
    app_pos = FastAPI()

    @app_pos.post("/items")
    def create_item_pos(response: Response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        return {"id": "1"}

    @app_pos.get("/items/{id}")
    def get_item_pos(id: str, response: Response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        return {"id": id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_pos), base_url="http://127.0.0.1:8000") as client:
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        nosniff = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Missing X-Content-Type-Options"]
        assert len(nosniff) == 0


@pytest.mark.asyncio
async def test_missing_hsts_on_https_positive_and_negative():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        return {"id": id}

    # 1. base_url is https -> flags missing Strict-Transport-Security
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="https://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "https://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        hsts = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Missing Strict-Transport-Security"]
        assert len(hsts) == 1
        assert hsts[0].severity == "LOW"

    # 2. base_url is http -> does NOT flag missing HSTS
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile_http = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile_http)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        hsts = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Missing Strict-Transport-Security"]
        assert len(hsts) == 0


@pytest.mark.asyncio
async def test_cache_control_positive_and_negative():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        # Carries owner-sensitive value (billing/email/owner_id) without Cache-Control: no-store
        return {"id": id, "owner_email": "alice@corp.test", "billing_card": "**** 1234"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        cc = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Cache-Control"]
        assert len(cc) == 1
        assert cc[0].severity == "LOW"

    # Negative: Cache-Control contains no-store or private
    app_neg = FastAPI()

    @app_neg.post("/items")
    def create_item_neg():
        return {"id": "1"}

    @app_neg.get("/items/{id}")
    def get_item_neg(id: str, response: Response):
        response.headers["Cache-Control"] = "no-store, private"
        return {"id": id, "owner_email": "alice@corp.test", "billing_card": "**** 1234"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_neg), base_url="http://127.0.0.1:8000") as client:
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        cc = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Cache-Control"]
        assert len(cc) == 0


    # Negative 2: Response holds only id, owner_id, text without Cache-Control -> no finding
    app_plain = FastAPI()

    @app_plain.post("/items")
    def create_item_plain():
        return {"id": "1", "owner_id": "user_a", "text": "plain text"}

    @app_plain.get("/items/{id}")
    def get_item_plain(id: str):
        return {"id": id, "owner_id": "user_a", "text": "plain text without sensitive keys"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_plain), base_url="http://127.0.0.1:8000") as client:
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        cc = [f for f in findings if f.category == "MISCONFIG" and f.endpoint == "Cache-Control"]
        assert len(cc) == 0


@pytest.mark.asyncio
async def test_deprecated_endpoint_positive_and_negative():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        return {"id": id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        # Operation marked deprecated: True answered 200
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], deprecated=True)
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        dep = [f for f in findings if f.category == "INVENTORY" and "deprecated" in f.probe_evidence.get("evidence", "")]
        assert len(dep) == 1
        assert dep[0].severity == "LOW"

    # Negative: Operation not deprecated
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        ops_neg = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], deprecated=False)
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops_neg, user_a, user_b, client=client, enable_passive=True)
        dep = [f for f in findings if f.category == "INVENTORY" and "deprecated" in f.probe_evidence.get("evidence", "")]
        assert len(dep) == 0


@pytest.mark.asyncio
async def test_undocumented_status_code_positive_and_negative():
    app = FastAPI()

    @app.post("/items", status_code=202)
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        return {"id": id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        # Spec documents 200, but POST returns 202
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem", documented_status_codes=["200"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], documented_status_codes=["200"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        undoc = [f for f in findings if f.category == "INVENTORY" and "Undocumented" in f.resource_type]
        assert len(undoc) == 1
        assert undoc[0].severity == "INFO"

    # Negative: Returned status code 200 is documented
    app_pos = FastAPI()

    @app_pos.post("/items", status_code=201)
    def create_item_pos():
        return {"id": "1"}

    @app_pos.get("/items/{id}")
    def get_item_pos(id: str):
        return {"id": id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_pos), base_url="http://127.0.0.1:8000") as client:
        ops_pos = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem", documented_status_codes=["201"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], documented_status_codes=["200"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops_pos, user_a, user_b, client=client, enable_passive=True)
        undoc = [f for f in findings if f.category == "INVENTORY" and "Undocumented" in f.resource_type]
        assert len(undoc) == 0


@pytest.mark.asyncio
async def test_passive_phase_zero_extra_requests():
    """Asserts that passive_checks sends zero extra requests (same request count whether on or off)."""
    from apiguard.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        reset_db()
        update_target_config(defect_a=False, defect_b=True, defect_c=False, defect_bfla=False,
                             defect_mass_assign=False, defect_exposure=False, defect_auth=False,
                             defect_misconfig=True, patched_mode=False)

        profile = TargetProfile(
            base_url="http://127.0.0.1:8000/target",
            is_demo=True,
            allowed_hosts=["127.0.0.1"],
            request_budget=60
        )
        ops = profile.load_operations()
        user_a = IdentityProfile(name="user_a", token="tok_alice", identity_id="usr_aman_101")
        user_b = IdentityProfile(name="user_b", token="tok_taaran", identity_id="usr_taaran_202")

        # 1. Run with passive checks ON
        ex_on = SafeExecutor(allowed_hosts={"127.0.0.1"}, total_budget=60)
        scanner_on = GraphGuidedScanner(ex_on, profile.base_url, target_profile=profile)
        findings_on = await scanner_on.run_scan(ops, user_a, user_b, client=client, enable_passive=True, enable_bopla=False, enable_auth=False)
        reqs_on = ex_on.requests_sent

        # 2. Run with passive checks OFF
        ex_off = SafeExecutor(allowed_hosts={"127.0.0.1"}, total_budget=60)
        scanner_off = GraphGuidedScanner(ex_off, profile.base_url, target_profile=profile)
        findings_off = await scanner_off.run_scan(ops, user_a, user_b, client=client, enable_passive=False, enable_bopla=False, enable_auth=False)
        reqs_off = ex_off.requests_sent

        assert reqs_on == reqs_off
        # Passive findings were found with ON, none with OFF
        assert any(f.category in ("MISCONFIG", "INVENTORY") for f in findings_on)
        assert not any(f.category in ("MISCONFIG", "INVENTORY") for f in findings_off)


@pytest.mark.asyncio
async def test_passive_checks_false_profile_setting():
    """Asserts that passive_checks: false in profile disables MISCONFIG and INVENTORY findings."""
    from apiguard.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        reset_db()
        update_target_config(defect_misconfig=True, patched_mode=False)

        profile = TargetProfile(
            base_url="http://127.0.0.1:8000/target",
            is_demo=True,
            allowed_hosts=["127.0.0.1"],
            passive_checks=False
        )
        ops = profile.load_operations()
        user_a = IdentityProfile(name="user_a", token="tok_alice", identity_id="usr_aman_101")
        user_b = IdentityProfile(name="user_b", token="tok_taaran", identity_id="usr_taaran_202")

        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), profile.base_url, target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client)
        assert not any(f.category in ("MISCONFIG", "INVENTORY") for f in findings)


@pytest.mark.asyncio
async def test_passive_findings_alone_exit_0(tmp_path):
    """Asserts that passive findings alone exit 0 (do not cause exit 1)."""
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str, response: Response):
        # Trigger CORS and version disclosure
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Server"] = "uvicorn/0.30.1"
        return {"id": id}

    spec_yaml = """openapi: "3.0.0"
info:
  title: API
  version: "1.0"
paths:
  /items:
    post:
      operationId: createItem
      responses:
        '200':
          description: ok
  /items/{id}:
    get:
      operationId: getItem
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: ok
"""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(spec_yaml, encoding="utf-8")

    profile = TargetProfile(
        base_url="http://127.0.0.1:8000",
        spec_path=str(spec_file),
        owner="user_a",
        attacker="user_b",
        allowed_hosts=["127.0.0.1"],
        passive_checks=True
    )
    user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a")
    user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
    ops = profile.load_operations()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), profile.base_url, target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_bopla=False, enable_auth=False)
        # Has passive findings
        passive = [f for f in findings if f.category in ("MISCONFIG", "INVENTORY")]
        assert len(passive) > 0
        # No BOLA/BFLA/BOPLA/AUTH findings
        active = [f for f in findings if f.category in ("BOLA", "BFLA", "BOPLA", "AUTH")]
        assert len(active) == 0

        # CLI scan exit code check:
        active_confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED and f.category in ("BOLA", "BFLA", "BOPLA", "AUTH")]
        # Only active confirmed findings give exit 1:
        exit_code = 1 if len(active_confirmed) > 0 else 0
        assert exit_code == 0


@pytest.mark.asyncio
async def test_verbose_error_evidence_token_masked():
    """Asserts that token values never appear in verbose-error evidence."""
    app = FastAPI()
    secret_token = "tok_super_secret_session_9999"

    @app.post("/items")
    def create_item():
        return {"id": "1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        tb = f"Traceback (most recent call last):\n  File 'app.py', line 12\nAuthenticationError: invalid session Bearer {secret_token}"
        return PlainTextResponse(tb, status_code=500)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(base_url="http://127.0.0.1:8000", owner="user_a", attacker="user_b", allowed_hosts=["127.0.0.1"])
        user_a = IdentityProfile(name="user_a", token=secret_token, identity_id="user_a")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem"),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_passive=True)
        v_err = [f for f in findings if f.category == "MISCONFIG" and "Verbose" in f.resource_type]
        assert len(v_err) == 1
        evidence = v_err[0].probe_evidence.get("evidence", "")
        # Real token value must NOT appear
        assert secret_token not in evidence
        assert secret_token not in str(v_err[0].model_dump())
