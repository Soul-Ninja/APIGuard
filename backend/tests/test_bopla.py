import pytest
import httpx
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any

from apiguard.engine.models import Operation, FindingStatus, IdentityProfile
from apiguard.engine.target import TargetProfile, load_target_profile
from apiguard.engine.scanner import scan_target, GraphGuidedScanner
from apiguard.engine.executor import SafeExecutor
from apiguard.target.config import update_target_config
from apiguard.target.data import reset_db


@pytest.mark.asyncio
async def test_demo_bopla_toggles():
    from apiguard.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        # 1. Toggles ON: defect_mass_assign = True, defect_exposure = True
        reset_db()
        update_target_config(defect_a=False, defect_b=False, defect_c=False, defect_bfla=False,
                             defect_mass_assign=True, defect_exposure=True, patched_mode=False)

        profile = load_target_profile("backend/apiguard/targets/demo.yaml")
        findings_on = await scan_target(target_profile=profile, client=client, enable_bopla=True)
        bopla_findings = [f for f in findings_on if getattr(f, "category", "") == "BOPLA"]
        assert len(bopla_findings) >= 2

        ma_findings = [f for f in bopla_findings if f.endpoint == "/projects" and f.method == "POST"]
        assert len(ma_findings) == 1
        assert ma_findings[0].status == FindingStatus.CONFIRMED
        assert ma_findings[0].severity == "HIGH"
        assert "owner_id" in ma_findings[0].diff_fields or "role" in ma_findings[0].diff_fields

        exp_findings = [f for f in bopla_findings if f.endpoint == "/projects/{project_id}" and f.method == "GET"]
        assert len(exp_findings) == 1
        assert exp_findings[0].status == FindingStatus.CONFIRMED
        assert exp_findings[0].severity == "MEDIUM"
        assert any("password_hash" in df for df in exp_findings[0].diff_fields)
        assert any("***" in df for df in exp_findings[0].diff_fields)

        # 2. Toggles OFF
        reset_db()
        update_target_config(defect_a=False, defect_b=False, defect_c=False, defect_bfla=False,
                             defect_mass_assign=False, defect_exposure=False, patched_mode=False)

        findings_off = await scan_target(target_profile=profile, client=client, enable_bopla=True)
        bopla_findings_off = [f for f in findings_off if getattr(f, "category", "") == "BOPLA"]
        assert len(bopla_findings_off) == 0


@pytest.mark.asyncio
async def test_mass_assignment_persisted_confirmed():
    app = FastAPI()
    db = {}

    class ItemCreate(BaseModel):
        name: str
        model_config = {"extra": "allow"}

    @app.post("/items")
    def create_item(item: ItemCreate):
        data = item.model_dump()
        data["id"] = "item_1"
        db["item_1"] = data
        return data

    @app.get("/items/{id}")
    def get_item(id: str):
        return db.get(id, {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem",
                      request_schema={"type": "object", "properties": {"name": {"type": "string"}}}),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"],
                      response_schemas={"200": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}})
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_bopla=True)
        ma = [f for f in findings if getattr(f, "category", "") == "BOPLA" and f.method == "POST"]
        assert len(ma) == 1
        assert ma[0].status == FindingStatus.CONFIRMED
        assert "role" in ma[0].diff_fields or "is_admin" in ma[0].diff_fields


@pytest.mark.asyncio
async def test_mass_assignment_ignored_no_finding():
    app = FastAPI()
    db = {}

    class ItemCreate(BaseModel):
        name: str
        model_config = {"extra": "allow"}

    @app.post("/items")
    def create_item(item: ItemCreate):
        # Strict server: only stores documented 'name'
        data = {"id": "item_1", "name": item.name}
        db["item_1"] = data
        return data

    @app.get("/items/{id}")
    def get_item(id: str):
        return db.get(id, {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem",
                      request_schema={"type": "object", "properties": {"name": {"type": "string"}}}),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"],
                      response_schemas={"200": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}})
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_bopla=True)
        ma = [f for f in findings if getattr(f, "category", "") == "BOPLA" and f.method == "POST"]
        assert len(ma) == 0


@pytest.mark.asyncio
async def test_mass_assignment_echoed_potential():
    app = FastAPI()
    db = {}

    class ItemCreate(BaseModel):
        name: str
        model_config = {"extra": "allow"}

    @app.post("/items")
    def create_item(item: ItemCreate):
        # Echoes extra fields in create response, but does NOT persist them in db
        data = {"id": "item_1", "name": item.name}
        db["item_1"] = data
        return item.model_dump() | {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        return db.get(id, {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem",
                      request_schema={"type": "object", "properties": {"name": {"type": "string"}}}),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"],
                      response_schemas={"200": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}})
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_bopla=True)
        ma = [f for f in findings if getattr(f, "category", "") == "BOPLA" and f.method == "POST"]
        assert len(ma) == 1
        assert ma[0].status == FindingStatus.POTENTIAL
        assert ma[0].confidence <= 0.5


@pytest.mark.asyncio
async def test_mass_assignment_documented_writable_no_finding():
    app = FastAPI()
    db = {}

    class ItemCreate(BaseModel):
        name: str
        role: Optional[str] = None
        is_admin: Optional[bool] = None
        owner_id: Optional[str] = None

    @app.post("/items")
    def create_item(item: ItemCreate):
        data = item.model_dump()
        data["id"] = "item_1"
        db["item_1"] = data
        return data

    @app.get("/items/{id}")
    def get_item(id: str):
        return db.get(id, {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        # Spec documents role, is_admin, owner_id as writable properties
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem",
                      request_schema={"type": "object", "properties": {
                          "name": {"type": "string"},
                          "role": {"type": "string"},
                          "is_admin": {"type": "boolean"},
                          "owner_id": {"type": "string"}
                      }}),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"],
                      response_schemas={"200": {"type": "object", "properties": {
                          "id": {"type": "string"},
                          "name": {"type": "string"},
                          "role": {"type": "string"},
                          "is_admin": {"type": "boolean"},
                          "owner_id": {"type": "string"}
                      }}})
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_bopla=True)
        ma = [f for f in findings if getattr(f, "category", "") == "BOPLA" and f.method == "POST"]
        assert len(ma) == 0


@pytest.mark.asyncio
async def test_excessive_data_exposure_undocumented_password_hash():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        return {
            "id": id,
            "username": "alice",
            "password_hash": "$2b$12$e8YQJ8N6mU5J2hK1.m3jLu"
        }

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem",
                      request_schema={"type": "object", "properties": {"name": {"type": "string"}}}),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"],
                      response_schemas={"200": {"type": "object", "properties": {"id": {"type": "string"}, "username": {"type": "string"}}}})
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_bopla=True)
        exp = [f for f in findings if getattr(f, "category", "") == "BOPLA" and "password_hash" in str(f.diff_fields)]
        assert len(exp) == 1
        assert exp[0].status == FindingStatus.CONFIRMED
        assert exp[0].severity == "MEDIUM"
        assert "$2b$" not in str(exp[0].model_dump())
        assert "***" in exp[0].probe_evidence.get("preview", "")


@pytest.mark.asyncio
async def test_excessive_data_exposure_documented_sensitive_not_flagged():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        return {"id": id, "api_key": "live_secret_123"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem",
                      request_schema={"type": "object", "properties": {"name": {"type": "string"}}}),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"],
                      response_schemas={"200": {"type": "object", "properties": {"id": {"type": "string"}, "api_key": {"type": "string"}}}})
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_bopla=True)
        exp = [f for f in findings if getattr(f, "category", "") == "BOPLA"]
        assert len(exp) == 0


@pytest.mark.asyncio
async def test_excessive_data_exposure_no_response_schema_skip():
    app = FastAPI()

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str):
        return {"id": id, "secret_key": "secret"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem",
                      request_schema={"type": "object", "properties": {"name": {"type": "string"}}},
                      response_schemas={"200": {"type": "object", "properties": {"id": {"type": "string"}}}}),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"], response_schemas={})
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_bopla=True)
        exp = [f for f in findings if getattr(f, "category", "") == "BOPLA"]
        assert len(exp) == 0
        skips = [s for s in scanner.coverage.skipped if "no documented response schema" in s.reason]
        assert len(skips) == 1


@pytest.mark.asyncio
async def test_patch_injection_not_sent_without_mutations():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "name": "Item 1"}}

    class ItemPatch(BaseModel):
        name: Optional[str] = None
        model_config = {"extra": "allow"}

    @app.post("/items")
    def create_item(item: ItemPatch):
        data = item.model_dump()
        data["id"] = "item_1"
        db["item_1"] = data
        return data

    @app.get("/items/{id}")
    def get_item(id: str):
        return db.get(id, {})

    @app.patch("/items/{id}")
    def patch_item(id: str, patch: ItemPatch):
        db[id].update(patch.model_dump(exclude_unset=True))
        return db[id]

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_a", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem",
                      request_schema={"type": "object", "properties": {"name": {"type": "string"}}}),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"],
                      response_schemas={"200": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}})
            ,
            Operation(id="3", method="PATCH", path="/items/{id}", operation_id="patchItem",
                      path_params=["id"],
                      request_schema={"type": "object", "properties": {"name": {"type": "string"}}})
        ]

        # 1. Without mutations: PATCH injection skipped
        scanner_no_mut = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}, enable_mutations=False), "http://127.0.0.1:8000", target_profile=profile)
        findings_no_mut = await scanner_no_mut.run_scan(ops, user_a, user_b, enable_mutations=False, client=client, enable_bopla=True)
        patch_skips = [s for s in scanner_no_mut.coverage.skipped if "Mass Assignment: PATCH" in s.resource and "--mutations not set" in s.reason]
        assert len(patch_skips) == 1

        # 2. With mutations: PATCH injection executed and finds mass assignment
        scanner_mut = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}, enable_mutations=True), "http://127.0.0.1:8000", target_profile=profile)
        findings_mut = await scanner_mut.run_scan(ops, user_a, user_b, enable_mutations=True, client=client, enable_bopla=True)
        patch_f = [f for f in findings_mut if f.method == "PATCH" and getattr(f, "category", "") == "BOPLA"]
        assert len(patch_f) == 1
        assert patch_f[0].status == FindingStatus.CONFIRMED


@pytest.mark.asyncio
async def test_no_secret_or_token_leaked_in_bopla_findings():
    from apiguard.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        reset_db()
        update_target_config(defect_a=False, defect_b=False, defect_c=False, defect_bfla=False,
                             defect_mass_assign=True, defect_exposure=True, patched_mode=False)

        profile = load_target_profile("backend/apiguard/targets/demo.yaml")
        findings = await scan_target(target_profile=profile, client=client, enable_bopla=True)
        bopla_findings = [f for f in findings if getattr(f, "category", "") == "BOPLA"]
        assert len(bopla_findings) > 0

        for f in bopla_findings:
            dumped = f.model_dump()
            repro = dumped.get("repro_curl", "")
            steps = " ".join(dumped.get("reproduction_steps", []))
            diffs = " ".join(dumped.get("diff_fields", []))
            combined = f"{repro} {steps} {diffs}"

            assert "eyJ" not in combined  # JWT prefix
            assert "argon2" not in combined  # raw hash
            assert "$2b$" not in combined  # bcrypt hash
            if f.method == "POST":
                assert "<USER_A_TOKEN>" in repro or "<TOKEN>" in repro
