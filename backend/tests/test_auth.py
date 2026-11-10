import pytest
import httpx
import json
import base64
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any

from apiguard.engine.models import Operation, FindingStatus, IdentityProfile
from apiguard.engine.target import TargetProfile, load_target_profile
from apiguard.engine.scanner import scan_target, GraphGuidedScanner, is_jwt, make_alg_none_jwt, make_altered_sig_jwt
from apiguard.engine.executor import SafeExecutor
from apiguard.target.config import update_target_config
from apiguard.target.data import reset_db


def test_jwt_helpers():
    # Valid JWT structure
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(b'{"sub":"user123"}').decode().rstrip("=")
    sig = "valid_signature_123"
    token = f"{h}.{p}.{sig}"

    assert is_jwt(token) is True
    assert is_jwt("tok_opaque_string") is False
    assert is_jwt(None) is False
    assert is_jwt("bad.token") is False

    alg_none = make_alg_none_jwt(token)
    assert alg_none.endswith(".")
    parts = alg_none.split(".")
    assert len(parts) == 3
    decoded_h = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert decoded_h.get("alg") == "none"

    altered = make_altered_sig_jwt(token)
    assert altered != token
    assert altered.split(".")[2] != sig


@pytest.mark.asyncio
async def test_demo_variant_auth():
    from apiguard.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        # 1. Defect ON
        reset_db()
        update_target_config(defect_a=False, defect_b=False, defect_c=False, defect_bfla=False,
                             defect_mass_assign=False, defect_exposure=False, defect_auth=True, patched_mode=False)

        profile = load_target_profile("backend/apiguard/targets/demo.yaml")
        findings_on = await scan_target(target_profile=profile, client=client, enable_auth=True)
        auth_findings = [f for f in findings_on if getattr(f, "category", "") == "AUTH"]
        assert len(auth_findings) >= 1
        summary_f = [f for f in auth_findings if "/summary" in f.endpoint]
        assert len(summary_f) == 1
        assert summary_f[0].status == FindingStatus.CONFIRMED
        assert summary_f[0].severity == "HIGH"
        assert any("No Authorization header" in d for d in summary_f[0].diff_fields)

        # 2. Defect OFF
        reset_db()
        update_target_config(defect_a=False, defect_b=False, defect_c=False, defect_bfla=False,
                             defect_mass_assign=False, defect_exposure=False, defect_auth=False, patched_mode=False)

        findings_off = await scan_target(target_profile=profile, client=client, enable_auth=True)
        auth_findings_off = [f for f in findings_off if getattr(f, "category", "") == "AUTH"]
        assert len(auth_findings_off) == 0


@pytest.mark.asyncio
async def test_tampering_no_auth_confirmed():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "data": "val"}}

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str, authorization: Optional[str] = Header(None)):
        # Accepts request without authorization!
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
                      security_schemes=["bearerAuth"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem",
                      path_params=["id"], security_schemes=["bearerAuth"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        assert len(auth_f) >= 1
        no_auth_f = [f for f in auth_f if any("No Authorization header" in d for d in f.diff_fields)]
        assert len(no_auth_f) == 1
        assert no_auth_f[0].status == FindingStatus.CONFIRMED


@pytest.mark.asyncio
async def test_tampering_garbage_token_confirmed():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "data": "val"}}

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str, authorization: Optional[str] = Header(None)):
        # Accepts garbage token or valid token, rejects missing header
        if not authorization:
            raise HTTPException(status_code=401, detail="Unauthorized")
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
            Operation(id="1", method="POST", path="/items", operation_id="createItem", security_schemes=["bearerAuth"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], security_schemes=["bearerAuth"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        garbage_f = [f for f in auth_f if any("Garbage Bearer token" in d for d in f.diff_fields)]
        assert len(garbage_f) == 1
        assert garbage_f[0].status == FindingStatus.CONFIRMED


@pytest.mark.asyncio
async def test_tampering_alg_none_and_altered_jwt():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "data": "val"}}

    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(b'{"sub":"user_a"}').decode().rstrip("=")
    valid_jwt = f"{h}.{p}.secret_sig"

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str, authorization: Optional[str] = Header(None)):
        if not authorization:
            raise HTTPException(status_code=401, detail="Unauthorized")
        token = authorization.replace("Bearer ", "").strip()
        parts = token.split(".")
        if len(parts) == 3:
            h_json = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            # Vulnerable to alg:none
            if h_json.get("alg") == "none":
                return db.get(id, {})
            # Vulnerable if signature contains 'tampered'
            if "tampered" in parts[2]:
                return db.get(id, {})
            if parts[2] == "secret_sig":
                return db.get(id, {})
        raise HTTPException(status_code=401, detail="Unauthorized")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token=valid_jwt, identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem", security_schemes=["bearerAuth"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], security_schemes=["bearerAuth"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        alg_none_f = [f for f in auth_f if any("alg:none" in d for d in f.diff_fields)]
        assert len(alg_none_f) == 1
        assert alg_none_f[0].status == FindingStatus.CONFIRMED

        altered_f = [f for f in auth_f if any("Altered signature" in d for d in f.diff_fields)]
        assert len(altered_f) == 1
        assert altered_f[0].status == FindingStatus.CONFIRMED


@pytest.mark.asyncio
async def test_tampering_expired_token_confirmed():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "data": "val"}}

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str, authorization: Optional[str] = Header(None)):
        if not authorization:
            raise HTTPException(status_code=401, detail="Unauthorized")
        token = authorization.replace("Bearer ", "").strip()
        # Vulnerable: accepts expired token without checking exp
        if token in {"tok_valid", "tok_expired_old"}:
            return db.get(id, {})
        raise HTTPException(status_code=401, detail="Unauthorized")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_valid", expired_token="tok_expired_old", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem", security_schemes=["bearerAuth"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], security_schemes=["bearerAuth"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        exp_f = [f for f in auth_f if any("Expired token" in d for d in f.diff_fields)]
        assert len(exp_f) == 1
        assert exp_f[0].status == FindingStatus.CONFIRMED


@pytest.mark.asyncio
async def test_secure_endpoint_401_no_finding():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "data": "val"}}

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str, authorization: Optional[str] = Header(None)):
        if authorization != "Bearer tok_valid":
            raise HTTPException(status_code=401, detail="Unauthorized")
        return db.get(id, {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_valid", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem", security_schemes=["bearerAuth"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], security_schemes=["bearerAuth"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        assert len(auth_f) == 0


@pytest.mark.asyncio
async def test_soft_200_error_potential():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "data": "val"}}

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str, authorization: Optional[str] = Header(None)):
        if authorization != "Bearer tok_valid":
            # Soft-200 with error payload
            return {"error": "unauthorized", "detail": "invalid token provided"}
        return db.get(id, {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_valid", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem", security_schemes=["bearerAuth"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], security_schemes=["bearerAuth"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        assert len(auth_f) > 0
        for f in auth_f:
            assert f.status == FindingStatus.POTENTIAL
            assert f.confidence <= 0.50


@pytest.mark.asyncio
async def test_public_endpoint_skipped():
    app = FastAPI()

    @app.get("/public")
    def get_public():
        return {"public": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_valid", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="GET", path="/public", operation_id="getPublic", is_public=True)
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        assert len(auth_f) == 0
        skips = [s for s in scanner.coverage.skipped if "marked public in spec" in s.reason]
        assert len(skips) == 1


@pytest.mark.asyncio
async def test_non_jwt_token_skips_jwt_checks():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "data": "val"}}

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str, authorization: Optional[str] = Header(None)):
        return db.get(id, {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_opaque_string", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem", security_schemes=["bearerAuth"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], security_schemes=["bearerAuth"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        # Only no_auth and garbage_token should be tested, NOT JWT checks
        assert not any("alg:none" in str(f.diff_fields) for f in auth_f)
        assert not any("Altered signature" in str(f.diff_fields) for f in auth_f)


@pytest.mark.asyncio
async def test_auth_checks_false_nothing_sent():
    app = FastAPI()
    db = {"item_1": {"id": "item_1", "data": "val"}}

    @app.post("/items")
    def create_item():
        return {"id": "item_1"}

    @app.get("/items/{id}")
    def get_item(id: str, authorization: Optional[str] = Header(None)):
        return db.get(id, {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        profile = TargetProfile(
            base_url="http://127.0.0.1:8000",
            owner="user_a",
            attacker="user_b",
            auth_checks=False,
            allowed_hosts=["127.0.0.1"]
        )
        user_a = IdentityProfile(name="user_a", token="tok_valid", identity_id="user_a_id")
        user_b = IdentityProfile(name="user_b", token="tok_b", identity_id="user_b_id")
        ops = [
            Operation(id="1", method="POST", path="/items", operation_id="createItem", security_schemes=["bearerAuth"]),
            Operation(id="2", method="GET", path="/items/{id}", operation_id="getItem", path_params=["id"], security_schemes=["bearerAuth"])
        ]
        scanner = GraphGuidedScanner(SafeExecutor(allowed_hosts={"127.0.0.1"}), "http://127.0.0.1:8000", target_profile=profile)
        findings = await scanner.run_scan(ops, user_a, user_b, client=client, enable_auth=True)
        auth_f = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        assert len(auth_f) == 0
        assert len(scanner.coverage.auth_operations_tested) == 0


@pytest.mark.asyncio
async def test_no_token_in_auth_findings():
    from apiguard.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        reset_db()
        update_target_config(defect_a=False, defect_b=False, defect_c=False, defect_bfla=False,
                             defect_mass_assign=False, defect_exposure=False, defect_auth=True, patched_mode=False)

        profile = load_target_profile("backend/apiguard/targets/demo.yaml")
        findings = await scan_target(target_profile=profile, client=client, enable_auth=True)
        auth_findings = [f for f in findings if getattr(f, "category", "") == "AUTH"]
        assert len(auth_findings) > 0

        for f in auth_findings:
            dumped = f.model_dump()
            repro = dumped.get("repro_curl", "")
            steps = " ".join(dumped.get("reproduction_steps", []))
            diffs = " ".join(dumped.get("diff_fields", []))
            evidence = str(dumped.get("control_evidence", {})) + str(dumped.get("probe_evidence", {}))
            combined = f"{repro} {steps} {diffs} {evidence}"

            assert "tok_live" not in combined
            assert "invalid" not in repro  # Repro curl must use <GARBAGE_TOKEN> placeholder
            assert "eyJ" not in combined
