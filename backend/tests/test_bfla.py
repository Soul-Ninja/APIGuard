import pytest
import httpx
from apiguard.engine.models import Operation, IdentityProfile
from apiguard.engine.target import TargetProfile, is_admin_operation, load_target_profile
from apiguard.engine.scanner import scan_target
from apiguard.engine.cli import run_cli_scan
from apiguard.target.config import update_target_config
from apiguard.target.data import reset_db


def test_rule1_admin_operations_operation_id():
    profile = TargetProfile(
        base_url="http://127.0.0.1:8000",
        admin_operations=["get_secret_vault", "purge*"]
    )
    op1 = Operation(id="1", method="GET", path="/vault", operation_id="get_secret_vault")
    op2 = Operation(id="2", method="POST", path="/data", operation_id="purge_all_records")
    op3 = Operation(id="3", method="GET", path="/public", operation_id="get_public_feed")

    assert is_admin_operation(op1, profile) is True
    assert is_admin_operation(op2, profile) is True
    assert is_admin_operation(op3, profile) is False


def test_rule1_admin_operations_method_path_globs():
    profile = TargetProfile(
        base_url="http://127.0.0.1:8000",
        admin_operations=["POST /internal/*", "DELETE /config/*", "/system/reboot"]
    )
    op1 = Operation(id="1", method="POST", path="/internal/reset", operation_id="resetInternal")
    op2 = Operation(id="2", method="GET", path="/internal/reset", operation_id="getInternal")
    op3 = Operation(id="3", method="DELETE", path="/config/keys", operation_id="delKey")
    op4 = Operation(id="4", method="POST", path="/system/reboot", operation_id="rebootSystem")

    assert is_admin_operation(op1, profile) is True
    assert is_admin_operation(op2, profile) is False  # method is GET, pattern was POST
    assert is_admin_operation(op3, profile) is True
    assert is_admin_operation(op4, profile) is True


def test_rule2_admin_path_segment():
    profile = TargetProfile(base_url="http://127.0.0.1:8000")
    op1 = Operation(id="1", method="GET", path="/admin/users", operation_id="getUsers")
    op2 = Operation(id="2", method="POST", path="/api/v1/admin/settings", operation_id="setSettings")
    op3 = Operation(id="3", method="GET", path="/administrator/dashboard", operation_id="getDashboard")
    op4 = Operation(id="4", method="GET", path="/projects/admin-guide", operation_id="getGuide")

    assert is_admin_operation(op1, profile) is True
    assert is_admin_operation(op2, profile) is True
    assert is_admin_operation(op3, profile) is False  # 'administrator' is not 'admin' segment
    assert is_admin_operation(op4, profile) is False  # 'admin-guide' is not 'admin' segment


def test_rule3_openapi_tag_admin():
    profile = TargetProfile(base_url="http://127.0.0.1:8000")
    op1 = Operation(id="1", method="GET", path="/users/manage", operation_id="manageUsers", tags=["admin"])
    op2 = Operation(id="2", method="GET", path="/system/stats", operation_id="getStats", tags=["Admin", "metrics"])
    op3 = Operation(id="3", method="GET", path="/projects", operation_id="getProjects", tags=["projects"])

    assert is_admin_operation(op1, profile) is True
    assert is_admin_operation(op2, profile) is True
    assert is_admin_operation(op3, profile) is False


@pytest.mark.asyncio
async def test_demo_bfla_toggle_on_and_off():
    from apiguard.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        # 1. Toggle ON: defect_bfla = True
        reset_db()
        update_target_config(defect_a=False, defect_b=False, defect_c=False, defect_bfla=True, patched_mode=False)

        profile = load_target_profile("backend/apiguard/targets/demo.yaml")
        findings_on = await scan_target(target_profile=profile, client=client)
        bfla_findings_on = [f for f in findings_on if getattr(f, "category", "") == "BFLA"]
        assert len(bfla_findings_on) == 1
        f = bfla_findings_on[0]
        assert f.endpoint == "/admin/users"
        assert f.method == "GET"
        assert f.severity == "HIGH"
        assert f.status.value == "confirmed"

        # 2. Toggle OFF: defect_bfla = False
        reset_db()
        update_target_config(defect_a=False, defect_b=False, defect_c=False, defect_bfla=False, patched_mode=False)

        findings_off = await scan_target(target_profile=profile, client=client)
        bfla_findings_off = [f for f in findings_off if getattr(f, "category", "") == "BFLA"]
        assert len(bfla_findings_off) == 0


@pytest.mark.asyncio
async def test_missing_admin_identity_skips_bfla(tmp_path, capsys):
    """
    If admin identity is missing from profile identities, print note and skip BFLA;
    exit code is not an error and does not change.
    """
    spec = """
openapi: 3.0.3
info:
  title: Test API
  version: 1.0.0
paths:
  /admin/stats:
    get:
      operationId: getAdminStats
      tags: [admin]
      responses:
        '200':
          description: OK
"""
    spec_file = tmp_path / "admin_spec.yaml"
    spec_file.write_text(spec, encoding="utf-8")

    profile_content = f"""
base_url: "http://127.0.0.1:59999"
spec_path: "{spec_file.as_posix()}"
allowed_hosts:
  - "127.0.0.1"
owner: "user_a"
attacker: "user_b"
admin: "missing_admin_user"
identities:
  - name: "user_a"
  - name: "user_b"
"""
    profile_file = tmp_path / "missing_admin.yaml"
    profile_file.write_text(profile_content, encoding="utf-8")

    # In dry-run, missing admin prints note and exits 0 cleanly
    code = await run_cli_scan(dry_run=True, profile_path=str(profile_file))
    assert code == 0

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "Admin identity 'missing_admin_user' not found; skipping BFLA scan" in combined


@pytest.mark.asyncio
async def test_no_identity_tokens_in_any_findings():
    from apiguard.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        reset_db()
        update_target_config(defect_a=True, defect_b=True, defect_c=True, defect_bfla=True, patched_mode=False)

        profile = load_target_profile("backend/apiguard/targets/demo.yaml")
        findings = await scan_target(target_profile=profile, client=client)
        assert len(findings) > 0

        secret_tokens = ["tok_demo_a", "tok_demo_b", "tok_demo_admin", "dev_secret_jwt"]
        for f in findings:
            for tok in secret_tokens:
                assert tok not in f.repro_curl, f"Token {tok} leaked in repro_curl of {f.id}"
                for step in f.reproduction_steps:
                    assert tok not in step, f"Token {tok} leaked in reproduction_steps of {f.id}"
            if f.category == "BFLA" or "Bearer" in f.repro_curl:
                assert "<USER_B_TOKEN>" in f.repro_curl or "<TOKEN>" in f.repro_curl


@pytest.mark.asyncio
async def test_admin_path_parameters_harvested_vs_unharvested():
    from fastapi import FastAPI, Header, HTTPException
    from apiguard.engine.executor import SafeExecutor
    from apiguard.engine.scanner import GraphGuidedScanner

    app = FastAPI()
    items_db = {}

    @app.post("/items")
    def create_item():
        items_db["itm-999"] = {"id": "itm-999", "name": "secret-widget"}
        return {"id": "itm-999", "name": "secret-widget"}

    @app.get("/items/{id}")
    def get_item(id: str):
        return items_db.get(id, {"id": id})

    @app.get("/admin/items/{id}")
    def admin_item(id: str, authorization: str = Header(None)):
        if id != "itm-999":
            raise HTTPException(status_code=404, detail="not found")
        return {"id": id, "admin_data": "secret"}

    @app.get("/admin/tenants/{tenant_id}")
    def admin_tenant(tenant_id: str, authorization: str = Header(None)):
        return {"tenant_id": tenant_id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        executor = SafeExecutor(allowed_hosts={"127.0.0.1"}, total_budget=30, enable_mutations=True)
        scanner = GraphGuidedScanner(executor=executor, base_url="http://127.0.0.1:8000")

        ops = [
            Operation(id="create_item", method="POST", path="/items", operation_id="create_item"),
            Operation(id="get_item", method="GET", path="/items/{id}", operation_id="get_item", path_params=["id"]),
            Operation(id="admin_item", method="GET", path="/admin/items/{id}", operation_id="admin_item", path_params=["id"]),
            Operation(id="admin_tenant", method="GET", path="/admin/tenants/{tenant_id}", operation_id="admin_tenant", path_params=["tenant_id"]),
        ]

        user_a = IdentityProfile(identity_id="user_a", token="tok_a")
        user_b = IdentityProfile(identity_id="user_b", token="tok_b")
        admin = IdentityProfile(identity_id="admin", token="tok_admin")

        findings = await scanner.run_scan(operations=ops, user_a=user_a, user_b=user_b, admin_user=admin, client=client)

        assert "GET /admin/tenants/{tenant_id}" not in scanner.coverage.admin_operations_tested
        skip_tenant = next((s for s in scanner.coverage.skipped if s.resource == "GET /admin/tenants/{tenant_id}"), None)
        assert skip_tenant is not None
        assert "needs path parameter tenant_id" in skip_tenant.reason

        assert "GET /admin/items/{id}" in scanner.coverage.admin_operations_tested


@pytest.mark.asyncio
async def test_admin_control_non_2xx_recorded_as_skip():
    from fastapi import FastAPI, Header, HTTPException
    from apiguard.engine.executor import SafeExecutor
    from apiguard.engine.scanner import GraphGuidedScanner

    app = FastAPI()

    @app.get("/admin/restricted")
    def restricted_admin(authorization: str = Header(None)):
        raise HTTPException(status_code=403, detail="Super-admin only")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        executor = SafeExecutor(allowed_hosts={"127.0.0.1"}, total_budget=30)
        scanner = GraphGuidedScanner(executor=executor, base_url="http://127.0.0.1:8000")

        ops = [
            Operation(id="restricted_admin", method="GET", path="/admin/restricted", operation_id="restricted_admin")
        ]

        user_a = IdentityProfile(identity_id="user_a", token="tok_a")
        user_b = IdentityProfile(identity_id="user_b", token="tok_b")
        admin = IdentityProfile(identity_id="admin", token="tok_admin")

        findings = await scanner.run_scan(operations=ops, user_a=user_a, user_b=user_b, admin_user=admin, client=client)

        assert "GET /admin/restricted" not in scanner.coverage.admin_operations_tested
        skip = next((s for s in scanner.coverage.skipped if s.resource == "GET /admin/restricted"), None)
        assert skip is not None
        assert "HTTP 403" in skip.reason
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_bfla_shape_verification_soft_200_and_empty():
    from fastapi import FastAPI, Header
    from apiguard.engine.executor import SafeExecutor
    from apiguard.engine.scanner import GraphGuidedScanner
    from apiguard.engine.models import FindingStatus

    app = FastAPI()

    @app.get("/admin/soft_error")
    def soft_error(authorization: str = Header(None)):
        if "admin" in (authorization or ""):
            return {"users": ["alice", "bob"], "total": 2}
        return {"error": "forbidden", "code": 403}

    @app.get("/admin/empty_list")
    def empty_list(authorization: str = Header(None)):
        if "admin" in (authorization or ""):
            return [{"id": "usr_1", "name": "alice"}, {"id": "usr_2", "name": "bob"}]
        return []

    @app.get("/admin/real_leak")
    def real_leak(authorization: str = Header(None)):
        return [{"id": "usr_1", "name": "alice"}, {"id": "usr_2", "name": "bob"}]

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        executor = SafeExecutor(allowed_hosts={"127.0.0.1"}, total_budget=30)
        scanner = GraphGuidedScanner(executor=executor, base_url="http://127.0.0.1:8000")

        ops = [
            Operation(id="soft_error", method="GET", path="/admin/soft_error", operation_id="soft_error"),
            Operation(id="empty_list", method="GET", path="/admin/empty_list", operation_id="empty_list"),
            Operation(id="real_leak", method="GET", path="/admin/real_leak", operation_id="real_leak"),
        ]

        user_a = IdentityProfile(identity_id="user_a", token="tok_a")
        user_b = IdentityProfile(identity_id="user_b", token="tok_b")
        admin = IdentityProfile(identity_id="admin", token="tok_admin")

        findings = await scanner.run_scan(operations=ops, user_a=user_a, user_b=user_b, admin_user=admin, client=client)

        f_soft = next(f for f in findings if f.endpoint == "/admin/soft_error")
        assert f_soft.status == FindingStatus.POTENTIAL
        assert f_soft.confidence <= 0.50

        f_empty = next(f for f in findings if f.endpoint == "/admin/empty_list")
        assert f_empty.status == FindingStatus.POTENTIAL
        assert f_empty.confidence <= 0.50

        f_leak = next(f for f in findings if f.endpoint == "/admin/real_leak")
        assert f_leak.status == FindingStatus.CONFIRMED
        assert f_leak.confidence >= 0.90
