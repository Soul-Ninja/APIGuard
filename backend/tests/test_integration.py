import pytest
import threading
import time
import uvicorn
import httpx
from apiguard.main import app
from apiguard.engine.spec import OpenAPIParser, DEMO_SPEC_YAML
from apiguard.engine.executor import SafeExecutor
from apiguard.engine.scanner import GraphGuidedScanner
from apiguard.engine.baseline import BaselineScanner
from apiguard.engine.auth import AuthRegistry
from apiguard.target.data import reset_db
from apiguard.target.config import update_target_config

TEST_PORT = 8124
TEST_HOST = "127.0.0.1"
BASE_URL = f"http://{TEST_HOST}:{TEST_PORT}/target"

class UvicornServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        config = uvicorn.Config(app, host=TEST_HOST, port=TEST_PORT, log_level="error")
        self.server = uvicorn.Server(config)
        self.daemon = True

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True

@pytest.fixture(scope="module")
def real_uvicorn_server():
    server_thread = UvicornServerThread()
    server_thread.start()

    client = httpx.Client(timeout=5.0)
    for _ in range(30):
        try:
            res = client.get(f"http://{TEST_HOST}:{TEST_PORT}/api/health")
            if res.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)

    yield BASE_URL
    server_thread.stop()

@pytest.mark.asyncio
async def test_dynamic_login_and_defect_b(real_uvicorn_server):
    """
    Asserts dynamic authentication via /auth/login and proves Defect B (export)
    is confirmed by graph scanner and missed by baseline.
    """
    reset_db()
    update_target_config(defect_a=False, defect_b=True, defect_c=False, patched_mode=False)

    auth_reg = AuthRegistry(real_uvicorn_server)
    identities = await auth_reg.authenticate_all()
    user_a = identities["user_a"]
    user_b = identities["user_b"]
    assert user_a.token.startswith("tok_live_")
    assert user_b.token.startswith("tok_live_")

    parser = OpenAPIParser(DEMO_SPEC_YAML)
    operations = parser.extract_operations()

    # 1. Graph scanner confirms Defect B
    executor = SafeExecutor(allowed_hosts={"127.0.0.1", "localhost"}, total_budget=30)
    graph_scanner = GraphGuidedScanner(executor, real_uvicorn_server)
    graph_findings = await graph_scanner.run_scan(operations, user_a, user_b)

    assert len(graph_findings) == 1
    f = graph_findings[0]
    assert f.endpoint == "/projects/{project_id}/export"
    assert f.status.value == "confirmed"
    assert "owner_email" in f.diff_fields or "financial_payload.billing" in f.diff_fields

    # 2. Baseline scanner misses Defect B
    base_exec = SafeExecutor(allowed_hosts={"127.0.0.1", "localhost"}, total_budget=30)
    baseline_scanner = BaselineScanner(base_exec, real_uvicorn_server)
    base_findings = await baseline_scanner.scan_operations(operations, user_a, user_b)
    assert len(base_findings) == 0

@pytest.mark.asyncio
async def test_defect_a_direct_bola(real_uvicorn_server):
    """
    Asserts Defect A (direct read on GET /projects/{project_id} vulnerable)
    is confirmed by both scanners.
    """
    reset_db()
    update_target_config(defect_a=True, defect_b=False, defect_c=False, patched_mode=False)

    auth_reg = AuthRegistry(real_uvicorn_server)
    identities = await auth_reg.authenticate_all()
    user_a = identities["user_a"]
    user_b = identities["user_b"]

    parser = OpenAPIParser(DEMO_SPEC_YAML)
    operations = parser.extract_operations()

    executor = SafeExecutor(allowed_hosts={"127.0.0.1", "localhost"}, total_budget=30)
    graph_scanner = GraphGuidedScanner(executor, real_uvicorn_server)
    findings = await graph_scanner.run_scan(operations, user_a, user_b)

    # Defect A confirmed on primary read
    assert any(f.endpoint == "/projects/{project_id}" and f.method == "GET" for f in findings)

@pytest.mark.asyncio
async def test_defect_c_mutation_patch(real_uvicorn_server):
    """
    Asserts Defect C (mutating PATCH without ownership) is confirmed when mutations are enabled.
    """
    reset_db()
    update_target_config(defect_a=False, defect_b=False, defect_c=True, patched_mode=False)

    auth_reg = AuthRegistry(real_uvicorn_server)
    identities = await auth_reg.authenticate_all()
    user_a = identities["user_a"]
    user_b = identities["user_b"]

    parser = OpenAPIParser(DEMO_SPEC_YAML)
    operations = parser.extract_operations()

    executor = SafeExecutor(allowed_hosts={"127.0.0.1", "localhost"}, total_budget=30, enable_mutations=True)
    graph_scanner = GraphGuidedScanner(executor, real_uvicorn_server)
    findings = await graph_scanner.run_scan(operations, user_a, user_b, enable_mutations=True)

    # Defect C confirmed on PATCH
    assert any(f.endpoint == "/projects/{project_id}" and f.method == "PATCH" for f in findings)

@pytest.mark.asyncio
async def test_zero_false_positives_when_secure_and_patched(real_uvicorn_server):
    """
    Asserts 0 findings when target is fully secure or in patched mode.
    The scans pass through the decoys the spec exposes: /summary (200 with an empty body) and
    /members (not implemented, so even the owner gets 404). Neither may be flagged.
    """
    auth_reg = AuthRegistry(real_uvicorn_server)
    identities = await auth_reg.authenticate_all()
    user_a = identities["user_a"]
    user_b = identities["user_b"]

    parser = OpenAPIParser(DEMO_SPEC_YAML)
    operations = parser.extract_operations()

    # Case 1: All secure configuration
    reset_db()
    update_target_config(defect_a=False, defect_b=False, defect_c=False, patched_mode=False)
    executor = SafeExecutor(allowed_hosts={"127.0.0.1", "localhost"}, total_budget=30, enable_mutations=True)
    graph_scanner = GraphGuidedScanner(executor, real_uvicorn_server)
    findings = await graph_scanner.run_scan(operations, user_a, user_b, enable_mutations=True)
    assert len(findings) == 0

    # Case 2: Patched mode
    reset_db()
    update_target_config(defect_a=True, defect_b=True, defect_c=True, patched_mode=True)
    executor_patched = SafeExecutor(allowed_hosts={"127.0.0.1", "localhost"}, total_budget=30, enable_mutations=True)
    graph_scanner_patched = GraphGuidedScanner(executor_patched, real_uvicorn_server)
    findings_patched = await graph_scanner_patched.run_scan(operations, user_a, user_b, enable_mutations=True)
    assert len(findings_patched) == 0

@pytest.mark.asyncio
async def test_owner_control_failed_404_emits_inconclusive(real_uvicorn_server):
    """
    If the owner's CONTROL request does not return success (e.g. /members 404 because
    the route doesn't exist on the target), the engine must emit 'test_inconclusive' with
    'control failed (404), test inconclusive' and NEVER flag the operation as secure or confirmed.
    Also asserts empty-body /summary trap emits status='secure_empty_body'.
    """
    auth_reg = AuthRegistry(real_uvicorn_server)
    identities = await auth_reg.authenticate_all()
    user_a = identities["user_a"]
    user_b = identities["user_b"]

    parser = OpenAPIParser(DEMO_SPEC_YAML)
    operations = parser.extract_operations()

    events = []
    async def capture_event(ev):
        events.append(ev)

    executor = SafeExecutor(allowed_hosts={"127.0.0.1", "localhost"}, total_budget=30, enable_mutations=False)
    graph_scanner = GraphGuidedScanner(executor, real_uvicorn_server)
    findings = await graph_scanner.run_scan(
        operations,
        user_a,
        user_b,
        enable_mutations=False,
        on_event=capture_event
    )

    # 1. /members is NOT in confirmed findings
    assert not any(f.endpoint == "/projects/{project_id}/members" for f in findings)

    # 2. Scanner emitted test_inconclusive event for getProjectMembers
    inconclusive_events = [
        ev for ev in events
        if ev.event_type == "test_inconclusive" and ev.data.get("operation_id") == "getProjectMembers"
    ]
    assert len(inconclusive_events) >= 1
    inc_ev = inconclusive_events[0]
    assert "control failed (404), test inconclusive" in inc_ev.message
    assert inc_ev.data.get("status") == "inconclusive"
    assert inc_ev.data.get("status_code") == 404

    # 3. /members was NEVER falsely marked as secure ("TESTED: NO LEAK")
    secure_events = [
        ev for ev in events
        if ev.event_type == "probe_denied" and ev.data and ev.data.get("operation_id") == "getProjectMembers"
    ]
    assert len(secure_events) == 0

    # 4. /summary empty-body trap emitted status='secure_empty_body'
    summary_trap_events = [
        ev for ev in events
        if ev.event_type == "probe_denied" and ev.data and ev.data.get("operation_id") == "getProjectSummary"
    ]
    assert len(summary_trap_events) >= 1
    assert summary_trap_events[0].data.get("status") == "secure_empty_body"
