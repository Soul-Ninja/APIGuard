import os
import time
import threading
import pytest
import uvicorn
import httpx
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from apiguard.engine.cli import run_cli_scan
from apiguard.engine.target import load_target_profile, TargetProfile
from apiguard.engine.scanner import scan_target

TEST_PORT = 8126
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"

orders_app = FastAPI()
orders_db = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class OrderCreate(BaseModel):
    item: str = "apiguard-test"
    amount: float = 1.0


@orders_app.post("/auth/login")
def login(req: LoginRequest):
    return {
        "access_token": f"tok_{req.username}",
        "uid": f"uid_{req.username}"
    }


@orders_app.post("/orders", status_code=201)
def create_order(order: OrderCreate, authorization: str = Header(None)):
    token = (authorization or "").replace("Bearer ", "").strip()
    cust_id = token.replace("tok_", "uid_")
    order_id = "ord_101"
    # Note: no generic "secret" or "owner" fields; customer_id is the sole identifier
    record = {
        "id": order_id,
        "item": order.item,
        "amount": order.amount,
        "customer_id": cust_id
    }
    orders_db[order_id] = record
    return record


@orders_app.get("/orders/{order_id}")
def get_order(order_id: str, authorization: str = Header(None)):
    if order_id not in orders_db:
        raise HTTPException(status_code=404, detail="Order not found")
    # Deliberate BOLA: does not check if caller is owner
    return orders_db[order_id]


@orders_app.get("/admin/orders")
def get_admin_orders(authorization: str = Header(None)):
    # Deliberate BFLA: normal customer callers can access admin order inventory
    return list(orders_db.values())


AUTH401_PORT = 8127
auth401_app = FastAPI()


@auth401_app.post("/orders", status_code=201)
def create_order_rejected():
    raise HTTPException(status_code=401, detail="Unauthorized")


@auth401_app.get("/orders/{order_id}")
def get_order_placeholder(order_id: str):
    return {"id": order_id}


class Auth401ServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        config = uvicorn.Config(auth401_app, host="127.0.0.1", port=AUTH401_PORT, log_level="error")
        self.server = uvicorn.Server(config)
        self.daemon = True

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


@pytest.fixture(scope="module")
def auth401_server():
    server = Auth401ServerThread()
    server.start()
    client = httpx.Client(timeout=2.0)
    for _ in range(30):
        try:
            res = client.get(f"http://127.0.0.1:{AUTH401_PORT}/orders/1")
            if res.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{AUTH401_PORT}"
    server.stop()


ORDERS_SPEC = """
openapi: 3.0.3
info:
  title: Orders Service API
  version: 1.0.0
paths:
  /auth/login:
    post:
      operationId: login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [username, password]
              properties:
                username: { type: string }
                password: { type: string }
      responses:
        '200':
          description: OK
  /orders:
    post:
      operationId: createOrder
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [item, amount]
              properties:
                item: { type: string }
                amount: { type: number }
      responses:
        '201':
          description: Created
  /orders/{order_id}:
    get:
      operationId: getOrderById
      security:
        - bearerAuth: []
      parameters:
        - name: order_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: OK
  /admin/orders:
    get:
      operationId: getAdminOrders
      tags:
        - admin
      security:
        - bearerAuth: []
      responses:
        '200':
          description: OK
"""


class UvicornServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        config = uvicorn.Config(orders_app, host="127.0.0.1", port=TEST_PORT, log_level="error")
        self.server = uvicorn.Server(config)
        self.daemon = True

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


@pytest.fixture(scope="module")
def orders_server():
    server = UvicornServerThread()
    server.start()

    # Wait for server to be responsive
    client = httpx.Client(timeout=2.0)
    for _ in range(30):
        try:
            res = client.post(f"{BASE_URL}/auth/login", json={"username": "test", "password": "pwd"})
            if res.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)

    yield BASE_URL
    server.stop()


@pytest.mark.asyncio
async def test_orders_custom_target_bola_found(tmp_path, orders_server, capsys):
    """
    Asserts a non-demo target ("orders", non-Project, non-owner_id "customer_id",
    access_token/uid login) scanned via YAML profile confirms BOLA on GET /orders/{order_id}
    using sensitive_fields: ["customer"] and owner_field: "customer_id", exiting with 1.
    """
    spec_file = tmp_path / "orders_spec.yaml"
    spec_file.write_text(ORDERS_SPEC, encoding="utf-8")

    profile_content = f"""
base_url: "{orders_server}"
spec_path: "{spec_file.as_posix()}"
allowed_hosts:
  - "127.0.0.1"
  - "localhost"
request_budget: 30
owner: "customer_a"
attacker: "customer_b"
login:
  path: "/auth/login"
  body_template:
    username: "{{username}}"
    password: "{{password}}"
  token_path: "access_token"
  user_id_path: "uid"
identities:
  - name: "customer_a"
    username: "alice@orders.test"
    password: "pwd"
  - name: "customer_b"
    username: "bob@orders.test"
    password: "pwd"
resources:
  orders:
    id_path: "id"
    owner_field: "customer_id"
    sensitive_fields:
      - "customer"
"""
    profile_file = tmp_path / "orders_profile.yaml"
    profile_file.write_text(profile_content, encoding="utf-8")

    profile = load_target_profile(str(profile_file))
    findings = await scan_target(target_profile=profile)
    assert len(findings) == 1
    f = findings[0]
    assert f.status.value == "confirmed"
    assert f.endpoint == "/orders/{order_id}"
    assert f.resource_type == "Orders"
    assert f.hypothesis.rule.owner_field == "customer_id"
    assert "customer_id" in f.diff_fields

    exit_code = await run_cli_scan(dry_run=False, profile_path=str(profile_file))
    # Exit code 1 indicates confirmed vulnerability found
    assert exit_code == 1

    captured = capsys.readouterr()
    combined_output = captured.out + captured.err
    assert "Skipped resource 'auth'" not in combined_output
    assert "'auth'" not in combined_output
    assert "Tested 1 of 1 resources" in combined_output


@pytest.mark.asyncio
async def test_orders_custom_target_bfla_found(tmp_path, orders_server, capsys):
    """
    Proves BFLA detection works on non-demo targets:
    Orders API with an /admin/orders route and configured admin identity confirms BFLA.
    """
    spec_file = tmp_path / "orders_spec.yaml"
    spec_file.write_text(ORDERS_SPEC, encoding="utf-8")

    profile_content = f"""
base_url: "{orders_server}"
spec_path: "{spec_file.as_posix()}"
allowed_hosts:
  - "127.0.0.1"
  - "localhost"
request_budget: 30
owner: "customer_a"
attacker: "customer_b"
admin: "admin"
login:
  path: "/auth/login"
  body_template:
    username: "{{username}}"
    password: "{{password}}"
  token_path: "access_token"
  user_id_path: "uid"
identities:
  - name: "customer_a"
    username: "alice@orders.test"
    password: "pwd"
  - name: "customer_b"
    username: "bob@orders.test"
    password: "pwd"
  - name: "admin"
    username: "admin@orders.test"
    password: "pwd"
resources:
  orders:
    id_path: "id"
    owner_field: "customer_id"
    sensitive_fields:
      - "customer"
"""
    profile_file = tmp_path / "orders_bfla_profile.yaml"
    profile_file.write_text(profile_content, encoding="utf-8")

    profile = load_target_profile(str(profile_file))
    findings = await scan_target(target_profile=profile)
    bfla_findings = [f for f in findings if getattr(f, "category", "") == "BFLA"]
    assert len(bfla_findings) == 1
    assert bfla_findings[0].endpoint == "/admin/orders"
    assert bfla_findings[0].severity == "HIGH"
    assert bfla_findings[0].status.value == "confirmed"

    exit_code = await run_cli_scan(dry_run=False, profile_path=str(profile_file))
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "[!] BFLA FINDING:" in captured.out
    assert "BFLA Coverage: Tested 1 of 1 admin operations" in captured.out


@pytest.mark.asyncio
async def test_static_token_unreachable_base_url_exits_2(tmp_path, capsys):
    """
    A profile with static tokens (no login) pointing to an unreachable port
    skips resources due to connection error and exits with 2 (nothing tested).
    """
    spec_file = tmp_path / "orders_spec.yaml"
    spec_file.write_text(ORDERS_SPEC, encoding="utf-8")

    profile_content = f"""
base_url: "http://127.0.0.1:9"
spec_path: "{spec_file.as_posix()}"
allowed_hosts:
  - "127.0.0.1"
owner: "user_a"
attacker: "user_b"
identities:
  - name: "user_a"
    identity_id: "usr_static_a"
    token: "tok_a"
  - name: "user_b"
    identity_id: "usr_static_b"
    token: "tok_b"
"""
    profile_file = tmp_path / "static_unreachable.yaml"
    profile_file.write_text(profile_content, encoding="utf-8")

    exit_code = await run_cli_scan(dry_run=False, profile_path=str(profile_file))
    assert exit_code == 2

    captured = capsys.readouterr()
    combined_output = captured.out + captured.err
    assert "Skipped resource 'auth'" not in combined_output
    assert "'auth'" not in combined_output
    assert "AUDIT COMPLETE" not in combined_output
    assert "Tested 0 of 1 resources" in combined_output
    assert "Nothing was tested - check base_url, credentials and spec" in combined_output
    assert "[-] Skipped resource 'orders'" in captured.out
    assert "[ERROR] Nothing was tested" in captured.err


@pytest.mark.asyncio
async def test_target_create_returns_401_exits_2(tmp_path, auth401_server, capsys):
    """
    A target whose create endpoint returns 401 exits 2, naming the owner identity
    and reporting that credentials were rejected.
    """
    spec_file = tmp_path / "orders_spec.yaml"
    spec_file.write_text(ORDERS_SPEC, encoding="utf-8")

    profile_content = f"""
base_url: "{auth401_server}"
spec_path: "{spec_file.as_posix()}"
allowed_hosts:
  - "127.0.0.1"
owner: "user_a"
attacker: "user_b"
identities:
  - name: "user_a"
    identity_id: "usr_alice_owner"
    token: "tok_invalid"
  - name: "user_b"
    identity_id: "usr_bob_attacker"
    token: "tok_b"
"""
    profile_file = tmp_path / "auth401_profile.yaml"
    profile_file.write_text(profile_content, encoding="utf-8")

    exit_code = await run_cli_scan(dry_run=False, profile_path=str(profile_file))
    assert exit_code == 2

    captured = capsys.readouterr()
    combined_output = captured.out + captured.err
    assert "usr_alice_owner" in combined_output
    assert "credentials were rejected" in combined_output
    assert "Nothing was tested - check base_url, credentials and spec" in combined_output
    assert "Skipped resource 'auth'" not in combined_output
    assert "'auth'" not in combined_output
    assert "AUDIT COMPLETE" not in combined_output
    assert "Tested 0 of 1 resources" in combined_output
    assert "[-] Skipped resource 'orders'" in captured.out
    assert "[ERROR] Nothing was tested" in captured.err


@pytest.mark.asyncio
async def test_user_demo_yaml_in_temp_dir_exits_2(tmp_path):
    """
    A user's own demo.yaml in a temp dir must NOT be treated as the bundled demo,
    and attempting to scan an unreachable target on port 9 must exit with code 2.
    """
    user_demo = tmp_path / "demo.yaml"
    user_demo.write_text("""
base_url: "http://127.0.0.1:9"
spec_path: "non_existent_spec.yaml"
is_demo: true
""", encoding="utf-8")

    exit_code = await run_cli_scan(dry_run=False, profile_path=str(user_demo))
    assert exit_code == 2


@pytest.mark.asyncio
async def test_dry_run_unused_port_exits_0(tmp_path):
    """
    A dry run against an unused, unreachable port sends ZERO network requests
    and exits 0 cleanly.
    """
    spec_file = tmp_path / "orders_spec.yaml"
    spec_file.write_text(ORDERS_SPEC, encoding="utf-8")

    profile_file = tmp_path / "dry_run.yaml"
    profile_file.write_text(f"""
base_url: "http://127.0.0.1:59999"
spec_path: "{spec_file.as_posix()}"
allowed_hosts:
  - "127.0.0.1"
owner: "user_a"
attacker: "user_b"
identities:
  - name: "user_a"
  - name: "user_b"
""", encoding="utf-8")

    exit_code = await run_cli_scan(dry_run=True, profile_path=str(profile_file))
    assert exit_code == 0


@pytest.mark.asyncio
async def test_disallowed_host_refused(tmp_path):
    profile_content = """
base_url: "http://unauthorized-evil-domain.com/api"
spec_path: "demo_spec.yaml"
allowed_hosts:
  - "127.0.0.1"
  - "localhost"
"""
    profile_file = tmp_path / "disallowed.yaml"
    profile_file.write_text(profile_content, encoding="utf-8")

    exit_code = await run_cli_scan(dry_run=False, profile_path=str(profile_file))
    # Exit code 2 indicates config / safety rejection
    assert exit_code == 2


@pytest.mark.asyncio
async def test_missing_env_var_errors(tmp_path):
    profile_content = """
base_url: "http://127.0.0.1:8000"
spec_path: "demo_spec.yaml"
identities:
  - name: "user_a"
    password: "${UNSET_APIGUARD_SECRET_KEY_999}"
"""
    profile_file = tmp_path / "env_test.yaml"
    profile_file.write_text(profile_content, encoding="utf-8")

    # Loading raises ValueError
    with pytest.raises(ValueError, match="UNSET_APIGUARD_SECRET_KEY_999"):
        load_target_profile(str(profile_file))

    # CLI scan catches error and returns code 2
    exit_code = await run_cli_scan(dry_run=False, profile_path=str(profile_file))
    assert exit_code == 2


@pytest.mark.asyncio
async def test_exit_codes_matrix(tmp_path, orders_server, capsys):
    spec_file = tmp_path / "orders_spec.yaml"
    spec_file.write_text(ORDERS_SPEC, encoding="utf-8")

    profile_content = f"""
base_url: "{orders_server}"
spec_path: "{spec_file.as_posix()}"
allowed_hosts:
  - "127.0.0.1"
owner: "customer_a"
attacker: "customer_b"
login:
  path: "/auth/login"
  body_template:
    username: "{{username}}"
    password: "{{password}}"
  token_path: "access_token"
  user_id_path: "uid"
identities:
  - name: "customer_a"
    username: "alice"
    password: "pwd"
  - name: "customer_b"
    username: "bob"
    password: "pwd"
resources:
  orders:
    sensitive_fields:
      - "customer"
"""
    profile_file = tmp_path / "orders_profile.yaml"
    profile_file.write_text(profile_content, encoding="utf-8")

    # 1. Exit code 0: Dry run
    code_dry = await run_cli_scan(dry_run=True, profile_path=str(profile_file))
    assert code_dry == 0

    # 2. Exit code 1: Confirmed findings on vulnerable target
    code_scan = await run_cli_scan(dry_run=False, profile_path=str(profile_file))
    assert code_scan == 1
    out_scan = capsys.readouterr()
    assert "Skipped resource 'auth'" not in (out_scan.out + out_scan.err)
    assert "'auth'" not in (out_scan.out + out_scan.err)

    # 3. Exit code 2: Unreachable server
    unreachable_content = profile_content.replace(str(TEST_PORT), "59876")
    unreachable_file = tmp_path / "unreachable.yaml"
    unreachable_file.write_text(unreachable_content, encoding="utf-8")

    code_err = await run_cli_scan(dry_run=False, profile_path=str(unreachable_file))
    assert code_err == 2
    out_err = capsys.readouterr()
    assert "Skipped resource 'auth'" not in (out_err.out + out_err.err)
    assert "'auth'" not in (out_err.out + out_err.err)
    assert "AUDIT COMPLETE" not in (out_err.out + out_err.err)


@pytest.mark.asyncio
async def test_missing_spec_path_errors_for_non_demo():
    profile = TargetProfile(
        base_url="http://127.0.0.1:8000",
        spec_path=None,
        is_demo=False
    )
    with pytest.raises(ValueError, match="spec_path is required for non-demo profiles"):
        profile.load_operations()
