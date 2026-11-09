import pytest
import httpx
from fastapi import FastAPI, HTTPException, Header
from apiguard.engine.target import (
    get_path,
    build_body_from_schema,
    load_target_profile,
    TargetProfile,
    IdentityConfig,
    ResourceOverride
)
from apiguard.engine.models import Operation
from apiguard.engine.scanner import scan_target, GraphGuidedScanner
from apiguard.engine.executor import SafeExecutor
from apiguard.engine.spec import OpenAPIParser


def test_get_path_id_and_dotted_and_missing():
    # 1. Standard top-level id
    data1 = {"id": "proj_123", "name": "Test"}
    assert get_path(data1, "id") == "proj_123"

    # 2. Dotted path data.projectId
    data2 = {"data": {"projectId": "proj_nested_456", "active": True}}
    assert get_path(data2, "data.projectId") == "proj_nested_456"

    # 3. Missing path
    assert get_path(data2, "missing") is None
    assert get_path(data2, "data.missingField") is None
    assert get_path(data1, "data.projectId") is None

    # 4. Edge cases
    assert get_path(None, "id") is None
    assert get_path("string", "id") is None
    assert get_path({}, "id") is None
    assert get_path({"id": None}, "id") is None


def test_body_generation_from_small_schema():
    # Schema with required fields and various data types
    schema = {
        "type": "object",
        "required": ["name", "count", "is_active", "status"],
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"},
            "is_active": {"type": "boolean"},
            "status": {"type": "string", "enum": ["draft", "published", "archived"]},
            "optional_note": {"type": "string"},
            "tags": {"type": "array"}
        }
    }

    body = build_body_from_schema(schema)

    assert body["name"] == "apiguard-test"
    assert body["count"] == 1
    assert body["is_active"] is True
    assert body["status"] == "draft"  # first enum value
    assert "optional_note" not in body  # optional, not in required

    # Schema without required (generates all properties)
    schema_no_required = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "score": {"type": "number"}
        }
    }
    body2 = build_body_from_schema(schema_no_required)
    assert body2["title"] == "apiguard-test"
    assert body2["score"] == 1


def test_demo_profile_loads_cleanly():
    profile = load_target_profile("targets/demo.yaml")
    assert profile.base_url == "http://127.0.0.1:8000/target"
    assert profile.login is not None
    assert profile.login.path == "/auth/login"
    assert len(profile.identities) >= 2
    user_a = profile.get_identity("user_a")
    assert user_a is not None
    assert user_a.username == "aman@acme.corp"
    override = profile.get_resource_override("projects")
    assert override is not None
    assert override.id_path == "id"


@pytest.mark.asyncio
async def test_mock_api_custom_id_path_scans_without_crashing():
    """
    Criterion (c): A second YAML profile pointing at a mock API that returns
    {"data": {"projectId": "x"}} scans without crashing.
    """
    mock_app = FastAPI()
    db = {}

    @mock_app.post("/items", status_code=201)
    async def create_item(payload: dict, authorization: str = Header(None)):
        item_id = "x"
        db[item_id] = {
            "id": item_id,
            "owner": authorization,
            "secret": "TENANT-A-SECRET-999"
        }
        return {"data": {"projectId": item_id}}

    @mock_app.get("/items/{item_id}")
    async def get_item(item_id: str, authorization: str = Header(None)):
        if item_id not in db:
            raise HTTPException(status_code=404, detail="Not Found")
        if "token_mock_attacker" in (authorization or ""):
            # Secure: unauthorized attacker is forbidden
            raise HTTPException(status_code=403, detail="Forbidden")
        return {"data": {"projectId": item_id, "secret": db[item_id]["secret"]}}

    mock_spec_yaml = """
openapi: 3.0.3
info:
  title: Mock Items API
  version: 1.0.0
paths:
  /items:
    post:
      operationId: createItem
      responses:
        '201':
          description: Created
  /items/{item_id}:
    get:
      operationId: getItemById
      parameters:
        - name: item_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: OK
"""
    parser = OpenAPIParser(mock_spec_yaml)
    operations = parser.extract_operations()

    profile = TargetProfile(
        base_url="http://testserver",
        allowed_hosts=["127.0.0.1", "localhost", "testserver"],
        identities=[
            IdentityConfig(name="user_a", role="customer", headers={"Authorization": "Bearer token_mock_owner"}),
            IdentityConfig(name="user_b", role="customer", headers={"Authorization": "Bearer token_mock_attacker"})
        ],
        resources={
            "items": ResourceOverride(id_path="data.projectId", body={"name": "test-item"})
        }
    )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_app), base_url="http://testserver") as client:
        findings = await scan_target(
            target_profile=profile,
            operations=operations,
            client=client
        )
        # Completed scan cleanly without crashing
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_mock_api_missing_id_skips_without_crashing():
    """
    If the create response does not have the configured id_path,
    the resource is marked skipped without crashing or raising.
    """
    mock_app = FastAPI()

    @mock_app.post("/items", status_code=201)
    async def create_item(payload: dict):
        # Returns response without the requested id_path
        return {"status": "ok"}

    @mock_app.get("/items/{item_id}")
    async def get_item(item_id: str):
        return {"status": "ok"}

    mock_spec_yaml = """
openapi: 3.0.3
info:
  title: Mock Items API
  version: 1.0.0
paths:
  /items:
    post:
      operationId: createItem
      responses:
        '201':
          description: Created
  /items/{item_id}:
    get:
      operationId: getItemById
      parameters:
        - name: item_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: OK
"""
    parser = OpenAPIParser(mock_spec_yaml)
    operations = parser.extract_operations()

    profile = TargetProfile(
        base_url="http://testserver",
        allowed_hosts=["127.0.0.1", "localhost", "testserver"],
        identities=[
            IdentityConfig(name="user_a", headers={"Authorization": "Bearer tok_a"}),
            IdentityConfig(name="user_b", headers={"Authorization": "Bearer tok_b"})
        ],
        resources={
            "items": ResourceOverride(id_path="data.nonexistent_id")
        }
    )

    events = []
    async def capture_event(ev):
        events.append(ev)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_app), base_url="http://testserver") as client:
        findings = await scan_target(
            target_profile=profile,
            operations=operations,
            client=client,
            on_event=capture_event
        )
        assert len(findings) == 0
        assert any("skipped" in ev.message.lower() for ev in events)
