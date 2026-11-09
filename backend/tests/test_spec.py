import pytest
from apiguard.engine.spec import OpenAPIParser, DEMO_SPEC_YAML

def test_parse_valid_spec():
    parser = OpenAPIParser(DEMO_SPEC_YAML)
    operations = parser.extract_operations()
    assert len(operations) >= 5

    op_map = {op.operation_id: op for op in operations}
    assert "login" in op_map
    assert "createProject" in op_map
    assert "getProjectById" in op_map
    assert "exportProjectBilling" in op_map

    # Check path parameters extraction
    get_proj = op_map["getProjectById"]
    assert get_proj.method == "GET"
    assert get_proj.path_params == ["project_id"]
    assert "bearerAuth" in get_proj.security_schemes

def test_ref_resolution():
    parser = OpenAPIParser(DEMO_SPEC_YAML)
    # Check that $ref in paths was resolved
    paths = parser.resolved_spec.get("paths", {})
    create_op = paths.get("/projects", {}).get("post", {})
    schema = create_op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
    assert "properties" in schema
    assert "name" in schema["properties"]
