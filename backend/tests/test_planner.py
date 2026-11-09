import pytest
from apiguard.engine.spec import OpenAPIParser, DEMO_SPEC_YAML
from apiguard.engine.graph import ResourceGraph
from apiguard.engine.planner import TestPlanner
from apiguard.engine.models import IdentityProfile

def test_planner_sequence_and_prerequisites():
    parser = OpenAPIParser(DEMO_SPEC_YAML)
    ops = parser.extract_operations()
    graph = ResourceGraph()
    graph.build_from_operations(ops)

    planner = TestPlanner(graph, "http://localhost:8000/target")
    user_a = IdentityProfile(identity_id="usr_a", username="alice", password="p", role="customer", token="tok_a")
    user_b = IdentityProfile(identity_id="usr_b", username="bob", password="p", role="customer", token="tok_b")

    get_proj_op = [o for o in ops if o.operation_id == "getProjectById"][0]
    steps = planner.plan_audit_for_operation(get_proj_op, user_a, user_b)

    assert len(steps) == 3
    # Step 1: Prerequisite setup via createProject
    assert steps[0].purpose == "setup"
    assert steps[0].operation_id == "createProject"
    assert steps[0].identity_id == "usr_a"

    # Step 2: Owner control
    assert steps[1].purpose == "control_owner"
    assert steps[1].operation_id == "getProjectById"
    assert steps[1].identity_id == "usr_a"

    # Step 3: Adversary probe
    assert steps[2].purpose == "probe_adversary"
    assert steps[2].operation_id == "getProjectById"
    assert steps[2].identity_id == "usr_b"

def test_planner_refuses_mutations_when_disabled():
    parser = OpenAPIParser(DEMO_SPEC_YAML)
    ops = parser.extract_operations()
    graph = ResourceGraph()
    graph.build_from_operations(ops)

    planner = TestPlanner(graph, "http://localhost:8000/target")
    user_a = IdentityProfile(identity_id="usr_a", username="alice", password="p", role="customer", token="tok_a")
    user_b = IdentityProfile(identity_id="usr_b", username="bob", password="p", role="customer", token="tok_b")

    patch_op = [o for o in ops if o.operation_id == "updateProject"][0]
    # When enable_mutations is False, returns empty plan
    steps = planner.plan_audit_for_operation(patch_op, user_a, user_b, enable_mutations=False)
    assert len(steps) == 0
