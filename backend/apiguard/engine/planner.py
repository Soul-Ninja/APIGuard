import uuid
from typing import List, Dict, Any, Optional
from apiguard.engine.models import Operation, PlanStep, IdentityProfile
from apiguard.engine.graph import ResourceGraph
from apiguard.engine.target import build_body_from_schema

class TestPlanner:
    __test__ = False
    """
    Builds minimal, dependency-aware owner-versus-non-owner test sequences.
    Ensures prerequisites are created as Identity A, harvested, and probed as Identity B.
    """
    def __init__(self, graph: ResourceGraph, base_url: str = "http://localhost:8000", target_profile: Optional[Any] = None):
        self.graph = graph
        self.base_url = base_url.rstrip("/")
        self.target_profile = target_profile

    def plan_audit_for_operation(
        self,
        target_op: Operation,
        user_a: IdentityProfile,
        user_b: IdentityProfile,
        enable_mutations: bool = False
    ) -> List[PlanStep]:
        steps = []
        is_mutation = target_op.method in {"POST", "PUT", "PATCH", "DELETE"}

        # Refuse mutating tests unless explicitly enabled and cleanup declared
        if is_mutation and not enable_mutations and target_op.method != "GET":
            return []

        # Check if operation consumes a dynamic identifier (e.g. {project_id})
        if target_op.path_params:
            producers = self.graph.get_producers_for_consumer(target_op.operation_id)
            if not producers:
                # Inconclusive if no producer exists to create the prerequisite entity
                return []

            producer_op, path_nodes = producers[0]

            segments = [s for s in producer_op.path.split("/") if s]
            root_res = segments[0] if segments else ""
            override = self.target_profile.get_resource_override(root_res) if self.target_profile else None

            if override and override.body is not None:
                setup_body = override.body
            elif producer_op.request_schema:
                setup_body = build_body_from_schema(producer_op.request_schema)
            else:
                setup_body = {}

            # Step 1: Prerequisite creation as User A
            setup_id = f"step_setup_{uuid.uuid4().hex[:6]}"
            steps.append(PlanStep(
                step_id=setup_id,
                identity_id=user_a.identity_id,
                operation_id=producer_op.operation_id,
                method=producer_op.method,
                path_template=producer_op.path,
                url=f"{self.base_url}{producer_op.path}",
                headers=user_a.get_auth_headers(),
                json_body=setup_body,
                expected_status=201,
                purpose="setup",
                cleanup=True
            ))

        # Step 2: Control step as User A (Owner)
        ctrl_id = f"step_ctrl_{uuid.uuid4().hex[:6]}"
        steps.append(PlanStep(
            step_id=ctrl_id,
            identity_id=user_a.identity_id,
            operation_id=target_op.operation_id,
            method=target_op.method,
            path_template=target_op.path,
            url=f"{self.base_url}{target_op.path}",
            headers=user_a.get_auth_headers(),
            expected_status=200,
            purpose="control_owner",
            cleanup=False
        ))

        # Step 3: Probe step as User B (Attacker / Adversary)
        probe_id = f"step_probe_{uuid.uuid4().hex[:6]}"
        steps.append(PlanStep(
            step_id=probe_id,
            identity_id=user_b.identity_id,
            operation_id=target_op.operation_id,
            method=target_op.method,
            path_template=target_op.path,
            url=f"{self.base_url}{target_op.path}",
            headers=user_b.get_auth_headers(),
            expected_status=403,
            purpose="probe_adversary",
            cleanup=False
        ))

        return steps
