from typing import List, Dict, Optional
import httpx
from apiguard.engine.models import (
    Operation, IdentityProfile, Finding, Rule, RuleType, FindingStatus, ExecutionResult, PlanStep, Hypothesis, Provenance
)
from apiguard.engine.executor import SafeExecutor
from apiguard.engine.policy import PolicyEvaluator, PolicyResult
from apiguard.engine.verifier import DifferentialVerifier

class BaselineScanner:
    """
    Endpoint-by-endpoint baseline scanner.
    Harvests its own resource like the graph scanner, but tests operations in isolation
    without a resource graph, without rule propagation, and without sibling knowledge.
    """
    def __init__(
        self,
        executor: SafeExecutor,
        base_url: str = "http://127.0.0.1:8000/target",
        oracle_mode: bool = False
    ):
        self.executor = executor
        self.base_url = base_url.rstrip("/")
        self.oracle_mode = oracle_mode

        # Documented/configured rules known to the baseline scanner
        self.known_rules: Dict[str, Rule] = {
            "getProjectById": Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project"),
            "deleteProject": Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project"),
            "updateProject": Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project")
        }
        if self.oracle_mode:
            # Oracle baseline has documented rules for everything including export
            self.known_rules["exportProjectBilling"] = Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project")

    async def scan_operations(
        self,
        operations: List[Operation],
        user_a: IdentityProfile,
        user_b: IdentityProfile,
        enable_mutations: bool = False,
        client: Optional[httpx.AsyncClient] = None
    ) -> List[Finding]:
        findings = []

        # 1. Harvest state dynamically via producer operation (identical harvest to graph scanner)
        producer_ops = [op for op in operations if op.method == "POST" and not op.path_params]
        if not producer_ops:
            return []
        prod_op = producer_ops[0]

        setup_step = PlanStep(
            step_id="base_harvest",
            identity_id=user_a.identity_id,
            operation_id=prod_op.operation_id,
            method="POST",
            path_template=prod_op.path,
            url=f"{self.base_url}{prod_op.path}",
            headers={"Authorization": f"Bearer {user_a.token}"} if user_a.token else {},
            json_body={"name": "Baseline Entity", "confidential_data": "BASE-SECRET-123", "budget": "$100,000"},
            purpose="setup"
        )
        setup_res = await self.executor.execute_step(setup_step, client=client)
        harvested_id = setup_res.body.get("id", "proj_42") if isinstance(setup_res.body, dict) else "proj_42"

        # 2. Iterate operations endpoint-by-endpoint
        # DELETE runs last: the owner control would otherwise destroy the harvested
        # resource and make every later test on it inconclusive.
        ordered_ops = sorted(operations, key=lambda o: o.method == "DELETE")
        for op in ordered_ops:
            if not op.path_params:
                continue

            if op.method in {"PATCH", "PUT", "DELETE"} and not enable_mutations:
                continue

            rule = self.known_rules.get(op.operation_id)
            eval_result = PolicyEvaluator.evaluate(rule, user_b.identity_id, user_a.identity_id)

            # If no rule exists for this operation, evaluate returns UNKNOWN -> Counted as no finding!
            if eval_result == PolicyResult.UNKNOWN:
                continue

            url = f"{self.base_url}{op.path}".replace(f"{{{op.path_params[0]}}}", str(harvested_id))

            # Control step as User A
            ctrl_step = PlanStep(
                step_id=f"base_ctrl_{op.operation_id}",
                identity_id=user_a.identity_id,
                operation_id=op.operation_id,
                method=op.method,
                path_template=op.path,
                url=url,
                headers={"Authorization": f"Bearer {user_a.token}"} if user_a.token else {},
                json_body={"name": "Baseline Update"} if op.method in {"PATCH", "PUT"} else None,
                purpose="control_owner"
            )
            ctrl_res = await self.executor.execute_step(ctrl_step, client=client)

            # Probe step as User B
            probe_step = PlanStep(
                step_id=f"base_probe_{op.operation_id}",
                identity_id=user_b.identity_id,
                operation_id=op.operation_id,
                method=op.method,
                path_template=op.path,
                url=url,
                headers={"Authorization": f"Bearer {user_b.token}"} if user_b.token else {},
                json_body={"name": "Baseline Attack"} if op.method in {"PATCH", "PUT"} else None,
                purpose="probe_adversary"
            )
            probe_res = await self.executor.execute_step(probe_step, client=client)

            # Verify response
            hyp = Hypothesis(
                id=f"hyp_base_{op.operation_id}",
                rule=rule,
                operation_id=op.operation_id,
                confidence=0.85,
                provenance=Provenance.DOCUMENTED
            )
            finding = DifferentialVerifier.verify(
                operation_id=op.operation_id,
                endpoint=op.path,
                method=op.method,
                hypothesis=hyp,
                graph_path=[op.operation_id],
                owner_result=ctrl_res,
                probe_result=probe_res,
                owner_identity_id=user_a.identity_id,
                probe_identity_id=user_b.identity_id
            )
            if finding and finding.status == FindingStatus.CONFIRMED:
                findings.append(finding)

        return findings
