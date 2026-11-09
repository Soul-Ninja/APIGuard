import uuid
from typing import Dict, List, Optional, Any
from apiguard.engine.models import (
    Operation, Rule, RuleType, Hypothesis, Provenance, ExecutionResult, NodeType, EdgeType
)
from apiguard.engine.graph import ResourceGraph
from apiguard.engine.confidence import compute_hypothesis_confidence

class InferenceEngine:
    """
    Infers authorization rules from empirical control observations and
    propagates candidate hypotheses across the resource dependency DAG.
    """
    def __init__(self, graph: ResourceGraph, target_profile: Optional[Any] = None):
        self.graph = graph
        self.target_profile = target_profile
        self.hypotheses: Dict[str, Hypothesis] = {}  # key: operation_id

    def record_control_observation(
        self,
        operation_id: str,
        owner_result: ExecutionResult,
        probe_result: ExecutionResult
    ) -> Optional[Hypothesis]:
        """
        Inference loop:
        Owner allowed (200) + Non-owner denied (401/403/404) -> Validated owner_only rule.
        Derives resource type and owner field dynamically from graph and profile overrides.
        """
        if owner_result.status_code == 200 and probe_result.status_code in {401, 403, 404}:
            rtype = "Resource"
            rname = ""
            for edge in self.graph.edges:
                if edge.from_node == operation_id and edge.type == EdgeType.OPERATES_ON:
                    res_node = self.graph.nodes.get(edge.to_node)
                    if res_node and res_node.type == NodeType.RESOURCE_TYPE:
                        rtype = res_node.label or rtype
                        rname = res_node.metadata.get("resource_name", "")
                        break

            owner_field = "owner_id"
            if self.target_profile and rname:
                override = self.target_profile.get_resource_override(rname)
                if override and getattr(override, "owner_field", None):
                    owner_field = override.owner_field

            rule = Rule(
                rule_type=RuleType.OWNER_ONLY,
                resource_type=rtype,
                owner_field=owner_field,
                target_operation_id=operation_id
            )
            hyp = Hypothesis(
                id=f"hyp_{uuid.uuid4().hex[:8]}",
                rule=rule,
                operation_id=operation_id,
                confidence=compute_hypothesis_confidence(Provenance.OBSERVED, supporting_count=1, contradiction_count=0),
                provenance=Provenance.OBSERVED,
                status="validated",
                supporting_observations=[owner_result.step_id, probe_result.step_id]
            )
            self.hypotheses[operation_id] = hyp
            return hyp
        return None

    def propagate_rules(self, source_operation_id: str) -> List[Hypothesis]:
        """
        Propagates validated rules to graph-adjacent operations as candidate hypotheses.
        """
        propagated = []
        source_hyp = self.hypotheses.get(source_operation_id)
        if not source_hyp or source_hyp.status != "validated":
            return []

        adjacent_ops = self.graph.get_graph_adjacent_operations(source_operation_id)
        for adj_op in adjacent_ops:
            if adj_op.operation_id not in self.hypotheses:
                cand_rule = Rule(
                    rule_type=source_hyp.rule.rule_type,
                    resource_type=source_hyp.rule.resource_type,
                    owner_field=source_hyp.rule.owner_field,
                    target_operation_id=adj_op.operation_id
                )
                cand_hyp = Hypothesis(
                    id=f"hyp_prop_{uuid.uuid4().hex[:8]}",
                    rule=cand_rule,
                    operation_id=adj_op.operation_id,
                    confidence=compute_hypothesis_confidence(Provenance.PROPAGATED, supporting_count=0, contradiction_count=0),
                    provenance=Provenance.PROPAGATED,
                    status="candidate",
                    supporting_observations=[]
                )
                self.hypotheses[adj_op.operation_id] = cand_hyp
                propagated.append(cand_hyp)

        return propagated
