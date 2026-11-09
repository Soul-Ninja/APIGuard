from typing import List, Dict, Any, Optional, Set, Tuple
from collections import deque
from apiguard.engine.models import (
    Operation, GraphNode, GraphEdge, NodeType, EdgeType, Provenance
)
from apiguard.engine.confidence import compute_edge_confidence

class ResourceGraph:
    """
    Dependency Directed Acyclic Graph (DAG) connecting API operations,
    resource types, and dynamic identifiers.
    """
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.operations: Dict[str, Operation] = {}

    def build_from_operations(self, operations: List[Operation]):
        self.nodes.clear()
        self.edges.clear()
        self.operations = {op.operation_id: op for op in operations}

        # 1. Add Operation Nodes
        for op in operations:
            self.nodes[op.operation_id] = GraphNode(
                id=op.operation_id,
                label=f"{op.method} {op.path}",
                type=NodeType.OPERATION,
                metadata={
                    "method": op.method,
                    "path": op.path,
                    "summary": op.summary,
                    "path_params": op.path_params,
                    "security": op.security_schemes
                }
            )

        # 2. Extract Resources and Identifiers
        # Look for entity groupings based on paths (e.g. /projects -> Resource: Project)
        for op in operations:
            segments = [s for s in op.path.split("/") if s]
            if not segments:
                continue

            root_resource = segments[0]
            resource_node_id = f"res_{root_resource}"
            if resource_node_id not in self.nodes:
                self.nodes[resource_node_id] = GraphNode(
                    id=resource_node_id,
                    label=root_resource.capitalize(),
                    type=NodeType.RESOURCE_TYPE,
                    metadata={"resource_name": root_resource}
                )

            # Link Operation -> OPERATES_ON -> ResourceType
            self.edges.append(GraphEdge(
                from_node=op.operation_id,
                to_node=resource_node_id,
                type=EdgeType.OPERATES_ON,
                confidence=0.90,
                provenance=Provenance.SCHEMA
            ))

            # 3. Detect Producer vs Consumer relationships
            # A POST /projects (or 201 response) produces the identifier (skip auth/token endpoints)
            if op.method == "POST" and not op.path_params and root_resource in op.path and root_resource.lower() not in {"auth", "login", "token", "oauth"}:
                id_node_id = f"id_{root_resource}"
                if id_node_id not in self.nodes:
                    self.nodes[id_node_id] = GraphNode(
                        id=id_node_id,
                        label=f"{root_resource}_id",
                        type=NodeType.IDENTIFIER,
                        metadata={"param_name": f"{root_resource[:-1] if root_resource.endswith('s') else root_resource}_id"}
                    )

                # Producer edge: Operation -> PRODUCES -> Identifier
                self.edges.append(GraphEdge(
                    from_node=op.operation_id,
                    to_node=id_node_id,
                    type=EdgeType.PRODUCES,
                    confidence=compute_edge_confidence(Provenance.SCHEMA, is_direct_param_match=True),
                    provenance=Provenance.SCHEMA
                ))

            # Operations with path parameters consume the identifier
            for param in op.path_params:
                # Disallow generic "id" match without path context
                expected_param_substr = root_resource[:-1] if root_resource.endswith("s") else root_resource
                is_valid_match = (expected_param_substr.lower() in param.lower()) or (param == "id" and len(segments) >= 2)

                if is_valid_match:
                    id_node_id = f"id_{root_resource}"
                    if id_node_id in self.nodes:
                        self.edges.append(GraphEdge(
                            from_node=id_node_id,
                            to_node=op.operation_id,
                            type=EdgeType.CONSUMES,
                            confidence=compute_edge_confidence(Provenance.SCHEMA, is_direct_param_match=True),
                            provenance=Provenance.SCHEMA
                        ))

            # 4. Detect child / nested / export routes
            if op.path_params and len(segments) >= 3:
                parent_op_candidates = [
                    o for o in operations 
                    if o.method == "GET" and o.path != op.path and op.path.startswith(o.path)
                ]
                for p_op in parent_op_candidates:
                    self.edges.append(GraphEdge(
                        from_node=p_op.operation_id,
                        to_node=op.operation_id,
                        type=EdgeType.NESTED_UNDER,
                        confidence=compute_edge_confidence(Provenance.PROPAGATED, is_direct_param_match=True),
                        provenance=Provenance.PROPAGATED
                    ))

    def get_producers_for_consumer(self, consumer_op_id: str) -> List[Tuple[Operation, List[str]]]:
        """
        Bounded BFS: Finds producer operations that generate identifiers consumed by consumer_op_id.
        Returns a list of tuples: (producer_operation, path_of_node_ids)
        """
        results = []
        # Find incoming CONSUMES edges
        target_id_nodes = [
            e.from_node for e in self.edges 
            if e.to_node == consumer_op_id and e.type == EdgeType.CONSUMES
        ]

        for id_node in target_id_nodes:
            producer_op_ids = [
                e.from_node for e in self.edges 
                if e.to_node == id_node and e.type == EdgeType.PRODUCES
            ]
            for p_id in producer_op_ids:
                if p_id in self.operations:
                    results.append((self.operations[p_id], [p_id, id_node, consumer_op_id]))

        return results

    def get_graph_adjacent_operations(self, operation_id: str) -> List[Operation]:
        """
        Finds sibling operations sharing the same resource/identifier or connected via NESTED_UNDER.
        """
        adjacent = set()
        for edge in self.edges:
            if edge.from_node == operation_id and edge.type in {EdgeType.NESTED_UNDER, EdgeType.REFERENCES}:
                adjacent.add(edge.to_node)
            elif edge.to_node == operation_id and edge.type == EdgeType.NESTED_UNDER:
                adjacent.add(edge.from_node)

        return [self.operations[op_id] for op_id in adjacent if op_id in self.operations]

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes the graph for UI rendering.
        """
        return {
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges]
        }
