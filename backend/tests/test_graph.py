import pytest
from apiguard.engine.spec import OpenAPIParser, DEMO_SPEC_YAML
from apiguard.engine.graph import ResourceGraph
from apiguard.engine.models import EdgeType, NodeType

def test_graph_construction():
    parser = OpenAPIParser(DEMO_SPEC_YAML)
    ops = parser.extract_operations()
    graph = ResourceGraph()
    graph.build_from_operations(ops)

    # Check node types
    node_types = {n.type for n in graph.nodes.values()}
    assert NodeType.OPERATION in node_types
    assert NodeType.RESOURCE_TYPE in node_types
    assert NodeType.IDENTIFIER in node_types

    # Check edge types
    edge_types = {e.type for e in graph.edges}
    assert EdgeType.OPERATES_ON in edge_types
    assert EdgeType.PRODUCES in edge_types
    assert EdgeType.CONSUMES in edge_types

def test_producer_consumer_bfs_query():
    parser = OpenAPIParser(DEMO_SPEC_YAML)
    ops = parser.extract_operations()
    graph = ResourceGraph()
    graph.build_from_operations(ops)

    # getProjectById consumes project_id; createProject should be found as producer
    producers = graph.get_producers_for_consumer("getProjectById")
    assert len(producers) >= 1
    prod_op, path = producers[0]
    assert prod_op.operation_id == "createProject"
    assert "getProjectById" in path
    assert "createProject" in path

def test_no_generic_id_collision():
    # If two unrelated operations use parameter 'id', they must not merge unless root resource matches
    parser = OpenAPIParser(DEMO_SPEC_YAML)
    ops = parser.extract_operations()
    graph = ResourceGraph()
    graph.build_from_operations(ops)

    # Ensure project identifier is tied to Project resource
    id_nodes = [n for n in graph.nodes.values() if n.type == NodeType.IDENTIFIER]
    for id_node in id_nodes:
        assert "projects" in id_node.id or "project" in id_node.label
