"""Unit tests for CHRONOS Causality Engine (Behavioral Attack Graph)."""
import pytest
from chronos.research.causality_engine import BehavioralGraph
from chronos.research.demo_data import ATTACK_EVENTS, HOST


def test_graph_node_and_edge_ingestion():
    graph = BehavioralGraph(HOST)
    for event in ATTACK_EVENTS:
        graph.ingest_event(event)
    assert len(graph.g.nodes) > 0
    assert len(graph.g.edges) > 0


def test_bounded_risk_diffusion():
    graph = BehavioralGraph(HOST)
    for event in ATTACK_EVENTS:
        graph.ingest_event(event)
    graph.propagate_risk()

    nodes_with_risk = [d.get("risk", 0.0) for _, d in graph.g.nodes(data=True)]
    assert max(nodes_with_risk) > 0.5


def test_asset_awareness_multiplier():
    ws_graph = BehavioralGraph(HOST, asset_type="WORKSTATION")
    for event in ATTACK_EVENTS:
        ws_graph.ingest_event(event)
    ws_graph.propagate_risk()
    ws_risk = max((d.get("risk", 0.0) for _, d in ws_graph.g.nodes(data=True)), default=0.0)

    dc_graph = BehavioralGraph(HOST, asset_type="DOMAIN_CONTROLLER")
    for event in ATTACK_EVENTS:
        dc_graph.ingest_event(event)
    dc_graph.propagate_risk()
    dc_risk = max((d.get("risk", 0.0) for _, d in dc_graph.g.nodes(data=True)), default=0.0)

    assert dc_risk >= ws_risk
