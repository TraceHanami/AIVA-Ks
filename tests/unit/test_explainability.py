"""Unit tests for CHRONOS Grounded Explainability Engine."""
import pytest
from chronos.research.causality_engine import BehavioralGraph
from chronos.research.explainability.evidence import EvidenceExtractor
from chronos.research.explainability.narrator import AttackNarrativeGenerator, TemplateNarrator
from chronos.research.mitre_intelligence import MitreMapper
from chronos.research.demo_data import ATTACK_EVENTS, HOST


def test_evidence_extraction_and_narration():
    graph = BehavioralGraph(HOST)
    for event in ATTACK_EVENTS:
        graph.ingest_event(event)
    graph.propagate_risk()

    mapper = MitreMapper()
    matches = mapper.map_events(ATTACK_EVENTS, graph)

    bundle = EvidenceExtractor().extract(graph, matches)
    assert bundle.host_id == HOST
    assert bundle.overall_risk_score > 0.5

    narrative = TemplateNarrator().narrate(bundle)
    assert HOST in narrative
    assert "Process Injection" in narrative


def test_chronological_timeline_generator():
    generator = AttackNarrativeGenerator()
    timeline = generator.generate_timeline(ATTACK_EVENTS)
    assert len(timeline) == len(ATTACK_EVENTS)
    summary = generator.generate_summary(timeline)
    assert "Attack timeline:" in summary
