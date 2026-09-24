"""Unit tests for CHRONOS MITRE ATT&CK Intelligence Mapper."""
import pytest
from chronos.research.causality_engine import BehavioralGraph
from chronos.research.mitre_intelligence import MitreMapper
from chronos.research.demo_data import ATTACK_EVENTS, BENIGN_EVENTS, HOST


def test_mitre_signature_matching():
    graph = BehavioralGraph(HOST)
    for event in ATTACK_EVENTS:
        graph.ingest_event(event)
    mapper = MitreMapper()
    matches = mapper.map_events(ATTACK_EVENTS, graph)
    technique_ids = {m.technique.technique_id for m in matches}

    assert "T1055" in technique_ids  # Process Injection
    assert "T1003" in technique_ids  # Credential Access


def test_mitre_ignores_benign_events():
    graph = BehavioralGraph(HOST)
    for event in BENIGN_EVENTS:
        graph.ingest_event(event)
    mapper = MitreMapper()
    matches = mapper.map_events(BENIGN_EVENTS, graph)
    technique_ids = {m.technique.technique_id for m in matches}

    assert "T1055" not in technique_ids
    assert "T1003" not in technique_ids
