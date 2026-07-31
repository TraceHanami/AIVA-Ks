"""
AIVA-KS AI Engine Package.

Provides behavioral graph construction, MITRE ATT&CK mapping, evidence-grounded XAI
explainability, threat heatmaps, and attack intent prediction.
"""

from ai.explainability.explainer import (
    AttackNarrativeGenerator,
    EvidenceExtractor,
    LLMNarrator,
    TemplateNarrator,
)
from ai.graph_engine.graph_builder import BehavioralGraph, NodeAttrs
from ai.mitre_mapping.mapping_engine import MitreMapper, Technique, TechniqueMatch
from ai.threat_heatmap.heatmap_engine import AreaScore, ThreatHeatmapEngine

__all__ = [
    "BehavioralGraph",
    "NodeAttrs",
    "MitreMapper",
    "Technique",
    "TechniqueMatch",
    "EvidenceExtractor",
    "TemplateNarrator",
    "LLMNarrator",
    "AttackNarrativeGenerator",
    "ThreatHeatmapEngine",
    "AreaScore",
]
