"""
CHRONOS Research Module — Threat Heatmap Engine (Module 8).

Aggregates per-node risk from the behavioral graph into area-level scores
(process, network, filesystem, memory) for dashboard rendering.
"""
from __future__ import annotations

from dataclasses import dataclass

AREA_BY_NODE_TYPE = {
    "Process": "process",
    "Thread": "process",
    "File": "filesystem",
    "Socket": "network",
    "MemoryRegion": "memory",
}

AREAS = ["process", "network", "filesystem", "memory"]


@dataclass
class AreaScore:
    area: str
    score: float          # 0-1
    peak_node: str | None
    peak_risk: float
    node_count: int


class ThreatHeatmapEngine:
    def __init__(self, peak_weight: float = 0.7, avg_weight: float = 0.3):
        assert abs(peak_weight + avg_weight - 1.0) < 1e-6
        self.peak_weight = peak_weight
        self.avg_weight = avg_weight

    def compute(self, graph) -> dict[str, AreaScore]:
        buckets: dict[str, list[tuple[str, float]]] = {a: [] for a in AREAS}

        for node_id, data in graph.g.nodes(data=True):
            area = AREA_BY_NODE_TYPE.get(data.get("type"))
            if area:
                buckets[area].append((node_id, data.get("risk", 0.0)))

        result = {}
        for area, nodes in buckets.items():
            if not nodes:
                result[area] = AreaScore(area, 0.0, None, 0.0, 0)
                continue
            peak_node, peak_risk = max(nodes, key=lambda n: n[1])
            avg_risk = sum(r for _, r in nodes) / len(nodes)
            score = self.peak_weight * peak_risk + self.avg_weight * avg_risk
            result[area] = AreaScore(area, min(1.0, score), peak_node, peak_risk, len(nodes))
        return result

    def to_dashboard_json(self, scores: dict[str, AreaScore]) -> dict:
        return {
            area: {
                "score": round(s.score, 3),
                "peak_node": s.peak_node,
                "peak_risk": round(s.peak_risk, 3),
                "node_count": s.node_count,
            }
            for area, s in scores.items()
        }
