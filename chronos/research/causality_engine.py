"""
CHRONOS Research Module — Causality Engine (Module 4 & 16).

Implements per-host directed multi-entity attack graphs with bounded risk diffusion
and asset-criticality risk scaling.
"""
from __future__ import annotations

from dataclasses import dataclass
import networkx as nx
from chronos.config.settings import settings

EDGE_WEIGHTS = {
    "creates": 0.05,
    "writes": 0.10,
    "reads": 0.05,
    "injects": 0.80,   # ptrace/process-injection edges are high risk
    "connects": 0.15,
    "loads": 0.10,
}

ASSET_MULTIPLIERS = {
    "DOMAIN_CONTROLLER": 1.5,
    "DATABASE_SERVER": 1.3,
    "DEVELOPER_HOST": 1.1,
    "WORKSTATION": 1.0,
}


@dataclass
class NodeAttrs:
    node_type: str          # Process|Thread|File|Socket|MemoryRegion
    label: str
    risk: float = 0.0
    first_seen: str | None = None
    meta: dict | None = None


class BehavioralGraph:
    """Directed MultiDiGraph representing causal relationships and risk diffusion."""

    def __init__(self, host_id: str, asset_type: str = "WORKSTATION"):
        self.host_id = host_id
        self.asset_type = asset_type.upper()
        self.asset_multiplier = ASSET_MULTIPLIERS.get(self.asset_type, settings.DEFAULT_WORKSTATION_MULTIPLIER)
        self.g = nx.MultiDiGraph()

    def _node_id(self, node_type: str, key: str) -> str:
        return f"{node_type}:{key}"

    def add_node(self, node_type: str, key: str, **attrs) -> str:
        nid = self._node_id(node_type, key)
        if nid not in self.g:
            self.g.add_node(nid, type=node_type, risk=0.0, **attrs)
        return nid

    def add_edge(self, src: str, dst: str, relation: str, event_id: int, **attrs):
        weight = EDGE_WEIGHTS.get(relation, 0.05)
        self.g.add_edge(src, dst, key=relation, relation=relation,
                         weight=weight, event_id=event_id, **attrs)

    def ingest_event(self, event: dict):
        etype = event.get("syscall") or event.get("event_type", "execve")
        pid_key = f"{event.get('host_id', self.host_id)}:{event.get('pid', 0)}"
        proc_node = self.add_node("Process", pid_key, label=event.get("comm", "?"),
                                   first_seen=event.get("time"))

        if etype == "execve":
            self.g.nodes[proc_node]["cmdline"] = event.get("args", {}).get("filename")

        elif etype in ("fork", "clone"):
            child_key = f"{event.get('host_id', self.host_id)}:{event.get('args', {}).get('target_pid', event.get('pid'))}"
            child_node = self.add_node("Process", child_key, label="child",
                                        first_seen=event.get("time"))
            self.add_edge(proc_node, child_node, "creates", event.get("event_id", 0))

        elif etype in ("open", "write", "unlink"):
            path = event.get("args", {}).get("filename") or event.get("args", {}).get("path", "unknown")
            file_node = self.add_node("File", f"{event.get('host_id', self.host_id)}:{path}", label=path)
            relation = "writes" if etype in ("write", "unlink") else "reads"
            self.add_edge(proc_node, file_node, relation, event.get("event_id", 0))

        elif etype == "connect":
            args = event.get("args", {})
            sock_key = f"{event.get('host_id', self.host_id)}:{args.get('daddr')}:{args.get('dport')}"
            sock_node = self.add_node("Socket", sock_key,
                                       label=f"{args.get('daddr')}:{args.get('dport')}")
            self.add_edge(proc_node, sock_node, "connects", event.get("event_id", 0))

        elif etype == "ptrace":
            target_key = f"{event.get('host_id', self.host_id)}:{event.get('args', {}).get('target_pid')}"
            target_node = self.add_node("Process", target_key, label="ptrace_target")
            self.add_edge(proc_node, target_node, "injects", event.get("event_id", 0),
                           ptrace_request=event.get("args", {}).get("ptrace_request"))

        elif etype == "mprotect":
            feats = event.get("features", {})
            if feats.get("rwx_mprotect_flag"):
                mem_key = f"{event.get('host_id', self.host_id)}:{event.get('pid')}:{event.get('args', {}).get('addr')}"
                mem_node = self.add_node("MemoryRegion", mem_key, label="RWX region")
                self.add_edge(proc_node, mem_node, "loads", event.get("event_id", 0),
                               suspicious=True)

    def propagate_risk(self, decay: float = settings.DEFAULT_RISK_DECAY, iterations: int = settings.MAX_RISK_ITERATIONS):
        """Bounded risk diffusion scaled by asset criticality multiplier."""
        for n in self.g.nodes:
            out_edges = self.g.out_edges(n, data=True)
            base = max((d["weight"] for _, _, d in out_edges), default=0.0)
            self.g.nodes[n]["risk"] = max(self.g.nodes[n].get("risk", 0.0), base)

        for _ in range(iterations):
            updates = {}
            for n in self.g.nodes:
                inherited = 0.0
                for pred in self.g.predecessors(n):
                    inherited = max(inherited, self.g.nodes[pred]["risk"] * decay)
                raw_risk = max(self.g.nodes[n]["risk"], inherited)
                updates[n] = min(1.0, raw_risk * self.asset_multiplier)
            for n, r in updates.items():
                self.g.nodes[n]["risk"] = r

    def highest_risk_path(self, min_risk: float = settings.MIN_HIGH_RISK_THRESHOLD) -> list[str]:
        candidates = [n for n, d in self.g.nodes(data=True) if d.get("risk", 0) >= min_risk]
        if not candidates:
            return []
        end = max(candidates, key=lambda n: self.g.nodes[n]["risk"])
        path = [end]
        cur = end
        seen = {end}
        while True:
            preds = list(self.g.predecessors(cur))
            preds = [p for p in preds if p not in seen]
            if not preds:
                break
            nxt = max(preds, key=lambda p: self.g.nodes[p]["risk"])
            path.append(nxt)
            seen.add(nxt)
            cur = nxt
        return list(reversed(path))

    def to_json(self) -> dict:
        return {
            "host_id": self.host_id,
            "nodes": [{"id": n, **d} for n, d in self.g.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in self.g.edges(data=True)],
        }
