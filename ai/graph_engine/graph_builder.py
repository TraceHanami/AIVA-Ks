"""
AIVA-KS Behavioral Graph Engine.

Consumes `enriched.events` and incrementally builds a per-host directed
multigraph:

    Nodes: Process, Thread, File, Socket, MemoryRegion
    Edges: creates, writes, reads, injects, connects, loads

Backed by NetworkX for research iteration. The `Neo4jGraphStore` adapter
at the bottom shows the swap-in path once graphs exceed single-process
memory or need Cypher-based cross-host traversal.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import networkx as nx

EDGE_WEIGHTS = {
    # base risk contribution of each behavior, used by risk propagation
    "creates": 0.05,
    "writes": 0.10,
    "reads": 0.05,
    "injects": 0.80,   # ptrace/process-injection edges are high risk
    "connects": 0.15,
    "loads": 0.10,
}


@dataclass
class NodeAttrs:
    node_type: str          # Process|Thread|File|Socket|MemoryRegion
    label: str
    risk: float = 0.0
    first_seen: str | None = None
    meta: dict | None = None


class BehavioralGraph:
    """One instance per host (or per investigation session)."""

    def __init__(self, host_id: str):
        self.host_id = host_id
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

    # ---------- ingestion ----------

    def ingest_event(self, event: dict):
        etype = event["syscall"]
        pid_key = f"{event['host_id']}:{event['pid']}"
        proc_node = self.add_node("Process", pid_key, label=event.get("comm", "?"),
                                   first_seen=event["time"])

        if etype == "execve":
            self.g.nodes[proc_node]["cmdline"] = event.get("args", {}).get("filename")

        elif etype in ("fork", "clone"):
            child_key = f"{event['host_id']}:{event.get('args', {}).get('target_pid', event['pid'])}"
            child_node = self.add_node("Process", child_key, label="child",
                                        first_seen=event["time"])
            self.add_edge(proc_node, child_node, "creates", event.get("event_id", 0))

        elif etype in ("open", "write", "unlink"):
            path = event.get("args", {}).get("filename") or event.get("args", {}).get("path", "unknown")
            file_node = self.add_node("File", f"{event['host_id']}:{path}", label=path)
            relation = "writes" if etype in ("write", "unlink") else "reads"
            self.add_edge(proc_node, file_node, relation, event.get("event_id", 0))

        elif etype == "connect":
            args = event.get("args", {})
            sock_key = f"{event['host_id']}:{args.get('daddr')}:{args.get('dport')}"
            sock_node = self.add_node("Socket", sock_key,
                                       label=f"{args.get('daddr')}:{args.get('dport')}")
            self.add_edge(proc_node, sock_node, "connects", event.get("event_id", 0))

        elif etype == "ptrace":
            target_key = f"{event['host_id']}:{event.get('args', {}).get('target_pid')}"
            target_node = self.add_node("Process", target_key, label="ptrace_target")
            self.add_edge(proc_node, target_node, "injects", event.get("event_id", 0),
                           ptrace_request=event.get("args", {}).get("ptrace_request"))

        elif etype == "mprotect":
            feats = event.get("features", {})
            if feats.get("rwx_mprotect_flag"):
                mem_key = f"{event['host_id']}:{event['pid']}:{event.get('args', {}).get('addr')}"
                mem_node = self.add_node("MemoryRegion", mem_key, label="RWX region")
                self.add_edge(proc_node, mem_node, "loads", event.get("event_id", 0),
                               suspicious=True)

    # ---------- risk propagation ----------

    def propagate_risk(self, decay: float = 0.7, iterations: int = 3):
        """
        Simple bounded diffusion: each node's risk = its own edge-derived
        risk + decayed risk inherited from predecessors, repeated for a
        few iterations so multi-hop chains (e.g. loader -> injector ->
        exfil socket) accumulate risk along the path without it exploding
        (bounded via decay < 1 and a final clamp to [0, 1]).
        """
        # seed: risk from outgoing edge weights
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
                updates[n] = min(1.0, max(self.g.nodes[n]["risk"], inherited))
            for n, r in updates.items():
                self.g.nodes[n]["risk"] = r

    def highest_risk_path(self, min_risk: float = 0.5) -> list[str]:
        """Return the node sequence of the highest-risk chain, for the narrative generator."""
        candidates = [n for n, d in self.g.nodes(data=True) if d.get("risk", 0) >= min_risk]
        if not candidates:
            return []
        end = max(candidates, key=lambda n: self.g.nodes[n]["risk"])
        # walk backward via highest-risk predecessor until none remain
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
        """Serialize for storage in attack_graphs.graph_json / dashboard rendering."""
        return {
            "host_id": self.host_id,
            "nodes": [{"id": n, **d} for n, d in self.g.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in self.g.edges(data=True)],
        }


class Neo4jGraphStore:
    """
    Production adapter — same ingest_event/propagate_risk interface,
    backed by Cypher MERGE statements instead of in-memory NetworkX,
    for graphs that need cross-host correlation or exceed single-process
    memory. Swap-in once MVP-1 graph volume outgrows NetworkX.

        MERGE (p:Process {id: $pid_key}) ON CREATE SET p.label = $label
        MERGE (f:File {id: $file_key})
        MERGE (p)-[:WRITES {event_id: $event_id}]->(f)

    Risk propagation becomes a Cypher/GDS PageRank-style query instead of
    the pure-Python loop above.
    """
    pass
