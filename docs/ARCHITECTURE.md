# AIVA-KS — AI-Powered Intelligent Kernel Security Visualizer
## System Architecture (v0.1)

## 1. Design Philosophy

    Observe -> Understand -> Predict -> Explain -> Visualize -> Respond

AIVA-KS is a **research platform**, not a production EDR replacement. Every
component is built so that raw kernel telemetry can be traced end-to-end to
a human-readable explanation and (optionally) a bounded containment action.
The system is intentionally split into independently-deployable services so
that any one layer (e.g. the intent-prediction model) can be swapped or
re-trained without touching the others.

## 2. Layer-by-Layer Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Linux Kernel                                                         │
│   syscalls: execve, fork, clone, open, read, write, unlink, connect, │
│   accept, ptrace, mprotect, mmap, socket, bind, listen               │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ tracepoints / kprobes (CO-RE)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ eBPF Sensor Layer (C, libbpf, BPF ring buffer)                       │
│   - per-syscall BPF programs write fixed-size event structs          │
│   - ring buffer -> userspace collector (Go or C)                     │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ protobuf / JSON events over Unix socket
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Event Collection Layer (Go collector daemon)                         │
│   - schema validation, host metadata enrichment, batching            │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ produce
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Streaming Layer (Kafka)                                              │
│   topics: raw.syscalls, raw.network, raw.file, enriched.events       │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ consume
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Feature Extraction Engine (Python, Faust/consumer)                   │
│   syscall frequency, parent-child lineage, entropy, burst detection  │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Behavioral Graph Engine (NetworkX -> Neo4j)                          │
│   nodes: Process/Thread/File/Socket/MemoryRegion                     │
│   edges: creates/writes/reads/injects/connects/loads                 │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ AI Analysis Engine                                                    │
│   ├─ Attack Intent Prediction (Temporal GNN / Transformer, PyTorch)  │
│   ├─ MITRE ATT&CK Mapping Engine (rule + embedding hybrid)           │
│   └─ Explainability Engine (evidence extraction + LLM narration)     │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Response Engine (policy-driven, human-in-the-loop by default)        │
│   isolate process/network, quarantine, snapshot, alert — NEVER kill  │
│   irreversible actions without an explicit approval policy           │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ FastAPI Backend  -->  React/TS Dashboard  +  Security Copilot (RAG)  │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. Why these technology choices

| Layer | Choice | Rationale |
|---|---|---|
| Kernel sensing | eBPF + CO-RE + libbpf | No kernel module to compile per-host; portable across kernel versions; safe (verifier-checked) |
| Transport | Kafka | Durable, replayable (needed for Incident Replay Engine), partitionable by host/pid |
| Storage | PostgreSQL + TimescaleDB | Relational integrity for entities (processes, alerts) + hypertables for high-cardinality time-series events |
| Graph | NetworkX (dev) → Neo4j (prod) | NetworkX has zero infra cost for research iteration; Neo4j needed once graphs exceed single-process memory / need Cypher traversal at scale |
| ML | PyTorch, Temporal GNN | Attack behavior is inherently a graph that evolves over time — a static classifier throws away sequence information |
| Backend | FastAPI | Async-native (needed for WebSocket live graph updates), Pydantic validation, OpenAPI for free |
| Frontend | React + TS + Tailwind | Standard, large ecosystem of graph-viz libs (react-flow, cytoscape.js) |

## 4. Security Considerations (platform itself)

- The eBPF collector runs as a privileged daemon — it must be the **only**
  privileged process; everything downstream runs unprivileged.
- Kafka topics carrying raw events should be encrypted in transit (TLS) and
  access-controlled (SASL/SCRAM) since raw syscall data can contain
  sensitive arguments (file paths, command lines, env vars).
- The Response Engine must default to **detect-and-recommend**, not
  **auto-contain**, in any multi-tenant or production-adjacent deployment.
  Auto-response is opt-in per policy and requires audit logging of every
  action taken, by whom/what triggered it, and a rollback path.
- The chatbot and explainability LLM calls must never receive raw
  credentials/secrets captured incidentally in syscall args — redact before
  it leaves the feature-extraction boundary.

## 5. Scalability Considerations

- Kafka partition key = host_id so all events for a host stay ordered.
- TimescaleDB hypertable chunking on `time` (1-day chunks) + continuous
  aggregates for the heatmap engine so dashboards don't scan raw events.
- Graph engine shards by host/session — cross-host lateral-movement
  correlation happens as a second-pass batch job, not inline.
- Model inference served separately (TorchServe / Triton) from the FastAPI
  API layer so GPU inference scaling is independent of API request load.

## 6. Repository Layout

```
aiva-ks/
├── backend/            # FastAPI app: REST + WebSocket API
├── frontend/           # React/TS dashboard
├── ebpf/               # eBPF C programs + userspace Go/C collector
├── streaming/          # Kafka producers/consumers, schemas
├── ai/                 # feature extraction, graph engine, intent model, XAI
├── response-engine/    # policy engine + action executors
├── database/           # SQL schema, migrations
├── docker/             # Dockerfiles, docker-compose
├── kubernetes/         # k8s manifests
├── docs/               # architecture, diagrams
├── research/           # thesis/methodology, eval framework
├── tests/              # cross-service integration tests
└── scripts/            # dev tooling
```

## 7. Build Roadmap (MVP → Advanced)

1. **MVP-0**: eBPF execve/connect sensor → Kafka → Postgres raw event table → simple React table view.
2. **MVP-1**: + feature extraction + NetworkX graph + rule-based risk scoring (no ML yet).
3. **MVP-2**: + intent prediction model (start with gradient-boosted trees on graph features before GNN) + MITRE mapping.
4. **MVP-3**: + explainability (LLM narration) + attack narrative generator + heatmap.
5. **MVP-4**: + incident replay + security copilot (RAG) + response engine + full dashboard.
6. **Research phase**: dataset curation, ablations, evaluation against known attack emulation (e.g. Atomic Red Team), writeup.

This document is the contract the rest of the phases implement against.
