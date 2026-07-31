# AIVA-KS — AI-Powered Intelligent Kernel Security Visualizer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Build Status](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)
[![Architecture](https://img.shields.io/badge/Architecture-CO--RE%20eBPF-orange.svg)](docs/ARCHITECTURE.md)

Research platform for kernel-level behavioral security monitoring with attack-intent prediction, explainability (XAI), threat heatmaps, and policy-governed response tooling.

```
     Observe ──► Understand ──► Predict ──► Explain ──► Visualize ──► Respond
```

---

## 🏛️ System Architecture

AIVA-KS captures low-level Linux syscall telemetry via CO-RE eBPF, constructs directed multi-entity attack graphs, maps evidence to MITRE ATT&CK techniques, and evaluates human-in-the-loop response policies.

```
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│   Linux Kernel & eBPF   │ ──► │  Go Collector & Kafka   │ ──► │ Feature Extraction &    │
│  (syscall tracepoints)  │     │   (raw event streams)   │     │ Behavioral Graph Engine │
└─────────────────────────┘     └─────────────────────────┘     └────────────┬────────────┘
                                                                             │
┌─────────────────────────┐     ┌─────────────────────────┐                  │
│    Response Engine      │ ◄── │   AI Analysis Engine    │ ◄────────────────┘
│ (policy-driven control) │     │ (Intent, MITRE, XAI)    │
└────────────┬────────────┘     └─────────────────────────┘
             │
             ▼
┌─────────────────────────┐
│ FastAPI REST/WS API     │ ──►  React/TS Dashboard
└─────────────────────────┘
```

For the complete system design and rationale, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 📊 Module Status Scorecard

Legend: ✅ Verified & Tested · 🟡 Implemented / Needs Infrastructure · ⬜ In Roadmap

| Phase | Status | Evidence / Details |
|---|---|---|
| **1. System Architecture** | ✅ | Full design specification in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| **2. Repo Structure** | ✅ | Standardized packaging with [`pyproject.toml`](pyproject.toml) & [`Makefile`](Makefile) |
| **3. eBPF Sensors** | 🟡 | CO-RE C probes for `execve`, `fork`, `ptrace`, `mprotect`, `connect`, `accept` in [`ebpf/src/`](ebpf/src/) |
| **4. Event Streaming** | 🟡 | Kafka + Zookeeper event topic definitions in [`streaming/`](streaming/) |
| **5. Database Schema** | 🟡 | PostgreSQL + TimescaleDB hypertable schema in [`database/schema/`](database/schema/) |
| **6. Feature Extraction** | 🟡 | Process lineage & memory flag extraction in [`ai/feature_extraction/`](ai/feature_extraction/) |
| **7. Behavioral Graph Engine** | ✅ | NetworkX-backed directed multigraph & bounded risk diffusion in [`ai/graph_engine/`](ai/graph_engine/) |
| **8. Attack Intent Prediction** | ✅ baseline | Gradient-boosted tree model trained in [`ai/intent_prediction/`](ai/intent_prediction/) |
| **9. MITRE ATT&CK Mapping** | ✅ | Signature mapper supporting T1055, T1003, T1041, T1071, T1059 in [`ai/mitre_mapping/`](ai/mitre_mapping/) |
| **10. Explainability Engine** | ✅ template / 🟡 LLM | Evidence-grounded narrative generator in [`ai/explainability/`](ai/explainability/) |
| **11. Attack Narrative Generator** | ✅ | Chronological attack timeline generation in [`ai/explainability/explainer.py`](ai/explainability/explainer.py) |
| **12. Threat Heatmap Engine** | ✅ | Weighted domain area aggregation (Process, Memory, Network, Filesystem) in [`ai/threat_heatmap/`](ai/threat_heatmap/) |
| **13. Incident Replay Engine** | ⬜ | Service interface in [`backend/app/services/`](backend/app/services/) |
| **14. Security Copilot (RAG)** | ⬜ | LLM prompt interface defined in [`ai/explainability/`](ai/explainability/) |
| **15. Response Engine** | ✅ policy logic | Safety invariant policy evaluation & audit logging in [`response-engine/`](response-engine/) |
| **16. Frontend Dashboard** | ⬜ | React/TypeScript UI component scaffolding in [`frontend/`](frontend/) |
| **17. FastAPI Backend** | 🟡 | Async API endpoints (`/api/health`, `/api/auth`) in [`backend/app/`](backend/app/) |
| **18. Deployment** | 🟡 | Container configuration in [`docker/`](docker/) |
| **19. Testing Framework** | ✅ | Automated Pytest suite with 11 passing tests in [`tests/`](tests/) |

---

## ⚡ Quickstart

### 1. Zero-Infrastructure Pipeline Demo
Run the end-to-end intelligence demo directly from the command line:

```bash
# Clone the repository
git clone https://github.com/your-username/aiva-ks.git
cd aiva-ks

# Run the full pipeline demo
python3 demo_full_pipeline.py
```

### 2. Run Automated Test Suite
```bash
python3 -m pytest tests/ -v
```
*or using the Makefile:*
```bash
make test
```

### 3. Developer Workflows (`Makefile`)
```bash
make help       # View all available developer commands
make setup      # Install python dependencies
make lint       # Run syntax and lint checks across the codebase
make clean      # Clean up cache files
```

---

## 📁 Directory Structure

```
aiva-ks/
├── ai/                 # Core AI Engine (Graph, MITRE mapping, XAI, Heatmaps)
├── backend/            # FastAPI REST & WebSocket Application
├── database/           # PostgreSQL / TimescaleDB Schemas & Migrations
├── docker/             # Docker Compose & Container Configurations
├── docs/               # System Architecture & Technical Specifications
├── ebpf/               # CO-RE eBPF C Sensor Probes
├── frontend/           # React + TypeScript Dashboard Scaffolding
├── response-engine/    # Policy Engine & Containment Decision Logic
├── streaming/          # Kafka Producer/Consumer Schemas
├── tests/              # Pytest Integration & Unit Test Suite
├── Makefile            # Developer Tooling & Task Automation
├── pyproject.toml      # Modern Python Package & Tooling Config
└── README.md           # Project Documentation
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
