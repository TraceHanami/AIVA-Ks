# AIVA-KS — AI-Powered Intelligent Kernel Security Visualizer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![CI Pipeline](https://github.com/TraceHanami/AIVA-Ks/actions/workflows/ci.yml/badge.svg)](https://github.com/TraceHanami/AIVA-Ks/actions/workflows/ci.yml)
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

### 1. Setup Environment
```bash
# Clone the repository
git clone https://github.com/TraceHanami/AIVA-Ks.git
cd AIVA-Ks

# Install Python and Frontend dependencies
make setup
```

### 2. Run the Project

#### Option A: Run Full Stack (Backend API + React SOC Dashboard)
```bash
make run
```
- **Backend API**: [http://127.0.0.1:8000](http://127.0.0.1:8000) (Interactive OpenAPI docs at [`/docs`](http://127.0.0.1:8000/docs))
- **Frontend Dashboard**: [http://127.0.0.1:5173](http://127.0.0.1:5173)

#### Option B: Run Services Individually
```bash
# Run FastAPI Backend only
make run-backend

# Run React/Vite Frontend only
make run-ui
```

#### Option C: Run via Docker Compose
```bash
# Bring up PostgreSQL/TimescaleDB, Kafka, Zookeeper, Backend API, and Frontend
make docker-up

# Stop all containerized services
make docker-down
```

### 3. Check System Status (CLI)
```bash
make cli
# or directly:
chronos status
```

### 4. Linux & Ubuntu Early-Boot Security & Vulnerability Scan
Perform an instant kernel posture, SUID privilege hazard, persistence, and malware audit:
```bash
make boot-scan
# or via CLI:
chronos boot-scan
```
> For complete instructions to enable this as an automated early-boot service on Linux/Ubuntu, see [`PROCEDURE.md`](PROCEDURE.md).

### 5. Zero-Infrastructure Intelligence Pipeline Demos
Run the end-to-end intelligence and graph demos:
```bash
python3 demo_full_pipeline.py
python3 demo_run.py
```

### 6. Automated Test Suite
```bash
# Run 27+ integration, e2e, and unit tests
make test

# Run tests with coverage report
pytest tests/ -v --cov=chronos --cov=ai --cov-report=term
```

---

## 🚀 CI/CD Pipeline

AIVA-KS features an enterprise-grade GitHub Actions CI/CD automation matrix:

```
                  ┌────────────────────────────────────────────────────────┐
                  │                    GitHub Actions                      │
                  └───────────┬────────────────────────────────┬───────────┘
                              │                                │
                  ┌───────────▼───────────┐        ┌───────────▼───────────┐
                  │     CI Pipeline       │        │     CD Pipeline       │
                  │ (.github/workflows/   │        │ (.github/workflows/   │
                  │         ci.yml)       │        │         cd.yml)       │
                  └───────────┬───────────┘        └───────────┬───────────┘
                              │                                │
        ┌─────────────────────┼──────────────────────┐         │
        ▼                     ▼                      ▼         ▼
┌───────────────┐     ┌───────────────┐      ┌───────────────┐ ┌───────────────┐
│ Python Matrix │     │ Frontend      │      │ Docker Build  │ │ PyPI / Wheel  │
│ (3.10, 3.11,  │     │ oxlint, Vite  │      │ Verification  │ │ GHCR Images   │
│  3.12) Pytest │     │ Build & Assets│      │ (Multi-stage) │ │ GitHub Release│
└───────────────┘     └───────────────┘      └───────────────┘ └───────────────┘
```

1. **Continuous Integration ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))**:
   - **Python Test Matrix**: Validates Python syntax and runs 27 unit, integration, and E2E tests across Python 3.10, 3.11, and 3.12.
   - **Frontend CI**: Automates dependency caching, Oxlint static analysis, and TypeScript/Vite production builds.
   - **Docker Verification**: Validates Docker Compose configs and verifies multi-stage Docker builds for API engine, frontend dashboard, and feature extraction.
   - **Pipeline Demo Verification**: Runs `demo_full_pipeline.py` and `demo_run.py` to ensure runtime safety invariants hold.

2. **Continuous Delivery ([`.github/workflows/cd.yml`](.github/workflows/cd.yml))**:
   - **Package Distribution**: Builds source and binary `.whl` distributions.
   - **Container Registry Publishing**: Automatically builds, tags, and pushes production images to GitHub Container Registry (`ghcr.io`).
   - **Automated Releases**: Generates changelog and publishes GitHub Releases upon tag creation (`v*.*.*`).

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
