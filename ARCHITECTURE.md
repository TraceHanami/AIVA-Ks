# CHRONOS — Architectural Blueprint & Subsystem Specification

```text
               +-------------------------------------------------------+
               |                  CHRONOS Web UI                       |
               |         (Vite + React + Tailwind + Lucide)           |
               +---------------------------+---------------------------+
                                           | HTTP / REST
                                           v
               +-------------------------------------------------------+
               |                    CHRONOS API                        |
               |            (FastAPI Domain-Driven App)                 |
               +-----+-------------+---------------+-------------+-----+
                     |             |               |             |
        +------------+   +---------+-----+   +-----+-------+  +--+----------+
        | Sensors    |   | Intelligence  |   | Investigation|  | Response   |
        | Collector  |   | Threat Intel  |   | Case Workspace|  | Policy Engine|
        | & Scanners |   | & Signatures  |   | Digital Twin |  | Executor   |
        +------------+   +---------------+   +-------------+  +-------------+
              |                  |                 |                 |
              +------------------+--------+--------+-----------------+
                                          |
                                          v
                         +-----------------------------------+
                         |         Research Engine           |
                         |  Causality Graph | MITRE Intelligence |
                         |  XAI Narrator    | GBT Predictor  |
                         |  UEBA Engine     | Asset Risk     |
                         +-----------------------------------+
```

---

## 1. Domain Architecture & Codebase Layout

The project follows **Domain-Driven Design (DDD)**, cleanly partitioning research software algorithms from OS-level infrastructure, web APIs, and CLI tooling.

```text
chronos/
├── config/                  # Global Pydantic settings & system profiles
│   ├── settings.py
│   └── __init__.py
├── research/                # Pure algorithmic research models & engines (Zero DB/API coupling)
│   ├── causality_engine.py  # Module 2: Behavioral Graph Builder & Risk Diffusion
│   ├── mitre_intelligence.py# Module 4: MITRE ATT&CK Mapper
│   ├── intent_predictor.py # Module 3: GBT Attack Intent & Vector Predictor
│   ├── threat_heatmap.py    # Module 5: 6-Dimensional Security Area Heatmap
│   ├── ueba_engine.py       # Module 17: User & Entity Behavior Analytics
│   ├── demo_data.py         # Synthetic attack datasets for reproducible research
│   ├── explainability/      # Module 6: Grounded XAI Attack Narrative Generator
│   │   ├── evidence.py
│   │   └── narrator.py
│   └── __init__.py
├── sensors/                 # Module 1: OS Telemetry Collection & Probe Interfaces
│   ├── collector.py         # Live Linux eBPF/Procfs syscall telemetry collector
│   └── __init__.py
├── intelligence/            # Module 10 & 11: Threat Intelligence & Static Heuristic Scanning
│   ├── threat_intel.py      # IOC Fusion Engine (APT29, Lazarus, Turla)
│   ├── scanner.py           # Antivirus Signature & Heuristic Pattern Engine
│   └── __init__.py
├── investigation/           # Module 12 & 19: Case Management & Digital Twin Replay
│   ├── case_workspace.py    # Multi-Analyst Case Binder Workspace
│   ├── replay_engine.py     # Attack Timeline Digital Twin Replay Engine
│   └── __init__.py
├── response/                # Module 9 & 15: Safety Policy & Automated OS Remediation
│   ├── policy_engine.py     # Policy Rules & Safety Invariants (Human-in-the-Loop)
│   ├── executor.py          # Containment Actions (File Quarantine, Process Isolation)
│   └── __init__.py
├── api/                     # Modular FastAPI Web Layer
│   ├── app.py               # Application Factory & Middleware
│   ├── state.py             # Engine State & Host Session Manager
│   └── routers/             # Domain API Routers
│       ├── dashboard.py
│       ├── cases.py
│       ├── threat_intel.py
│       ├── ueba.py
│       ├── actions.py
│       ├── copilot.py
│       ├── replay.py
│       └── scanner.py
└── cli/                     # Command Line Interface
    ├── main.py              # `chronos` CLI entrypoint
    └── __init__.py
```

---

## 2. 20-Module System Mapping

| Module | Subsystem Name | Package Location | Core Functionality |
| :--- | :--- | :--- | :--- |
| **M1** | Observe (Telemetry Collector) | `chronos.sensors.collector` | Live Linux syscall & process event collector |
| **M2** | Understand (Causality Graph) | `chronos.research.causality_engine` | Directional temporal causality graph builder & bounded risk diffusion |
| **M3** | Predict (Intent Engine) | `chronos.research.intent_predictor` | Machine learning attack vector & next-phase prediction |
| **M4** | Explain (MITRE Intelligence) | `chronos.research.mitre_intelligence` | System behavior to MITRE ATT&CK technique mapping |
| **M5** | Visualize (Heatmap Engine) | `chronos.research.threat_heatmap` | 6-area peak-weighted security posture scoring |
| **M6** | Explainability (XAI Narrator) | `chronos.research.explainability` | Evidence-grounded natural language attack narratives |
| **M7** | System Copilot | `chronos.api.routers.copilot` | Natural language SOC assistant with full graph context |
| **M8** | Dynamic Attack Timeline | `chronos.research.explainability.narrator` | Chronological event timeline reconstruction |
| **M9** | Response & Containment | `chronos.response.policy_engine` | Policy evaluation with human-in-the-loop safety enforcement |
| **M10** | Memory & File Scanner | `chronos.intelligence.scanner` | Static hash, regex signature, and heuristic dropper scanner |
| **M11** | Threat Intel Fusion | `chronos.intelligence.threat_intel` | Multi-source C2 IOC lookup and event enrichment |
| **M12** | Case Management Workspace | `chronos.investigation.case_workspace` | Analyst case binder, notes, and export system |
| **M13** | Detection Engineering Lab | `chronos.research.mitre_intelligence` | Rule validation and custom pattern matching |
| **M14** | Automated Playbooks | `chronos.response.policy_engine` | Remedial playbook evaluation |
| **M15** | OS Containment Executor | `chronos.response.executor` | File quarantine and process termination execution |
| **M16** | Asset Awareness | `chronos.research.causality_engine` | Domain Controller / Server asset blast-radius multipliers |
| **M17** | UEBA Engine | `chronos.research.ueba_engine` | Off-hours and credential store access anomaly detection |
| **M18** | Attack Surface Management | `chronos.research.threat_heatmap` | Surface area risk classification |
| **M19** | Digital Twin Attack Replay | `chronos.investigation.replay_engine` | Time-step digital twin attack replay and state inspection |
| **M20** | Executive Summary Generator | `chronos.research.explainability.narrator` | High-level non-technical executive breach summaries |

---

## 3. Data Processing Pipeline & Contracts

 telemetry processing follows a unidirectional flow:

```text
[Syscall / Event Telemetry]
            │
            ▼
   1. Sensor Ingestion & Enrichment (M1 + M11)
            │
            ▼
   2. Causality Graph Construction & Risk Diffusion (M2 + M16)
            │
            ▼
   3. MITRE ATT&CK & UEBA Anomaly Analysis (M4 + M17)
            │
            ▼
   4. Threat Heatmap & Intent Vector Prediction (M3 + M5)
            │
            ▼
   5. XAI Grounded Attack Narrative Generation (M6 + M8)
            │
            ▼
   6. Safety Policy Evaluation & Analyst Action Approval (M9 + M15)
```

---

## 4. Test Architecture

CHRONOS maintains strict test coverage across three isolated layers:

1. **Unit Tests (`tests/unit/`)**:
   - `test_causality.py`: Tests graph node creation, risk propagation, and asset risk multipliers.
   - `test_mitre.py`: Tests MITRE ATT&CK signature rules and false positive filter accuracy.
   - `test_explainability.py`: Tests evidence bundle extraction and narrative generation.
   - `test_policy.py`: Tests safety invariants (destructive actions default to RECOMMEND).
   - `test_scanner.py`: Tests static antivirus signatures and heuristic dropper detection.
   - `test_threat_intel.py`: Tests IOC lookups and automatic event enrichment.
   - `test_ueba.py`: Tests privilege escalation and credential access detection.

2. **Integration Tests (`tests/integration/`)**:
   - `test_integrated_pipeline.py`: Tests end-to-end telemetry flow from raw events to policy output.
   - `test_cases.py`: Tests Case Service lifecycle and Digital Twin replay snapshots.

3. **End-to-End Tests (`tests/e2e/`)**:
   - `test_api_e2e.py`: Exercises FastAPI endpoints using starlette/httpx test clients.
