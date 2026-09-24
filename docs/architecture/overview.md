# System Architecture Overview

CHRONOS is an enterprise-grade Cyber Threat Understanding and Response Operating System designed to convert low-level system telemetry into structured, explainable cyber investigations.

## Core Architectural Principles

1. **Domain-Driven Design (DDD)**: Code is organized strictly by security domain rather than arbitrary technical layers.
2. **Research Isolation**: Pure algorithmic code (`chronos/research/`) has zero external database or framework dependencies, enabling isolated scientific evaluation and unit testing.
3. **Human-in-the-Loop Safety Invariant**: Containment actions affecting system integrity (file quarantine, process termination, network isolation) strictly require explicit SOC analyst authorization before execution.
4. **Zero-Infra Reproducibility**: High-fidelity research demonstration and integration testing run entirely in memory without requiring Kafka, Postgres, or external LLM API keys.

## Component Subsystems

- **Sensors (`chronos.sensors`)**: Gathers Linux process and syscall events from kernel tracing probes.
- **Intelligence (`chronos.intelligence`)**: Fuses C2 threat intelligence feeds and performs static heuristic code scanning.
- **Research (`chronos.research`)**: Executes causality graph risk propagation, MITRE ATT&CK technique mapping, UEBA anomaly scoring, 6-dimensional area heatmaps, GBT attack prediction, and XAI evidence narration.
- **Investigation (`chronos.investigation`)**: Manages multi-analyst case workspace binders and provides digital twin attack replay capabilities.
- **Response (`chronos.response`)**: Evaluates safety policies and executes authorized OS-level containment actions.
- **API & UI (`chronos.api` / `frontend/`)**: Exposes REST endpoints and renders a real-time reactive SOC analyst interface.
