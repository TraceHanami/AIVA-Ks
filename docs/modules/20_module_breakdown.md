# 20-Module Architecture Specification

CHRONOS implements a full 20-module cybersecurity platform architecture divided into 7 core lifecycle phases.

## Phase 1: Telemetry & Observation
- **Module 1 (Observe - Telemetry Collector)**: Ingests raw syscall telemetry (`execve`, `fork`, `mprotect`, `ptrace`, `openat`, `connect`) from kernel probes and standardizes attributes.

## Phase 2: Causality & Context
- **Module 2 (Understand - Causality Graph)**: Builds a directed acyclic temporal causality graph linking processes, files, network sockets, and users, propagating risk scores via bounded diffusion.
- **Module 16 (Asset Awareness Engine)**: Applies asset criticality risk multipliers (e.g., 1.5x score boost for Domain Controllers and Database Production Hosts).
- **Module 17 (UEBA Engine)**: Analyzes user privilege escalation and off-hours credential store access anomalies.

## Phase 3: Threat Intelligence & Detection
- **Module 4 (MITRE ATT&CK Mapper)**: Evaluates behavioral graph patterns against MITRE ATT&CK techniques (T1055 Process Injection, T1003 Credential Dumping, T1041 Exfiltration).
- **Module 10 (Memory & Heuristic Scanner)**: Performs static hash lookups and heuristic regex pattern scanning for reverse shells, droppers, and miners.
- **Module 11 (Threat Intel Fusion)**: Enriches telemetry with known threat actor C2 IOC feeds (APT29, Lazarus Group, Turla).
- **Module 13 (Detection Engineering Lab)**: Provides rule prototyping and custom signature validation against telemetry.

## Phase 4: Attack Prediction & Surface Analysis
- **Module 3 (Predict - Intent Predictor)**: Uses Gradient Boosted Trees (GBT) to predict attacker intent, likely target assets, and next-phase kill-chain vectors.
- **Module 5 (Visualize - Threat Heatmap)**: Aggregates risk across 6 security areas (Process, Memory, File System, Network, User Privilege, Persistence) using peak-weighted scoring.
- **Module 18 (Attack Surface Management)**: Classifies system surface exposure and vulnerability windows.

## Phase 5: Explainability & Investigation
- **Module 6 (Explainability - XAI Narrator)**: Extracts evidence event bundles and synthesizes deterministic, grounded natural language attack narratives without hallucination risk.
- **Module 8 (Dynamic Attack Timeline)**: Reconstructs chronological step-by-step attack sequences.
- **Module 12 (Case Management Workspace)**: Provides analyst binder creation, status updates, analyst notes, and executive artifact export.
- **Module 19 (Digital Twin Attack Replay)**: Enables step-by-step temporal state replay and investigation of past security incidents.
- **Module 20 (Executive Summary Generator)**: Generates high-level breach summaries for non-technical leadership.

## Phase 6: Interactive Guidance
- **Module 7 (System Copilot)**: Conversational security copilot aware of live host state, causality graphs, and pending containment actions.

## Phase 7: Response & Remediation
- **Module 9 (Response & Containment Policy Engine)**: Evaluates policy rules against risk and technique confidence, strictly marking destructive actions as `RECOMMEND` (awaiting approval).
- **Module 14 (Automated Playbooks)**: Evaluates automated non-destructive workflows (e.g., memory snapshots).
- **Module 15 (OS Containment Executor)**: Executes authorized containment actions (file quarantine, SIGSTOP process freeze, iptables network isolation).
