# CHRONOS: Cyber Threat Understanding and Response Operating System

> **Platform Overview:** *A next-generation, AI-powered Cyber Investigation & Response Operating System (XDR/EDR-Grade Research Platform) that transforms low-level Linux kernel syscall telemetry into chronological attack timelines, multi-entity attack graphs, MITRE ATT&CK mappings, attacker intent predictions, hallucination-free attack stories, and safety-governed defense recommendations.*

---

## 🎯 Executive Overview & Elevator Pitch

> **CHRONOS is an AI-powered Cyber Investigation and Response Platform that continuously monitors system activity, reconstructs attack timelines, maps adversary behavior to MITRE ATT&CK, predicts attacker objectives, generates human-readable attack stories, and provides actionable defense recommendations to accelerate incident response.**

Traditional Endpoint Detection & Response (EDR) and Security Information & Event Management (SIEM) tools generate thousands of disconnected alerts:
- `Alert 1: PowerShell Executed`
- `Alert 2: Outbound Connection Port 8443`
- `Alert 3: ptrace Syscall Initiated`
- `Alert 4: Credential Store Opened`

This forces SOC analysts to perform manual log grepping and mental causality reconstruction. **CHRONOS replaces manual triaging with automated cyber investigation.**

```
Traditional EDR:  Telemetry ──► Alert ──► Analyst Manual Triaging ──► Slow Response
CHRONOS OS:       Telemetry ──► Context ──► Graph & Intent ──► Explanation ──► Guided Response
```

---

## 🎨 Design Philosophy & Visual Aesthetic

Designed for modern SOC Analysts, Incident Responders, and Security Engineers, CHRONOS blends the enterprise strength of **CrowdStrike Falcon, SentinelOne, Microsoft Defender XDR, Elastic Security, Datadog Security**, and the minimalist elegance of **Linear.app**:

- **Dark Theme Palette:** Background `#0b0e14`, panel containers `#121620`, borders `#1e2638`, with subtle indigo, cyan, amber, and red risk accents.
- **Typography Standard:** `Inter` for all UI text and `JetBrains Mono` for technical data (PIDs, IP addresses, eBPF syscalls, timestamps, and hashes).
- **First 5-Second Assessment Rule:** The UI immediately answers:
  1. **What happened?** (Grounded AI narrative summary)
  2. **How severe is it?** (Color-coded blast risk score %)
  3. **What should I do next?** (1-click policy containment recommendations)

---

## 🏛️ Complete 20-Module System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         MODULE 8: VISUALIZATION DASHBOARD                        │
│   (Overview · Investigations · Timeline · Graph · MITRE · AI Copilot · Response) │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
┌───────────────────┬────────────────────┴────────────────────┬────────────────────┐
│ MODULE 7: EXPLAIN │    MODULE 11: THREAT INTEL FUSION      │ MODULE 12: CASES   │
│ (Zero-LLM Narrative) │ (APT29 / Lazarus / FIN7 / IOC Feeds)  │ (Case Workspace #412)│
└───────────────────┴────────────────────┬────────────────────┴────────────────────┘
                                         │
┌───────────────────┬────────────────────┴────────────────────┬────────────────────┐
│ MODULE 4: GRAPH   │    MODULE 5: MITRE INTELLIGENCE        │ MODULE 6: PREDICT  │
│ (MultiDiGraph)    │   (Automated TTP Kill-Chain Mapper)     │  (Intent Scoring)  │
└───────────────────┴────────────────────┬────────────────────┴────────────────────┘
                                         │
┌───────────────────┬────────────────────┴────────────────────┬────────────────────┐
│ MODULE 10: MEMORY │    MODULE 17: UEBA ENGINE              │ MODULE 16: ASSET   │
│ (ptrace / RWX)    │  (Privilege Shifts & Off-Hours Access)  │ (Risk Weighting)   │
└───────────────────┴────────────────────┬────────────────────┴────────────────────┘
                                         │
┌────────────────────────────────────────┴─────────────────────────────────────────┐
│                          MODULE 3: ATTACK TIMELINE                               │
│                   (Chronological Event Chain Sequencing)                         │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
┌────────────────────────────────────────┴─────────────────────────────────────────┐
│                     MODULE 2: UNDERSTAND (ABSTRACTION)                           │
│                 (Syscall Telemetry ──► Attacker Behaviors)                        │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
┌────────────────────────────────────────┴─────────────────────────────────────────┐
│                       MODULE 1: OBSERVE (eBPF SENSORS)                           │
│              (CO-RE Probes: execve, fork, connect, mprotect, ptrace)             │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Module Descriptions & Capabilities

1. **Module 1: Observe (eBPF CO-RE Probes)**: Captures kernel syscalls (`execve`, `fork`, `clone`, `open`, `unlink`, `connect`, `accept`, `bind`, `ptrace`, `mprotect`) via zero-copy Ring Buffers in C.
2. **Module 2: Understand (Syscall Abstraction)**: Translates raw syscalls into threat behaviors (e.g. `curl + chmod` $\rightarrow$ Ingress, `mprotect(RWX) + ptrace` $\rightarrow$ Injection).
3. **Module 3: Attack Timeline**: Constructs sequential chronological attack histories with timestamps, PIDs, and anomaly scores.
4. **Module 4: Attack Graph Builder**: NetworkX directed multigraph mapping process parentage, file modifications, socket connections, and memory regions with bounded risk diffusion.
5. **Module 5: MITRE ATT&CK Intelligence**: Hybrid signature engine classifying T1059, T1105, T1055, T1003, T1041, T1071 with confidence scores.
6. **Module 6: Predict (Attack Intent)**: Gradient Boosted Trees forecasting adversary objectives (Credential Theft, Persistence, Exfiltration, Ransomware).
7. **Module 7: Explain (XAI Story Generator)**: Two-stage evidence extraction (`EvidenceBundle`) + narration ensuring zero hallucinations.
8. **Module 8: Visualize (Analyst UI)**: Modern ReactFlow graph canvas, forensics timeline, MITRE matrix, heatmaps, case workspace, and AI copilot.
9. **Module 9: Respond (Policy Engine)**: Policy-governed remediation enforcing `SIGSTOP` process freezes, IP blocking, file quarantine, and host isolation.
10. **Module 10: Memory Intelligence**: RWX memory allocation tracking and `ptrace` injection monitoring.
11. **Module 11: Threat Intel Fusion**: IOC enrichment matching APT29, Lazarus, FIN7, and LockBit indicators.
12. **Module 12: Case Workspace**: Formal case management (`Case #412`), evidence linking, analyst notes, and JSON case binder exports.
13. **Module 13: Confidence Engine**: Explicit percentage metrics on technique matches and intent predictions.
14. **Module 14: Evidence Linking**: Narrative statements citing exact eBPF event IDs (`evidence_event_ids: [1, 2, 3]`).
15. **Module 15: Adversary Emulation**: Built-in attack simulators and 1-click **Inject Attack** button.
16. **Module 16: Asset Awareness**: Criticality-weighted blast risk multipliers (Domain Controller 1.5x, DB Server 1.3x).
17. **Module 17: UEBA Engine**: Detection of privilege escalations (`sudo`/`setuid`), off-hours activity, and credential file reads.
18. **Module 18: Threat Hunting Engine**: Filterable syscall stream search and CLI defender scanning utilities (`aiva_cli.py`).
19. **Module 19: Digital Twin Replay Engine**: Step-by-step snapshot replay predicting future attack paths.
20. **Module 20: Autonomous Agent**: Background telemetry collector & AI Copilot for automated graph triaging.

---

## 🖥️ Page-by-Page Platform Navigation

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ 🏠 Overview  🔍 Investigations  📅 Timeline  🕸 Graph  🎯 MITRE  🧠 AI  🛡 Response│
└──────────────────────────────────────────────────────────────────────────────────┘
```

1. 🏠 **Overview Page**: High-level SOC dashboard featuring 5 KPI cards (Threat Level, Active Cases, Syscall Events, MITRE TTPs, Monitor Assets), a large AI Executive Summary card, Recent Investigations panel, Threat Intel Hits panel, and Subsystem Risk Matrix.
2. 🔍 **Investigations Page**: Interactive multi-entity ReactFlow graph canvas paired with a right Entity Inspector pane for process lineage, open sockets, risk scores, and raw attributes.
3. 📅 **Attack Timeline Page**: Chronological event progression view with instant search and risk filters (`Score ≥ 0.5`, `Score ≥ 0.8`).
4. 🕸 **Attack Graph Page**: Full-screen graph canvas with zoom/pan controls, minimap, color-coded node risk highlights, and edge relationship weights.
5. 🎯 **MITRE ATT&CK Page**: Tactical kill-chain matrix displaying technique cards (`T1059`, `T1105`, `T1055`, `T1003`, `T1041`, `T1071`) with confidence badges and evidence citations.
6. 🧠 **AI Analyst Page**: ChatGPT-like Copilot interface with 6 suggested prompt chips (`What happened?`, `Explain attack path`, `Why is this suspicious?`, `Show attacker objective`, `Recommend containment`, `Generate incident report`).
7. 🛡 **Response Center**: Containment Action Buttons (`[Kill Process]`, `[Block IP]`, `[Quarantine File]`, `[Disable Persistence]`, `[Isolate Host]`), Pending Approvals Queue, and Audit Log.
8. 📁 **Cases Page**: Enterprise Case Workspace (`CASE-412`) showing title, assigned analyst, status, notes, verdict, and binder export.
9. ⚙ **Settings Page**: eBPF Kernel Sensor controls and Asset Risk Multipliers.

---

## 🧪 Verification & Empirical Testing

All 26 automated unit and integration tests across the 20-module stack pass cleanly:

```bash
$ .venv/bin/pytest tests/ -v
============================== 26 passed in 0.21s ==============================
```

Frontend production build status:
```bash
$ cd frontend && npm run build
✓ built in 470ms
```

Live services are running locally at:
- **FastAPI AI Server**: [`http://localhost:8000`](http://localhost:8000)
- **SOC React Dashboard**: [`http://localhost:5173`](http://localhost:5173)
