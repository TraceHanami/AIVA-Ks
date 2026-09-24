# CHRONOS: Cyber Threat Understanding and Response Operating System

> **Research Contribution:** *An AI-assisted cyber investigation framework that transforms low-level system telemetry into attack timelines, intent predictions, explainable attack stories, and automated response recommendations.*

---

## 🎯 Executive Summary & The Final Pitch

> **CHRONOS is an AI-powered Cyber Investigation and Response Platform that continuously monitors system activity, reconstructs attack timelines, maps adversary behavior to MITRE ATT&CK, predicts attacker objectives, generates human-readable attack stories, and provides actionable defense recommendations to accelerate incident response.**

Traditional Endpoint Detection & Response (EDR) and Security Information & Event Management (SIEM) platforms operate on alert generation. When malware or suspicious activity is flagged, the burden of contextualization, causality reconstruction, and intent estimation falls entirely on the SOC analyst.

**CHRONOS shifts the paradigm from Alert Generation to Cyber Investigation.**

```
Traditional EDR:  Telemetry ──► Alert ──► Analyst Manual Triaging ──► Slow Response
CHRONOS OS:       Telemetry ──► Context ──► Graph & Intent ──► Explanation ──► Guided Response
```

---

## 🏛️ System Lifecycle

CHRONOS follows a 6-stage autonomous investigation lifecycle:

```
┌─────────┐     ┌────────────┐     ┌─────────┐     ┌───────────┐     ┌───────────┐     ┌─────────┐
│ Observe │ ──► │ Understand │ ──► │ Predict │ ──► │  Explain  │ ──► │ Visualize │ ──► │ Respond │
└─────────┘     └────────────┘     └─────────┘     └───────────┘     └───────────┘     └─────────┘
```

---

## 🧩 9-Module Architectural Taxonomy

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             MODULE 8: VISUALIZATION                              │
│         (Attack Graph Canvas · Forensics Timeline · MITRE Matrix · Heatmaps)    │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
┌────────────────────────────────────────┴─────────────────────────────────────────┐
│                           MODULE 7: EXPLAIN (XAI)                                │
│                   (Grounded Incident Narrative Generator)                        │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
┌───────────────────┬────────────────────┴────────────────────┬────────────────────┐
│ MODULE 4: GRAPH   │    MODULE 5: MITRE INTELLIGENCE        │ MODULE 6: PREDICT  │
│ (Causal Modeling) │   (Automated TTP Kill-Chain Mapper)     │  (Intent Scoring)  │
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

---

### Module 1: Observe (System Sensors)
* **Objective:** Serve as the system's high-fidelity eyes and ears at kernel depth.
* **Telemetry Collected:**
  - **Processes:** `execve`, `fork`, `clone`
  - **Filesystem:** `create`, `delete`, `rename`, `modify` (`open`, `write`, `unlink`)
  - **Network Sockets:** `connect`, `bind`, `accept`, `socket`, `listen`
  - **Security & Memory:** `ptrace`, `mprotect` (RWX flips), `sudo`, `setuid`
  - **Persistence:** `cron`, `systemd` service modifications, startup scripts
* **Underlying Stack:** CO-RE eBPF probes in C (`vmlinux.h`, `libbpf`), zero-copy Ring Buffers, and userspace collectors ([`ebpf/src/process_sensor.bpf.c`](file:///home/tracehanami/Github/AIVA-Ks/ebpf/src/process_sensor.bpf.c), [`ebpf/src/network_sensor.bpf.c`](file:///home/tracehanami/Github/AIVA-Ks/ebpf/src/network_sensor.bpf.c)).

---

### Module 2: Understand (Behavioral Abstraction)
* **Objective:** Translate raw syscall streams into meaningful threat actions.
* **Abstraction Layer:**
  - `curl / wget` + `chmod +x` $\longrightarrow$ **Payload Ingress & Staging**
  - `bash -i >& /dev/tcp` $\longrightarrow$ **Interactive Reverse Shell**
  - `open("/etc/shadow")` $\longrightarrow$ **Credential Access Attempt**
  - `mprotect(RWX) + ptrace()` $\longrightarrow$ **Process Injection & Shellcode Execution**
* **Code Reference:** [`ai/feature_extraction/extractor.py`](file:///home/tracehanami/Github/AIVA-Ks/ai/feature_extraction/extractor.py)

---

### Module 3: Attack Timeline
* **Objective:** Construct chronological attack sequences so responders immediately grasp attack velocity and ordering.
* **Example Progression:**
  ```text
  09:01  User Authentication / Shell Execution
  09:03  Payload Download via Curl (198.51.100.22)
  09:05  Binary Execution & RWX Memory Staging
  09:07  Reverse Shell Socket Opened to Port 8443
  09:10  Credential Store Read Attempt (/etc/shadow)
  ```
* **Code Reference:** [`ai/explainability/explainer.py`](file:///home/tracehanami/Github/AIVA-Ks/ai/explainability/explainer.py#L145-L179)

---

### Module 4: Attack Graph (Causality & Blast Radius)
* **Objective:** Convert isolated events into directed multi-entity graph structures showing parent-child process lineages, file operations, and socket connections.
* **Graph Topology:** Nodes (`Process`, `Thread`, `File`, `Socket`, `MemoryRegion`) and Edges (`creates`, `writes`, `reads`, `injects`, `connects`, `loads`).
* **Graph Risk Propagation:** Bounded risk diffusion algorithms score multi-hop blast radiuses.
* **Code Reference:** [`ai/graph_engine/graph_builder.py`](file:///home/tracehanami/Github/AIVA-Ks/ai/graph_engine/graph_builder.py#L41-L160)

---

### Module 5: MITRE ATT&CK Intelligence
* **Objective:** Map observed behavioral graph evidence to standard MITRE ATT&CK tactics and techniques.
* **TTP Coverage:**
  - `T1059`: Command and Scripting Interpreter
  - `T1105`: Ingress Tool Transfer
  - `T1055`: Process Injection
  - `T1003`: OS Credential Dumping
  - `T1041`: Exfiltration Over C2 Channel
  - `T1071`: Application Layer Protocol
* **Code Reference:** [`ai/mitre_mapping/mapping_engine.py`](file:///home/tracehanami/Github/AIVA-Ks/ai/mitre_mapping/mapping_engine.py#L33-L156)

---

### Module 6: Predict (Attack Intent Estimation)
* **Objective:** Forecast the adversary's ultimate objective (e.g. Credential Theft, Persistence, Ransomware Deployment, Data Exfiltration).
* **Machine Learning Pipeline:** Gradient Boosted Trees (GBT) and Temporal GNN classifiers trained on hand-engineered graph topology features, outputting objective class probabilities and next-action estimates.
* **Code Reference:** [`ai/intent_prediction/train_baseline.py`](file:///home/tracehanami/Github/AIVA-Ks/ai/intent_prediction/train_baseline.py#L38-L90)

---

### Module 7: Explain (XAI Story Generator)
* **Objective:** Convert technical graph data into audit-grounded, human-readable incident stories.
* **Core Differentiator:** Decouples deterministic evidence extraction (`EvidenceBundle`) from narration to guarantee **zero LLM hallucinations**.
* **Generated Narrative Example:**
  > *"On host `cachyos-x8664`, process `bash (PID 4260)` downloaded a remote payload and staged an RWX memory region. It executed `ptrace` against PID 4268 (Process Injection, T1055) and established an outbound socket connection to `198.51.100.22:8443` (Exfiltration C2, T1041). Overall blast risk score: 96%."*
* **Code Reference:** [`ai/explainability/explainer.py`](file:///home/tracehanami/Github/AIVA-Ks/ai/explainability/explainer.py#L31-L136)

---

### Module 8: Visualize (Analyst Workbench)
* **Objective:** Provide a unified SOC analyst workspace.
* **Dashboard Views:**
  1. **Interactive Causal Attack Graph Canvas** (`ReactFlow`)
  2. **Chronological Forensic Timeline View**
  3. **MITRE ATT&CK Tactical Matrix View**
  4. **Subsystem Threat Heatmap** (Process, Memory, Network, Filesystem)
* **Code Reference:** [`frontend/src/App.tsx`](file:///home/tracehanami/Github/AIVA-Ks/frontend/src/App.tsx)

---

### Module 9: Respond (Policy-Governed Containment)
* **Objective:** Guide defenders with actionable, policy-governed containment actions.
* **Remediation Capabilities:**
  - `ISOLATE_PROCESS`: Freeze execution via `SIGSTOP`
  - `ISOLATE_NETWORK`: Sever active socket connections / block IP
  - `QUARANTINE_FILE`: Move malicious file to isolated sandbox with permissions `000`
  - `MEMORY_SNAPSHOT`: Capture process memory dump
* **Safety Invariant:** Human-in-the-loop by default for destructive actions (`RECOMMEND` mode); non-destructive snapshots execute automatically (`AUTO` mode).
* **Code Reference:** [`response-engine/policy_engine.py`](file:///home/tracehanami/Github/AIVA-Ks/response-engine/policy_engine.py#L86-L208)

---

## 🌟 Strategic Identity & Value Proposition

| Stakeholder Audience | Key Value Proposition |
|---|---|
| **Academic Researchers** | Novel end-to-end framework combining CO-RE eBPF telemetry, bounded graph risk diffusion, and hallucination-free XAI narrative generation. |
| **SOC Analysts & Incident Responders** | Cuts Mean-Time-to-Respond (MTTR) by replacing manual log grepping with automated attack stories and 1-click containment. |
| **Security Executives & Judges** | Clear, intuitive narrative: *From raw alerts to complete understanding.* |

---

## 🏁 Conclusion

CHRONOS stands out because **it doesn't just detect alerts—it explains what happened, why it happened, what the attacker wants next, and how to stop them.**
