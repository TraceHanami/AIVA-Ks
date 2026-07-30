# AIVA-KS — AI-Powered Intelligent Kernel Security Visualizer

Research platform for kernel-level behavioral security monitoring with
attack-intent prediction, explainability, and analyst tooling.

    Observe -> Understand -> Predict -> Explain -> Visualize -> Respond

See `docs/ARCHITECTURE.md` for the full system design and rationale.

## Status (honest scorecard)

Legend: ✅ verified (actually run, output checked) · 🟡 written but unverified (no infra/hardware to run it here) · ⬜ not started

| Phase | Status | Evidence |
|---|---|---|
| 1. System Architecture | ✅ | design doc, no code to run |
| 2. Repo Structure | ✅ | N/A |
| 3. eBPF Kernel Monitoring | 🟡 ~60% written | Real C (execve/fork/ptrace/mprotect/connect/accept/socket/listen), never compiled — needs a real Linux kernel with CAP_BPF, not available in this sandbox |
| 4. Event Streaming | 🟡 designed, containers boot | Kafka+Zookeeper confirmed running via docker-compose on the user's machine; no producer/consumer has pushed a real message through yet |
| 5. Database Design | 🟡 schema loads | Postgres+TimescaleDB schema applied via docker-entrypoint-initdb; table existence not yet confirmed with `\dt` |
| 6. Feature Extraction | 🟡 ~70% written | Logic never run against live Kafka; unit-testable in isolation but not yet tested |
| 7. Behavioral Graph Engine | ✅ | `demo_run.py` + 2 passing pytest tests, correct risk propagation verified |
| 8. Attack Intent Prediction | ✅ baseline only | Gradient-boosted classifier actually trained on synthetic data: 99.8% held-out accuracy — inflated by clean synthetic separability, **not a real-world number**. Temporal GNN (the target architecture) not started. Model artifact saved to `ai/intent_prediction/model_artifacts/` |
| 9. MITRE ATT&CK Mapping | ✅ | Real signature-based mapper, 3 passing pytest tests including exact evidence-event-id checks |
| 10. Explainability Engine | ✅ template backend / 🟡 LLM backend | `TemplateNarrator` runs and produces cited, evidence-grounded prose (see `demo_full_pipeline.py` output). `LLMNarrator` builds the exact grounded prompt but the actual API call is an intentional `NotImplementedError` stub — no LLM credentials configured in this environment |
| 11. Attack Narrative Generator | ✅ | Chronological timeline generation verified against real event sequence |
| 12. Threat Heatmap Engine | ✅ | Weighted peak+average aggregation verified; caught and fixed one test-threshold miscalibration during verification |
| 13. Incident Replay Engine | ⬜ | Only an empty service stub (`backend/app/services/replay_service.py`) |
| 14. Security Copilot (RAG) | ⬜ | Stub raises `NotImplementedError` — no vector store, no embeddings, no LLM wired |
| 15. Response Engine | ✅ policy logic / ⬜ real executors | Policy engine verified: 4 passing tests, including a safety-invariant test that destructive actions can never be set to AUTO mode. Actual system-mutating executors (process isolation, network isolation) are intentionally unimplemented — that requires root/cgroups/iptables on a real host |
| 16. Frontend Dashboard | ⬜ | Not started — folder exists, no code |
| 17. FastAPI Backend | 🟡 ~65% written | `/api/health` confirmed live. Auth is now REAL (users table, argon2id hashing, timing-safe login) — verified: password hashing round-trips correctly, all 8 routes register correctly under pinned `fastapi==0.115.0`. Not yet verified: an actual DB round-trip on your machine (`docker compose exec backend python -m scripts.seed_db ...` — see `backend/scripts/SEEDING.md`) |
| 18. Deployment | 🟡 partial | docker-compose confirmed working for postgres/kafka/zookeeper/backend on the user's machine. No Kubernetes, no CI/CD |
| 19. Testing Framework | ✅ started | `tests/test_pipeline.py` — 11 real pytest tests, all passing, against real (non-mocked) logic for graph engine, MITRE mapping, explainability, heatmap, and response policy |
| 20. Research/Thesis Methodology | ⬜ | Not started |

**Rolling total: 9 of 20 phases have real, run-and-checked output. 4 more have substantial code with a clear, named reason it can't be verified in this sandbox (needs a Linux kernel, a live LLM key, or root/cgroups access). 7 are genuinely untouched.**

Run `python3 demo_full_pipeline.py` from the repo root to see phases 7, 9, 10, 11, 12, and 15 working together on one synthetic incident — no infrastructure required.

## Quickstart (dev)

```bash
# 0. Zero-infra demo — see phases 7, 9, 10, 11, 12, 15 working together
pip install networkx scikit-learn pytest
python3 demo_full_pipeline.py
python3 -m pytest tests/ -v

# 1. Bring up infra + backend (needs Docker)
cd docker && docker compose up -d postgres kafka zookeeper backend
curl http://localhost:8000/api/health

# 2. Build & run the eBPF collector on a real Linux host (needs root/CAP_BPF)
cd ../ebpf && cat README.md

# 3. Train the intent-prediction baseline
python3 -m ai.intent_prediction.train_baseline
```

Note: the eBPF collector needs real kernel access (tracepoints/kprobes),
so it isn't containerized in the compose file — run it directly on a Linux
dev host or VM, pointed at the Dockerized Kafka broker.

`backend/requirements.txt` is intentionally lightweight (no torch/sklearn —
those live in `ai/intent_prediction/requirements.txt` for the model-serving
image only, keeping the API container's build fast and small).

## Next steps (pick one to go deep on)

1. **Intent Prediction (Phase 8)** — Temporal GNN in PyTorch: dataset
   structure from `attack_graphs`, training pipeline, TorchServe inference.
2. **MITRE Mapping + Explainability (Phases 9–10)** — technique knowledge
   base, evidence extraction, LLM narrative prompt engineering.
3. **Frontend Dashboard (Phase 16)** — React/TS with live process tree,
   attack graph (react-flow/cytoscape), heatmap, copilot chat panel.
4. **Response Engine (Phase 15)** — policy engine + bounded containment
   actions with full audit trail.
5. **Deployment & Testing (Phases 18–19)** — Kubernetes manifests, CI/CD,
   unit/integration/load tests.
6. **Research writeup (Phase 20)** — methodology, evaluation against
   Atomic Red Team emulations, metrics, publication roadmap.

Tell me which one and I'll build it out at the same depth as what's here.
