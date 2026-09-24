# CHRONOS API Specification

The CHRONOS API is built with FastAPI and mounted under the `/api` prefix.

## Primary Endpoint Routes

### Dashboard & Health
- `GET /api/health` — System status, active mode (`live` vs `test`), host ID, and active graph node count.
- `GET /api/dashboard/summary` — Full security status payload including overall risk score, threat heatmap, MITRE matches, natural language narrative, graph nodes/edges, and pending response actions.
- `POST /api/reset` — Resets test host state to clean technical demonstration dataset.
- `POST /api/events/ingest` — Ingests custom syscall telemetry event into live or test host graph.

### Case Workspace (Module 12)
- `GET /api/cases` — List all active and closed analyst investigation cases.
- `POST /api/cases` — Create a new investigation case.
- `GET /api/cases/{case_id}` — Get specific case details and notes.
- `POST /api/cases/{case_id}/notes` — Add analyst note to case.
- `GET /api/cases/{case_id}/export` — Export full JSON investigation binder.

### Threat Intelligence & Scanning (Module 10 & 11)
- `GET /api/threat_intel/feed` — List active IOC threat intelligence feed indicators.
- `GET /api/threat_intel/lookup` — Query indicator (IP, hash, domain) against threat intel engine.
- `POST /api/scan/file` — Perform static signature scan on local file.
- `POST /api/scan/directory` — Perform static signature scan across directory tree.

### Response Actions (Module 9 & 15)
- `POST /api/actions/approve` — Authorize or reject pending containment action (process isolation, file quarantine).

### Copilot & Digital Twin Replay (Module 7 & 19)
- `POST /api/copilot/chat` — Interact with conversational SOC Assistant.
- `POST /api/replay/create` — Create digital twin replay session from event timeline.
- `GET /api/replay/snapshot` — Step through digital twin attack timeline snapshot.
