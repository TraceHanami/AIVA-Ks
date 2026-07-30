# Kafka Topic Design

| Topic | Partitions | Key | Retention | Producer | Consumer(s) |
|---|---|---|---|---|---|
| `raw.events` | 12 | `host_id` | 3 days | eBPF collector | feature-extraction, event-persister |
| `raw.network` | 6 | `host_id` | 3 days | eBPF collector | feature-extraction |
| `enriched.events` | 12 | `host_id` | 14 days | feature-extraction | graph-engine, event-persister |
| `graph.updates` | 6 | `host_id` | 14 days | graph-engine | intent-prediction, dashboard (via WS bridge) |
| `predictions` | 3 | `host_id` | 90 days | intent-prediction | explainability, alerting, event-persister |
| `alerts` | 3 | `host_id` | 180 days | alerting service | response-engine, dashboard |
| `responses.audit` | 1 | `host_id` | indefinite (compliance) | response-engine | event-persister |

Partition count on `raw.events`/`enriched.events` is set high (12) because
that's the highest-volume topic and consumer parallelism for feature
extraction scales with partition count. `host_id` as key guarantees
per-host event ordering, which the graph engine depends on (it builds
graphs incrementally and assumes causally-ordered arrival per host).

`responses.audit` retention is indefinite because containment actions are
the platform's most sensitive audit surface — never subject to Kafka's
normal retention/compaction cleanup; also mirrored into Postgres
`responses` table for durable, queryable storage.
