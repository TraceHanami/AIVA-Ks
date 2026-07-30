# Seeding the database

After `docker compose up -d postgres kafka zookeeper backend`, the schema
is loaded but empty. Run the seed script inside the backend container
(it already has the right Python env and network access to postgres):

```bash
docker compose exec backend python -m scripts.seed_db --username admin --password changeme123
```

This creates:
- one `admin`-role user with an argon2id-hashed password
- one synthetic host, attack graph, prediction, and high-severity alert
  (the same injection/credential-theft scenario from `demo_full_pipeline.py`,
  so the numbers you see in the API match what the graph/MITRE/heatmap
  engines actually computed for it)

Then get a token and hit a real protected route:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:8000/api/alerts -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

You should get back one alert with `severity: "high"`, `status: "open"`,
linked to the seeded graph/prediction. Re-run the seed script (without
`--skip-incident`) to add more sample alerts.

## Known remaining gaps after this step

- `/api/graphs/{graph_uid}` should now work — the seeded graph has real
  `graph_json`.
- `/api/predictions/{graph_uid}` should now work — pull the `graph_uid`
  from the alert response above.
- `/api/replay/*` and `/api/chat` are still stubs (Phases 13 and 14 —
  not built yet).
- `/api/graphs/live/{host_id}` WebSocket still only sends heartbeats —
  it isn't wired to a real Kafka consumer on `graph.updates` yet.
