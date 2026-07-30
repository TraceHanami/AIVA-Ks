-- AIVA-KS core schema
-- Requires: PostgreSQL 15+, TimescaleDB extension

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- USERS (analyst/admin accounts — argon2 password hashes only)
-- ============================================================
CREATE TABLE users (
    user_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username     TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,      -- argon2id hash, never plaintext
    role         TEXT NOT NULL DEFAULT 'viewer',  -- viewer|analyst|admin
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    active       BOOLEAN NOT NULL DEFAULT true
);

-- ============================================================
-- HOSTS
-- ============================================================
CREATE TABLE hosts (
    host_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname     TEXT NOT NULL,
    kernel_ver   TEXT,
    agent_ver    TEXT,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    tags         JSONB DEFAULT '{}'::jsonb
);

-- ============================================================
-- RAW EVENTS (hypertable — high volume, append-only)
-- ============================================================
CREATE TABLE events (
    event_id     BIGINT GENERATED ALWAYS AS IDENTITY,
    time         TIMESTAMPTZ NOT NULL,
    host_id      UUID NOT NULL REFERENCES hosts(host_id),
    pid          INT NOT NULL,
    tid          INT,
    ppid         INT,
    uid          INT,
    comm         TEXT,
    syscall      TEXT NOT NULL,          -- execve, connect, mmap, ...
    category     TEXT NOT NULL,          -- process|file|network|memory
    args         JSONB,                   -- redacted/structured syscall args
    return_code  INT,
    PRIMARY KEY (time, event_id)
);
SELECT create_hypertable('events', 'time', chunk_time_interval => INTERVAL '1 day');
CREATE INDEX idx_events_host_pid_time ON events (host_id, pid, time DESC);
CREATE INDEX idx_events_syscall ON events (syscall, time DESC);
CREATE INDEX idx_events_args_gin ON events USING GIN (args);

-- ============================================================
-- PROCESSES (entity table, one row per observed process lifetime)
-- ============================================================
CREATE TABLE processes (
    process_uid  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id      UUID NOT NULL REFERENCES hosts(host_id),
    pid          INT NOT NULL,
    ppid         INT,
    comm         TEXT,
    cmdline      TEXT,
    exe_path     TEXT,
    uid          INT,
    started_at   TIMESTAMPTZ NOT NULL,
    exited_at    TIMESTAMPTZ,
    exit_code    INT,
    parent_uid   UUID REFERENCES processes(process_uid)
);
CREATE INDEX idx_processes_host_pid ON processes (host_id, pid, started_at DESC);

-- ============================================================
-- THREADS
-- ============================================================
CREATE TABLE threads (
    thread_uid   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    process_uid  UUID NOT NULL REFERENCES processes(process_uid),
    tid          INT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    exited_at    TIMESTAMPTZ
);

-- ============================================================
-- NETWORK CONNECTIONS
-- ============================================================
CREATE TABLE connections (
    conn_uid     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    process_uid  UUID REFERENCES processes(process_uid),
    host_id      UUID NOT NULL REFERENCES hosts(host_id),
    proto        TEXT,                 -- tcp|udp
    local_addr   INET,
    local_port   INT,
    remote_addr  INET,
    remote_port  INT,
    direction    TEXT,                 -- inbound|outbound
    started_at   TIMESTAMPTZ NOT NULL,
    ended_at     TIMESTAMPTZ,
    bytes_sent   BIGINT DEFAULT 0,
    bytes_recv   BIGINT DEFAULT 0
);
CREATE INDEX idx_connections_remote ON connections (remote_addr, started_at DESC);

-- ============================================================
-- FILES
-- ============================================================
CREATE TABLE files (
    file_uid     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id      UUID NOT NULL REFERENCES hosts(host_id),
    process_uid  UUID REFERENCES processes(process_uid),
    path         TEXT NOT NULL,
    operation    TEXT NOT NULL,        -- open|read|write|unlink|chmod
    time         TIMESTAMPTZ NOT NULL,
    bytes        BIGINT,
    hash_sha256  TEXT
);
CREATE INDEX idx_files_path ON files (path, time DESC);

-- ============================================================
-- ATTACK GRAPHS (materialized snapshot metadata; full graph in Neo4j/graph store)
-- ============================================================
CREATE TABLE attack_graphs (
    graph_uid    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id      UUID NOT NULL REFERENCES hosts(host_id),
    root_process_uid UUID REFERENCES processes(process_uid),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    node_count   INT,
    edge_count   INT,
    graph_json   JSONB,                -- serialized graph for replay/small graphs
    risk_score   NUMERIC(5,2)
);

-- ============================================================
-- PREDICTIONS (model output per graph/process)
-- ============================================================
CREATE TABLE predictions (
    prediction_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    graph_uid     UUID REFERENCES attack_graphs(graph_uid),
    model_name    TEXT NOT NULL,
    model_version TEXT NOT NULL,
    intent_class  TEXT NOT NULL,       -- CredentialTheft|Ransomware|Exfiltration|...
    confidence    NUMERIC(5,4) NOT NULL,
    mitre_techniques JSONB,            -- [{technique_id, confidence}, ...]
    predicted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    explanation_id UUID
);

-- ============================================================
-- EXPLANATIONS (XAI narrative output)
-- ============================================================
CREATE TABLE explanations (
    explanation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    prediction_id  UUID REFERENCES predictions(prediction_id),
    narrative      TEXT NOT NULL,
    evidence_events BIGINT[],          -- references events.event_id
    generated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    llm_model      TEXT
);

-- ============================================================
-- ALERTS
-- ============================================================
CREATE TABLE alerts (
    alert_id     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id      UUID NOT NULL REFERENCES hosts(host_id),
    graph_uid    UUID REFERENCES attack_graphs(graph_uid),
    prediction_id UUID REFERENCES predictions(prediction_id),
    severity     TEXT NOT NULL,        -- low|medium|high|critical
    status       TEXT NOT NULL DEFAULT 'open', -- open|ack|closed|false_positive
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_alerts_status ON alerts (status, severity, created_at DESC);

-- ============================================================
-- INVESTIGATIONS (analyst workspace)
-- ============================================================
CREATE TABLE investigations (
    investigation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id     UUID REFERENCES alerts(alert_id),
    analyst      TEXT,
    notes        TEXT,
    status       TEXT NOT NULL DEFAULT 'open',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at    TIMESTAMPTZ
);

-- ============================================================
-- CHAT HISTORY (security copilot)
-- ============================================================
CREATE TABLE chat_history (
    message_id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(investigation_id),
    role         TEXT NOT NULL,        -- user|assistant|system
    content      TEXT NOT NULL,
    retrieved_context JSONB,           -- RAG chunks used
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- RESPONSES (containment actions — audit trail)
-- ============================================================
CREATE TABLE responses (
    response_id  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id     UUID REFERENCES alerts(alert_id),
    action_type  TEXT NOT NULL,        -- isolate_process|isolate_network|quarantine_file|snapshot
    target       JSONB NOT NULL,       -- what was acted on
    triggered_by TEXT NOT NULL,        -- 'auto:policy_v1' | 'analyst:jdoe'
    approved_by  TEXT,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|executed|failed|rolled_back
    executed_at  TIMESTAMPTZ,
    rollback_of  UUID REFERENCES responses(response_id)
);
CREATE INDEX idx_responses_alert ON responses (alert_id, executed_at DESC);

-- ============================================================
-- Continuous aggregate for the threat heatmap (5-min buckets)
-- ============================================================
CREATE MATERIALIZED VIEW events_5min
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('5 minutes', time) AS bucket,
    host_id,
    category,
    count(*) AS event_count
FROM events
GROUP BY bucket, host_id, category;
