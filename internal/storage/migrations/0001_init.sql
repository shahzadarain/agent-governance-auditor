-- SPDX-License-Identifier: Apache-2.0
-- Migration 0001: initial schema.
--
-- The SQL is dialect-neutral: it runs unchanged on SQLite and PostgreSQL.
-- Timestamps are Unix microseconds (UTC) in BIGINT columns. Booleans are
-- INTEGER 0/1. JSON documents are TEXT. Statements end with a semicolon at
-- the end of a line; the migration runner splits on that.

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_seen  BIGINT NOT NULL
);

CREATE TABLE projects (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE project_members (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT,
    expires_at   BIGINT,
    revoked_at   BIGINT
);

CREATE INDEX api_tokens_project ON api_tokens (project_id);

CREATE TABLE scans (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_id           TEXT NOT NULL,
    target            TEXT NOT NULL,
    commit_sha        TEXT NOT NULL,
    profile           TEXT NOT NULL,
    policy_pack       TEXT NOT NULL,
    policy_version    TEXT NOT NULL,
    tool_version      TEXT NOT NULL,
    decision          TEXT NOT NULL,
    score             INTEGER,
    score_label       TEXT NOT NULL,
    received_at       BIGINT NOT NULL,
    uploaded_by_token TEXT NOT NULL,
    payload           TEXT NOT NULL,
    payload_bytes     INTEGER NOT NULL,
    payload_sha256    TEXT NOT NULL,
    UNIQUE (project_id, payload_sha256)
);

CREATE INDEX scans_project_received ON scans (project_id, received_at);

CREATE TABLE agents (
    agent_key     TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL,
    name          TEXT NOT NULL,
    framework     TEXT NOT NULL,
    language      TEXT NOT NULL,
    owner         TEXT NOT NULL,
    risk_tier     TEXT NOT NULL,
    last_scan_id  TEXT NOT NULL,
    last_decision TEXT NOT NULL,
    last_score    INTEGER,
    first_seen    BIGINT NOT NULL,
    last_seen     BIGINT NOT NULL,
    UNIQUE (project_id, agent_id)
);

CREATE TABLE scan_agents (
    scan_row_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL,
    decision    TEXT NOT NULL,
    score       INTEGER,
    score_label TEXT NOT NULL,
    PRIMARY KEY (scan_row_id, agent_id)
);

CREATE TABLE findings (
    scan_row_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ord         INTEGER NOT NULL,
    finding_id  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    control_id  TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    path        TEXT NOT NULL,
    line        INTEGER NOT NULL,
    PRIMARY KEY (scan_row_id, ord)
);

CREATE INDEX findings_scan_severity ON findings (scan_row_id, severity);

CREATE TABLE control_results (
    scan_row_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL,
    control_id  TEXT NOT NULL,
    status      TEXT NOT NULL,
    maturity    INTEGER NOT NULL,
    mandatory   INTEGER NOT NULL,
    PRIMARY KEY (scan_row_id, agent_id, control_id)
);

CREATE TABLE audit_events (
    seq         BIGINT PRIMARY KEY,
    occurred_at BIGINT NOT NULL,
    actor_type  TEXT NOT NULL,
    actor_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    project_id  TEXT NOT NULL,
    detail      TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);

CREATE INDEX audit_events_project ON audit_events (project_id, seq);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
