-- Copyright 2026 the original author or authors from the Chautari project.
--
-- This file is part of the Chautari project, see https://github.com/lukelittle/chautari
-- for more information.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Chautari schema, version 1.

CREATE TABLE IF NOT EXISTS registry (
    kind          text        NOT NULL,
    name          text        NOT NULL,
    status        text        NOT NULL,
    source        text        NOT NULL,
    spec          jsonb       NOT NULL DEFAULT '{}',
    requested_by  text        NOT NULL DEFAULT '',
    reviewed_by   text        NOT NULL DEFAULT '',
    approved_by   text        NOT NULL DEFAULT '',
    note          text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    version       bigint      NOT NULL DEFAULT 1,
    PRIMARY KEY (kind, name),
    CHECK (status IN ('requested', 'reviewed', 'approved', 'rejected', 'retired'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          text PRIMARY KEY,
    prefix      text        NOT NULL,
    hash        text        NOT NULL UNIQUE,
    name        text        NOT NULL,
    app         text        NOT NULL,
    team        text        NOT NULL,
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);

CREATE TABLE IF NOT EXISTS spend (
    scope         text           NOT NULL,
    subject       text           NOT NULL,
    period        text           NOT NULL,
    window_start  timestamptz    NOT NULL,
    usd           numeric(20, 8) NOT NULL DEFAULT 0,
    tokens        bigint         NOT NULL DEFAULT 0,
    requests      bigint         NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, subject, period, window_start)
);

-- The audit log. `body` holds the canonical JSON the hash covers, so
-- verification never depends on how Postgres re-serialises jsonb.
CREATE TABLE IF NOT EXISTS audit_log (
    seq        bigint PRIMARY KEY,
    ts         timestamptz NOT NULL,
    kind       text        NOT NULL,
    subject    text        NOT NULL,
    decision   text        NOT NULL,
    body       text        NOT NULL,
    prev_hash  text        NOT NULL,
    hash       text        NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log (ts);
CREATE INDEX IF NOT EXISTS audit_log_kind_ts ON audit_log (kind, ts);

-- Append-only: the database itself refuses to rewrite history.
CREATE OR REPLACE FUNCTION chautari_audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% rejected)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION chautari_audit_append_only();

DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION chautari_audit_append_only();
