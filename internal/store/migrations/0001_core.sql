-- 0001_core: projects, pipeline runs, artifacts, append-only raw evidence and audit log.
--
-- Conventions (ARCHITECTURE.md §4, ADR-007):
--   * surrogate keys are `bigint GENERATED ALWAYS AS IDENTITY`; natural keys are UNIQUE constraints
--   * every timestamp is timestamptz; enumerations are CHECK constraints (no PostgreSQL ENUM types,
--     so adding a value is a plain constraint swap in a later migration)
--   * every foreign key states its ON DELETE behaviour explicitly
--   * indexed text columns are bounded with octet_length() so no row can exceed the btree limit
--   * `evidence` and `audit_log` are append-only: triggers reject UPDATE, DELETE and TRUNCATE

-- Raised by the append-only triggers; the Go store maps SQLSTATE AF001 to store.ErrImmutable.
CREATE FUNCTION aegisflow_forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table "%" is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'AF001',
              HINT = 'evidence and audit records are immutable; record a new row instead';
END;
$$;

-- GitHub repositories, identified by their immutable numeric IDs (names can change, IDs cannot).
CREATE TABLE projects (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id        bigint      NOT NULL CHECK (repo_id > 0),
    repo_full_name text        NOT NULL CHECK (repo_full_name ~ '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$'),
    owner_id       bigint      NOT NULL CHECK (owner_id > 0),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT projects_repo_id_key UNIQUE (repo_id)
);

-- One row per GitHub Actions workflow run attempt. Identity columns (sha, ref, workflow_ref, event)
-- never change after the first insert; only status and timing are updated.
CREATE TABLE pipeline_runs (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id   bigint      NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    run_id       bigint      NOT NULL CHECK (run_id > 0),
    run_attempt  integer     NOT NULL CHECK (run_attempt BETWEEN 1 AND 1000),
    sha          text        NOT NULL CHECK (sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    ref          text        NOT NULL CHECK (octet_length(ref) BETWEEN 1 AND 512),
    event        text        NOT NULL CHECK (event ~ '^[a-z_]{1,64}$'),
    workflow_ref text        NOT NULL CHECK (octet_length(workflow_ref) BETWEEN 1 AND 1024),
    actor_id     bigint      CHECK (actor_id > 0),
    status       text        NOT NULL DEFAULT 'in_progress'
                             CHECK (status IN ('in_progress', 'success', 'failure', 'cancelled')),
    started_at   timestamptz,
    finished_at  timestamptz,
    oidc_claims  jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(oidc_claims) = 'object'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pipeline_runs_run_key UNIQUE (project_id, run_id, run_attempt),
    -- Target of composite foreign keys that pin evidence to the run's own project.
    CONSTRAINT pipeline_runs_id_project_key UNIQUE (id, project_id),
    CONSTRAINT pipeline_runs_timing CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

CREATE INDEX pipeline_runs_project_sha_idx ON pipeline_runs (project_id, sha);

-- Build outputs, always identified by content digest (never by tag), unique per project.
CREATE TABLE artifacts (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id   bigint      NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    kind         text        NOT NULL CHECK (kind IN ('container-image', 'binary', 'source', 'sbom')),
    name         text        NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 1024),
    digest       text        NOT NULL CHECK (digest ~ '^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$'),
    first_run_id bigint      REFERENCES pipeline_runs (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT artifacts_project_digest_key UNIQUE (project_id, digest),
    CONSTRAINT artifacts_id_project_key UNIQUE (id, project_id)
);

CREATE INDEX artifacts_digest_idx ON artifacts (digest);

-- Raw evidence as received from CI. Append-only; sha256/size describe the exact bytes received
-- (the JSONB body is semantically equal but not byte-identical). The composite foreign keys make
-- the database itself refuse evidence whose run and artifact belong to different projects.
CREATE TABLE evidence (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id      bigint      NOT NULL,
    run_id          bigint      NOT NULL,
    artifact_id     bigint,
    format          text        NOT NULL
                                CHECK (format IN ('cyclonedx', 'spdx', 'sarif', 'grype', 'govulncheck', 'openvex')),
    format_version  text        NOT NULL DEFAULT '' CHECK (octet_length(format_version) <= 64),
    sha256          text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size            bigint      NOT NULL CHECK (size BETWEEN 1 AND 67108864),
    body            jsonb       NOT NULL,
    tool_name       text        NOT NULL CHECK (octet_length(tool_name) BETWEEN 1 AND 128),
    tool_version    text        NOT NULL DEFAULT '' CHECK (octet_length(tool_version) <= 128),
    signer_identity text        CHECK (octet_length(signer_identity) BETWEEN 1 AND 1024),
    received_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT evidence_run_fk FOREIGN KEY (run_id, project_id)
        REFERENCES pipeline_runs (id, project_id) ON DELETE RESTRICT,
    CONSTRAINT evidence_artifact_fk FOREIGN KEY (artifact_id, project_id)
        REFERENCES artifacts (id, project_id) ON DELETE RESTRICT,
    CONSTRAINT evidence_content_key UNIQUE NULLS NOT DISTINCT (run_id, artifact_id, sha256)
);

CREATE INDEX evidence_artifact_idx ON evidence (artifact_id) WHERE artifact_id IS NOT NULL;
CREATE INDEX evidence_sha256_idx ON evidence (sha256);

CREATE TRIGGER evidence_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON evidence
    FOR EACH STATEMENT EXECUTE FUNCTION aegisflow_forbid_mutation();

-- Security-relevant actions (ingest, VEX and policy changes, status overrides). Append-only;
-- the timestamp is always assigned by the database.
CREATE TABLE audit_log (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts         timestamptz NOT NULL DEFAULT now(),
    actor      text        NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 256),
    action     text        NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.:-]{0,63}$'),
    target     text        NOT NULL DEFAULT '' CHECK (octet_length(target) <= 1024),
    project_id bigint      REFERENCES projects (id) ON DELETE RESTRICT,
    details    jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX audit_log_ts_idx ON audit_log (ts DESC, id DESC);
CREATE INDEX audit_log_project_ts_idx ON audit_log (project_id, ts DESC) WHERE project_id IS NOT NULL;

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION aegisflow_forbid_mutation();
