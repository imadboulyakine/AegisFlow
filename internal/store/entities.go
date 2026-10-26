package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// Project is a GitHub repository known to AegisFlow, identified by its immutable numeric ID.
type Project struct {
	// RepoID is GitHub's repository_id claim (immutable, survives renames and transfers).
	RepoID int64
	// RepoFullName is "owner/name" (informational; may change).
	RepoFullName string
	// OwnerID is GitHub's repository_owner_id claim.
	OwnerID int64
}

var repoFullNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

// UpsertProject creates the project for p.RepoID or refreshes its name and owner, returning the
// project's ID.
func (s *Store) UpsertProject(ctx context.Context, p Project) (int64, error) {
	switch {
	case p.RepoID <= 0:
		return 0, invalid("project: repo ID must be positive")
	case p.OwnerID <= 0:
		return 0, invalid("project: owner ID must be positive")
	case !repoFullNameRE.MatchString(p.RepoFullName):
		return 0, invalid("project: repo full name must be owner/name")
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
INSERT INTO projects AS p (repo_id, repo_full_name, owner_id) VALUES ($1, $2, $3)
ON CONFLICT (repo_id) DO UPDATE
    SET repo_full_name = EXCLUDED.repo_full_name, owner_id = EXCLUDED.owner_id, updated_at = now()
    WHERE (p.repo_full_name, p.owner_id) IS DISTINCT FROM (EXCLUDED.repo_full_name, EXCLUDED.owner_id)
RETURNING id`, p.RepoID, p.RepoFullName, p.OwnerID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) { // unchanged: the conditional update returned nothing
		err = s.pool.QueryRow(ctx, `SELECT id FROM projects WHERE repo_id = $1`, p.RepoID).Scan(&id)
	}
	if err != nil {
		return 0, fmt.Errorf("store: upsert project: %w", classify(err))
	}
	return id, nil
}

// RunStatus is the lifecycle state of a pipeline run.
type RunStatus string

// Run statuses.
const (
	RunInProgress RunStatus = "in_progress"
	RunSuccess    RunStatus = "success"
	RunFailure    RunStatus = "failure"
	RunCancelled  RunStatus = "cancelled"
)

func (s RunStatus) valid() bool {
	switch s {
	case RunInProgress, RunSuccess, RunFailure, RunCancelled:
		return true
	}
	return false
}

// Run is one GitHub Actions workflow run attempt. The identity fields (SHA, Ref, Event,
// WorkflowRef) come from verified OIDC claims and are immutable once recorded.
type Run struct {
	ProjectID   int64
	RunID       int64 // GitHub run_id
	RunAttempt  int   // GitHub run_attempt, ≥ 1
	SHA         string
	Ref         string
	Event       string
	WorkflowRef string
	ActorID     int64     // 0 = unknown
	Status      RunStatus // "" = in_progress
	StartedAt   time.Time // zero = unknown
	FinishedAt  time.Time // zero = not finished
	// OIDCClaims are the verified token claims (a JSON object); nil stores {}. Never include the
	// raw token.
	OIDCClaims json.RawMessage
}

var (
	shaRE   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	eventRE = regexp.MustCompile(`^[a-z_]{1,64}$`)
)

func (r *Run) validate() error {
	switch {
	case r.ProjectID <= 0:
		return invalid("run: project ID must be positive")
	case r.RunID <= 0:
		return invalid("run: run ID must be positive")
	case r.RunAttempt < 1 || r.RunAttempt > 1000:
		return invalid("run: run attempt %d out of range [1, 1000]", r.RunAttempt)
	case !shaRE.MatchString(r.SHA):
		return invalid("run: sha must be 40 or 64 lowercase hex characters")
	case !boundedText(r.Ref, 1, 512):
		return invalid("run: ref must be 1-512 bytes of valid UTF-8")
	case !eventRE.MatchString(r.Event):
		return invalid("run: event must match [a-z_]{1,64}")
	case !boundedText(r.WorkflowRef, 1, 1024):
		return invalid("run: workflow ref must be 1-1024 bytes of valid UTF-8")
	case r.ActorID < 0:
		return invalid("run: actor ID must not be negative")
	case r.Status != "" && !r.Status.valid():
		return invalid("run: unknown status %q", r.Status)
	case !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt):
		return invalid("run: finished before it started")
	}
	if r.OIDCClaims != nil && !isJSONObject(r.OIDCClaims) {
		return invalid("run: OIDC claims must be a JSON object")
	}
	return nil
}

// RecordRun inserts the run attempt or, when it already exists, updates its status and timing.
// Re-recording an attempt with different identity fields (sha, ref, event, workflow ref) returns
// ErrConflict: evidence bound to a run must never silently move to another commit.
func (s *Store) RecordRun(ctx context.Context, r Run) (int64, error) {
	if err := r.validate(); err != nil {
		return 0, err
	}
	status := r.Status
	if status == "" {
		status = RunInProgress
	}
	claims := r.OIDCClaims
	if claims == nil {
		claims = json.RawMessage(`{}`)
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
INSERT INTO pipeline_runs AS r (project_id, run_id, run_attempt, sha, ref, event, workflow_ref, actor_id,
    status, started_at, finished_at, oidc_claims)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (project_id, run_id, run_attempt) DO UPDATE SET
    -- "in_progress" never overwrites a terminal status recorded by a later job.
    status      = CASE WHEN EXCLUDED.status = 'in_progress' THEN r.status ELSE EXCLUDED.status END,
    started_at  = coalesce(r.started_at, EXCLUDED.started_at),
    finished_at = coalesce(EXCLUDED.finished_at, r.finished_at),
    actor_id    = coalesce(r.actor_id, EXCLUDED.actor_id),
    updated_at  = now()
WHERE (r.sha, r.ref, r.event, r.workflow_ref) = (EXCLUDED.sha, EXCLUDED.ref, EXCLUDED.event, EXCLUDED.workflow_ref)
RETURNING id`,
		r.ProjectID, r.RunID, r.RunAttempt, r.SHA, r.Ref, r.Event, r.WorkflowRef, nullInt64(r.ActorID),
		string(status), nullTime(r.StartedAt), nullTime(r.FinishedAt), []byte(claims)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: run %d attempt %d is already recorded with a different sha, ref, event or workflow",
			ErrConflict, r.RunID, r.RunAttempt)
	}
	if err != nil {
		return 0, fmt.Errorf("store: record run: %w", classify(err))
	}
	return id, nil
}

var digestRE = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$`)

func validArtifactKind(k evidence.ArtifactKind) bool {
	switch k {
	case evidence.ArtifactContainerImage, evidence.ArtifactBinary, evidence.ArtifactSource, evidence.ArtifactSBOM:
		return true
	}
	return false
}

// UpsertArtifact returns the ID of the project's artifact with a.Digest, creating it if needed.
// runID (0 = unknown) is recorded as the run that first produced it. The digest is mandatory
// (artifacts are never identified by tag); a known digest with a different kind is ErrConflict.
func (s *Store) UpsertArtifact(ctx context.Context, projectID, runID int64, a evidence.Artifact) (int64, error) {
	switch {
	case projectID <= 0:
		return 0, invalid("artifact: project ID must be positive")
	case runID < 0:
		return 0, invalid("artifact: run ID must not be negative")
	case !validArtifactKind(a.Kind):
		return 0, invalid("artifact: unknown kind %q", a.Kind)
	case !digestRE.MatchString(a.Digest):
		return 0, invalid("artifact: digest must be sha256:<64 hex> or sha512:<128 hex>")
	case !boundedText(a.Name, 1, 1024):
		return 0, invalid("artifact: name must be 1-1024 bytes of valid UTF-8")
	}
	var id int64
	err := s.inTx(ctx, "upsert artifact", func(tx pgx.Tx) error {
		if runID > 0 {
			p, err := runProject(ctx, tx, runID)
			if err != nil {
				return err
			}
			if p != projectID {
				return invalid("artifact: run %d belongs to another project", runID)
			}
		}
		err := tx.QueryRow(ctx, `
INSERT INTO artifacts AS a (project_id, kind, name, digest, first_run_id) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (project_id, digest) DO NOTHING
RETURNING id`, projectID, string(a.Kind), a.Name, a.Digest, nullInt64(runID)).Scan(&id)
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var kind string
		if err := tx.QueryRow(ctx, `SELECT id, kind FROM artifacts WHERE project_id = $1 AND digest = $2`,
			projectID, a.Digest).Scan(&id, &kind); err != nil {
			return err
		}
		if kind != string(a.Kind) {
			return fmt.Errorf("%w: artifact %s is already recorded as %s", ErrConflict, a.Digest, kind)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: upsert artifact: %w", classify(err))
	}
	return id, nil
}

// nullInt64 maps 0 to SQL NULL.
func nullInt64(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

// nullTime maps the zero time to SQL NULL.
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
