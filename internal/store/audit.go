package store

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
)

// maxAuditDetailsSize bounds an audit entry's details object.
const maxAuditDetailsSize = 64 << 10

var auditActionRE = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}$`)

// AuditEntry is one security-relevant action. The timestamp is assigned by the database.
type AuditEntry struct {
	// Actor identifies who acted, e.g. "github-repo:123456" or "user:<entra object id>".
	Actor string
	// Action is a dotted verb such as "evidence.ingest" or "finding.accept".
	Action string
	// Target names the object acted on, e.g. "artifact:sha256:…" ("" = none).
	Target string
	// ProjectID scopes the entry to a project (0 = global).
	ProjectID int64
	// Details is a JSON object with non-secret context (nil = {}). Never put tokens, secrets or
	// full request bodies here.
	Details json.RawMessage
}

// AppendAudit records an audit entry and returns its ID. The audit log is append-only: the
// database rejects UPDATE, DELETE and TRUNCATE on it.
func (s *Store) AppendAudit(ctx context.Context, e AuditEntry) (int64, error) {
	details := e.Details
	if details == nil {
		details = json.RawMessage(`{}`)
	}
	switch {
	case !boundedText(e.Actor, 1, 256):
		return 0, invalid("audit: actor must be 1-256 bytes of valid UTF-8")
	case !auditActionRE.MatchString(e.Action):
		return 0, invalid("audit: action must match [a-z][a-z0-9_.:-]{0,63}")
	case !boundedText(e.Target, 0, 1024):
		return 0, invalid("audit: target must be at most 1024 bytes of valid UTF-8")
	case e.ProjectID < 0:
		return 0, invalid("audit: project ID must not be negative")
	case len(details) > maxAuditDetailsSize:
		return 0, invalid("audit: details exceed %d bytes", maxAuditDetailsSize)
	case !isJSONObject(details):
		return 0, invalid("audit: details must be a JSON object")
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
INSERT INTO audit_log (actor, action, target, project_id, details) VALUES ($1, $2, $3, $4, $5)
RETURNING id`, e.Actor, e.Action, e.Target, nullInt64(e.ProjectID), []byte(details)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: append audit: %w", classify(err))
	}
	return id, nil
}
