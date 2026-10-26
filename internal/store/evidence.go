package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// MaxEvidenceSize is the largest evidence body the store accepts (64 MiB). It is a backstop: the
// ingestion API enforces its own, smaller request limits before reading a body into memory.
const MaxEvidenceSize = 64 << 20

// EvidenceInput is one raw evidence file as received from CI.
type EvidenceInput struct {
	RunID int64
	// ArtifactID binds the evidence to an artifact of the run's project; 0 = not bound.
	ArtifactID    int64
	Format        evidence.Format
	FormatVersion string
	Tool          evidence.Tool
	// SignerIdentity is the verified signing identity when the evidence was signed; "" = none.
	SignerIdentity string
	// Body is the exact bytes received; it must be a JSON document. SHA-256 and size are
	// computed by the store from these bytes.
	Body []byte
}

// EvidenceRecord identifies stored evidence.
type EvidenceRecord struct {
	ID     int64
	SHA256 string // hex SHA-256 of the received bytes
	Size   int64
	// Created is false when byte-identical evidence was already stored for the same run and
	// artifact; ID is then the existing row's.
	Created bool
}

func validFormat(f evidence.Format) bool {
	switch f {
	case evidence.FormatCycloneDX, evidence.FormatSPDX, evidence.FormatSARIF, evidence.FormatGrype,
		evidence.FormatGovulncheck, evidence.FormatOpenVEX:
		return true
	}
	return false
}

// normalizeToolName lowercases and trims a tool name so findings merge regardless of spelling.
func normalizeToolName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// AppendEvidence stores raw evidence append-only. It is idempotent: storing the same bytes again
// for the same run and artifact returns the existing row with Created == false. The run and the
// artifact must belong to the same project (ErrInvalidInput otherwise; ErrNotFound if missing).
func (s *Store) AppendEvidence(ctx context.Context, in EvidenceInput) (EvidenceRecord, error) {
	tool := normalizeToolName(in.Tool.Name)
	switch {
	case in.RunID <= 0:
		return EvidenceRecord{}, invalid("evidence: run ID must be positive")
	case in.ArtifactID < 0:
		return EvidenceRecord{}, invalid("evidence: artifact ID must not be negative")
	case !validFormat(in.Format):
		return EvidenceRecord{}, invalid("evidence: unknown format %q", in.Format)
	case !boundedText(in.FormatVersion, 0, 64):
		return EvidenceRecord{}, invalid("evidence: format version must be at most 64 bytes of valid UTF-8")
	case !boundedText(tool, 1, 128):
		return EvidenceRecord{}, invalid("evidence: tool name must be 1-128 bytes of valid UTF-8")
	case !boundedText(in.Tool.Version, 0, 128):
		return EvidenceRecord{}, invalid("evidence: tool version must be at most 128 bytes of valid UTF-8")
	case !boundedText(in.SignerIdentity, 0, 1024):
		return EvidenceRecord{}, invalid("evidence: signer identity must be at most 1024 bytes of valid UTF-8")
	case len(in.Body) == 0 || len(in.Body) > MaxEvidenceSize:
		return EvidenceRecord{}, invalid("evidence: body size %d out of range [1, %d]", len(in.Body), MaxEvidenceSize)
	case !json.Valid(in.Body):
		return EvidenceRecord{}, invalid("evidence: body is not valid JSON")
	}
	sum := sha256.Sum256(in.Body)
	rec := EvidenceRecord{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(in.Body))}
	var signer *string
	if in.SignerIdentity != "" {
		signer = &in.SignerIdentity
	}

	err := s.inTx(ctx, "append evidence", func(tx pgx.Tx) error {
		projectID, err := runProject(ctx, tx, in.RunID)
		if err != nil {
			return err
		}
		if in.ArtifactID != 0 {
			if err := checkArtifactProject(ctx, tx, in.ArtifactID, projectID); err != nil {
				return err
			}
		}
		err = tx.QueryRow(ctx, `
INSERT INTO evidence (project_id, run_id, artifact_id, format, format_version, sha256, size, body,
    tool_name, tool_version, signer_identity)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT ON CONSTRAINT evidence_content_key DO NOTHING
RETURNING id`,
			projectID, in.RunID, nullInt64(in.ArtifactID), string(in.Format), in.FormatVersion, rec.SHA256,
			rec.Size, in.Body, tool, in.Tool.Version, signer).Scan(&rec.ID)
		if err == nil {
			rec.Created = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		rec.Created = false
		return tx.QueryRow(ctx, `
SELECT id FROM evidence WHERE run_id = $1 AND artifact_id IS NOT DISTINCT FROM $2 AND sha256 = $3`,
			in.RunID, nullInt64(in.ArtifactID), rec.SHA256).Scan(&rec.ID)
	})
	if err != nil {
		return EvidenceRecord{}, fmt.Errorf("store: append evidence: %w", classify(err))
	}
	return rec, nil
}

// runProject returns the project of a pipeline run (ErrNotFound if it does not exist).
func runProject(ctx context.Context, q pgx.Tx, runID int64) (int64, error) {
	var projectID int64
	err := q.QueryRow(ctx, `SELECT project_id FROM pipeline_runs WHERE id = $1`, runID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: run %d", ErrNotFound, runID)
	}
	return projectID, err
}

// checkArtifactProject verifies that an artifact exists and belongs to projectID.
func checkArtifactProject(ctx context.Context, q pgx.Tx, artifactID, projectID int64) error {
	var p int64
	err := q.QueryRow(ctx, `SELECT project_id FROM artifacts WHERE id = $1`, artifactID).Scan(&p)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: artifact %d", ErrNotFound, artifactID)
	}
	if err != nil {
		return err
	}
	if p != projectID {
		return invalid("artifact %d does not belong to the run's project", artifactID)
	}
	return nil
}
