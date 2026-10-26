package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

const (
	testSHA    = "0123456789abcdef0123456789abcdef01234567"
	testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func validRun() Run {
	return Run{
		ProjectID: 1, RunID: 100, RunAttempt: 1, SHA: testSHA, Ref: "refs/heads/main", Event: "push",
		WorkflowRef: "octo/repo/.github/workflows/ci.yml@refs/heads/main",
	}
}

// TestInputValidation checks that invalid input is rejected with ErrInvalidInput before any
// database access (the Store has no pool here).
func TestInputValidation(t *testing.T) {
	t.Parallel()
	s := New(nil, nil)
	ctx := context.Background()
	now := time.Now()
	okRisk := Risk{Score: 50, Tier: TierP2, Explanation: json.RawMessage(`{"s":0.5}`)}
	vulnDoc := evidence.Document{
		Format: evidence.FormatGrype, Tool: evidence.Tool{Name: "grype"},
		Findings: []evidence.Finding{vulnFinding("fp", "CVE-2024-0001", "pkg:golang/a@1", "grype")},
	}

	tests := []struct {
		name string
		call func() error
	}{
		{"project repo id", func() error {
			_, err := s.UpsertProject(ctx, Project{RepoID: 0, OwnerID: 1, RepoFullName: "o/r"})
			return err
		}},
		{"project owner id", func() error {
			_, err := s.UpsertProject(ctx, Project{RepoID: 1, OwnerID: 0, RepoFullName: "o/r"})
			return err
		}},
		{"project name", func() error {
			_, err := s.UpsertProject(ctx, Project{RepoID: 1, OwnerID: 1, RepoFullName: "no-slash"})
			return err
		}},
		{"run project", func() error { r := validRun(); r.ProjectID = 0; _, err := s.RecordRun(ctx, r); return err }},
		{"run id", func() error { r := validRun(); r.RunID = -1; _, err := s.RecordRun(ctx, r); return err }},
		{"run attempt", func() error { r := validRun(); r.RunAttempt = 0; _, err := s.RecordRun(ctx, r); return err }},
		{"run sha", func() error { r := validRun(); r.SHA = "ABC"; _, err := s.RecordRun(ctx, r); return err }},
		{"run ref", func() error { r := validRun(); r.Ref = ""; _, err := s.RecordRun(ctx, r); return err }},
		{"run event", func() error { r := validRun(); r.Event = "Push!"; _, err := s.RecordRun(ctx, r); return err }},
		{"run workflow", func() error {
			r := validRun()
			r.WorkflowRef = strings.Repeat("w", 1025)
			_, err := s.RecordRun(ctx, r)
			return err
		}},
		{"run actor", func() error { r := validRun(); r.ActorID = -5; _, err := s.RecordRun(ctx, r); return err }},
		{"run status", func() error { r := validRun(); r.Status = "done"; _, err := s.RecordRun(ctx, r); return err }},
		{"run timing", func() error {
			r := validRun()
			r.StartedAt, r.FinishedAt = now, now.Add(-time.Second)
			_, err := s.RecordRun(ctx, r)
			return err
		}},
		{"run claims", func() error {
			r := validRun()
			r.OIDCClaims = json.RawMessage(`["not","an","object"]`)
			_, err := s.RecordRun(ctx, r)
			return err
		}},
		{"artifact project", func() error {
			_, err := s.UpsertArtifact(ctx, 0, 0, evidence.Artifact{Kind: evidence.ArtifactBinary, Name: "b", Digest: testDigest})
			return err
		}},
		{"artifact run", func() error {
			_, err := s.UpsertArtifact(ctx, 1, -1, evidence.Artifact{Kind: evidence.ArtifactBinary, Name: "b", Digest: testDigest})
			return err
		}},
		{"artifact kind", func() error {
			_, err := s.UpsertArtifact(ctx, 1, 0, evidence.Artifact{Kind: "vm", Name: "b", Digest: testDigest})
			return err
		}},
		{"artifact tag instead of digest", func() error {
			_, err := s.UpsertArtifact(ctx, 1, 0, evidence.Artifact{Kind: evidence.ArtifactContainerImage, Name: "img", Digest: "latest"})
			return err
		}},
		{"artifact name", func() error {
			_, err := s.UpsertArtifact(ctx, 1, 0, evidence.Artifact{Kind: evidence.ArtifactBinary, Digest: testDigest})
			return err
		}},
		{"evidence run", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.RunID = 0 }))
			return err
		}},
		{"evidence artifact", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.ArtifactID = -1 }))
			return err
		}},
		{"evidence format", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.Format = "xml" }))
			return err
		}},
		{"evidence format version", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.FormatVersion = strings.Repeat("1", 65) }))
			return err
		}},
		{"evidence tool", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.Tool.Name = "" }))
			return err
		}},
		{"evidence tool version", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.Tool.Version = "\xff" }))
			return err
		}},
		{"evidence signer", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.SignerIdentity = strings.Repeat("s", 1025) }))
			return err
		}},
		{"evidence empty body", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.Body = nil }))
			return err
		}},
		{"evidence huge body", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.Body = make([]byte, MaxEvidenceSize+1) }))
			return err
		}},
		{"evidence not json", func() error {
			_, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.Body = []byte("<xml/>") }))
			return err
		}},
		{"ingest run", func() error { _, err := s.IngestDocument(ctx, 0, 1, vulnDoc); return err }},
		{"ingest artifact", func() error { _, err := s.IngestDocument(ctx, 1, -1, vulnDoc); return err }},
		{"ingest findings without artifact", func() error { _, err := s.IngestDocument(ctx, 1, 0, vulnDoc); return err }},
		{"ingest bad document", func() error { _, err := s.IngestDocument(ctx, 1, 1, evidence.Document{}); return err }},
		{"risk finding id", func() error { return s.UpdateFindingRisk(ctx, 0, okRisk) }},
		{"risk nan", func() error {
			return s.UpdateFindingRisk(ctx, 1, Risk{Score: math.NaN(), Tier: TierP1, Explanation: okRisk.Explanation})
		}},
		{"risk range", func() error {
			return s.UpdateFindingRisk(ctx, 1, Risk{Score: 101, Tier: TierP1, Explanation: okRisk.Explanation})
		}},
		{"risk tier", func() error {
			return s.UpdateFindingRisk(ctx, 1, Risk{Score: 1, Tier: "P0", Explanation: okRisk.Explanation})
		}},
		{"risk explanation", func() error {
			return s.UpdateFindingRisk(ctx, 1, Risk{Score: 1, Tier: TierP3, Explanation: json.RawMessage(`[1]`)})
		}},
		{"risk explanation size", func() error {
			big := json.RawMessage(`{"x":"` + strings.Repeat("a", maxExplanationSize) + `"}`)
			return s.UpdateFindingRisk(ctx, 1, Risk{Score: 1, Tier: TierP3, Explanation: big})
		}},
		{"list ids", func() error { _, err := s.ListFindings(ctx, FindingFilter{ArtifactID: -1}); return err }},
		{"list tier", func() error { _, err := s.ListFindings(ctx, FindingFilter{Tier: "P9"}); return err }},
		{"list status", func() error { _, err := s.ListFindings(ctx, FindingFilter{Status: "gone"}); return err }},
		{"list kind", func() error { _, err := s.ListFindings(ctx, FindingFilter{Kind: "virus"}); return err }},
		{"list limit", func() error { _, err := s.ListFindings(ctx, FindingFilter{Limit: -1}); return err }},
		{"list cursor", func() error { _, err := s.ListFindings(ctx, FindingFilter{Cursor: "bogus"}); return err }},
		{"audit actor", func() error { _, err := s.AppendAudit(ctx, AuditEntry{Action: "x"}); return err }},
		{"audit action", func() error { _, err := s.AppendAudit(ctx, AuditEntry{Actor: "a", Action: "Drop Table"}); return err }},
		{"audit target", func() error {
			_, err := s.AppendAudit(ctx, AuditEntry{Actor: "a", Action: "x", Target: strings.Repeat("t", 1025)})
			return err
		}},
		{"audit project", func() error {
			_, err := s.AppendAudit(ctx, AuditEntry{Actor: "a", Action: "x", ProjectID: -1})
			return err
		}},
		{"audit details", func() error {
			_, err := s.AppendAudit(ctx, AuditEntry{Actor: "a", Action: "x", Details: json.RawMessage(`"str"`)})
			return err
		}},
		{"audit details size", func() error {
			big := json.RawMessage(`{"x":"` + strings.Repeat("a", maxAuditDetailsSize) + `"}`)
			_, err := s.AppendAudit(ctx, AuditEntry{Actor: "a", Action: "x", Details: big})
			return err
		}},
		{"intel cve", func() error { _, err := s.RecordVulnIntel(ctx, []VulnIntel{{CVE: "GHSA-x", Date: now}}); return err }},
		{"intel date", func() error { _, err := s.RecordVulnIntel(ctx, []VulnIntel{{CVE: "CVE-2024-1234"}}); return err }},
		{"intel epss", func() error {
			bad := 1.5
			_, err := s.RecordVulnIntel(ctx, []VulnIntel{{CVE: "CVE-2024-1234", Date: now, EPSS: &bad}})
			return err
		}},
		{"intel duplicate", func() error {
			_, err := s.RecordVulnIntel(ctx, []VulnIntel{{CVE: "CVE-2024-1234", Date: now}, {CVE: "CVE-2024-1234", Date: now}})
			return err
		}},
		{"intel batch", func() error { _, err := s.RecordVulnIntel(ctx, make([]VulnIntel, maxIntelBatch+1)); return err }},
		{"intel lookup batch", func() error { _, err := s.LatestVulnIntel(ctx, make([]string, maxIntelBatch+1)); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.call(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func evidenceInput(mutate func(*EvidenceInput)) EvidenceInput {
	in := EvidenceInput{
		RunID: 1, ArtifactID: 1, Format: evidence.FormatCycloneDX, FormatVersion: "1.6",
		Tool: evidence.Tool{Name: "syft", Version: "1.55.0"}, Body: []byte(`{"bomFormat":"CycloneDX"}`),
	}
	mutate(&in)
	return in
}

func TestEmptyInputsNeedNoDatabase(t *testing.T) {
	t.Parallel()
	s := New(nil, nil)
	ctx := context.Background()
	if err := s.UpdateFindingRisks(ctx, nil); err != nil {
		t.Errorf("UpdateFindingRisks(nil) = %v", err)
	}
	if n, err := s.RecordVulnIntel(ctx, nil); n != 0 || err != nil {
		t.Errorf("RecordVulnIntel(nil) = %d, %v", n, err)
	}
	if m, err := s.LatestVulnIntel(ctx, nil); len(m) != 0 || err != nil {
		t.Errorf("LatestVulnIntel(nil) = %v, %v", m, err)
	}
}

func TestOpenRejectsBadURLWithoutLeakingIt(t *testing.T) {
	t.Parallel()
	pw := strings.Repeat("q", 8) + time.Now().Format("150405.000000")
	_, err := Open(context.Background(), "postgres://u:"+pw+"@[::1/x", Options{})
	if err == nil || strings.Contains(err.Error(), pw) {
		t.Fatalf("Open() error = %v (must fail without echoing the URL)", err)
	}
}
