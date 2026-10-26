package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestLookupValidation(t *testing.T) {
	t.Parallel()
	s := &Store{} // validation fails before any database access
	tooMany := make([]int64, MaxLookupIDs+1)
	for i := range tooMany {
		tooMany[i] = int64(i + 1)
	}
	for _, ids := range [][]int64{tooMany, {1, 0}, {-3}} {
		if _, err := s.GetFindings(context.Background(), ids); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("GetFindings(%d ids) = %v, want ErrInvalidInput", len(ids), err)
		}
		if _, err := s.ApplicableVEX(context.Background(), ids); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("ApplicableVEX(%d ids) = %v, want ErrInvalidInput", len(ids), err)
		}
	}
	if recs, err := s.GetFindings(context.Background(), nil); err != nil || len(recs) != 0 {
		t.Errorf("GetFindings(nil) = %v, %v", recs, err)
	}
	if m, err := s.ApplicableVEX(context.Background(), nil); err != nil || len(m) != 0 {
		t.Errorf("ApplicableVEX(nil) = %v, %v", m, err)
	}
}

func TestLookupIntegration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)

	const purl = "pkg:golang/example.com/a@v1.0.0"
	f1 := vulnFinding("fp-1", "CVE-2024-0001", purl, "grype")
	f1.Vulnerability.Aliases = []string{"GHSA-1111-2222-3333"}
	f2 := vulnFinding("fp-2", "CVE-2024-0002", "pkg:golang/example.com/b@v2.0.0", "grype")
	res, err := s.IngestDocument(ctx, f.runID, f.artifactID, doc("grype", f1, f2))
	if err != nil || len(res.FindingIDs) != 2 {
		t.Fatalf("IngestDocument = %+v, %v", res, err)
	}

	recs, err := s.GetFindings(ctx, []int64{res.FindingIDs[1], res.FindingIDs[0], 999999})
	if err != nil || len(recs) != 2 || recs[0].ID != res.FindingIDs[0] || recs[1].ID != res.FindingIDs[1] {
		t.Fatalf("GetFindings = %+v, %v", recs, err)
	}
	one, err := s.GetFinding(ctx, res.FindingIDs[0])
	if err != nil || one.Finding.Vulnerability == nil || one.Finding.Component == nil || one.Finding.Component.PURL == "" {
		t.Fatalf("GetFinding = %+v, %v", one, err)
	}
	if _, err := s.GetFinding(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetFinding(missing) = %v, want ErrNotFound", err)
	}

	if m, err := s.ApplicableVEX(ctx, res.FindingIDs); err != nil || len(m) != 0 {
		t.Fatalf("ApplicableVEX before VEX = %v, %v", m, err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	vexDoc := evidence.Document{Format: evidence.FormatOpenVEX, Tool: evidence.Tool{Name: "vexctl"}, VEX: []evidence.VEXStatement{
		{VulnID: "GHSA-1111-2222-3333", Products: []string{purl}, Status: evidence.VEXNotAffected,
			Justification: "vulnerable_code_not_in_execute_path", Author: "sec@example.com", Timestamp: t0},
		{VulnID: "CVE-2024-0001", Products: []string{purl}, Status: evidence.VEXAffected, Timestamp: t0.Add(-time.Hour)},
		{VulnID: "CVE-2024-0002", Products: []string{"pkg:golang/example.com/other@v1"}, Status: evidence.VEXFixed},
	}}
	if _, err := s.IngestDocument(ctx, f.runID, 0, vexDoc); err != nil {
		t.Fatal(err)
	}
	m, err := s.ApplicableVEX(ctx, res.FindingIDs)
	if err != nil || len(m) != 1 {
		t.Fatalf("ApplicableVEX = %v, %v", m, err)
	}
	st := m[res.FindingIDs[0]]
	if st.VulnID != "GHSA-1111-2222-3333" || st.Status != evidence.VEXNotAffected || len(st.Products) != 1 ||
		st.Products[0] != purl || st.Author != "sec@example.com" || !st.Timestamp.Equal(t0) ||
		st.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("latest statement = %+v", st)
	}
}
