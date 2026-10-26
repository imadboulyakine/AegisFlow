package ingest

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/ingest/ingesttest"
	"github.com/imadboulyakine/aegisflow/internal/risk"
	"github.com/imadboulyakine/aegisflow/internal/store"
)

// TestIngestIntegration runs grype + govulncheck + govulncheck's OpenVEX through the real store.
func TestIngestIntegration(t *testing.T) {
	t.Parallel()
	st := ingesttest.Store(t)
	svc := newService(t, st, Options{
		Intel:    ingesttest.Intel(t, []string{"CVE-2022-32149"}, map[string]float64{"CVE-2022-32149": 0.6}),
		Exposure: risk.ExposureInternet,
	})
	ctx := t.Context()

	for _, name := range []string{"grype-image-handbuilt.json", "govulncheck-source.json", "openvex-govulncheck.json"} {
		res, err := svc.Ingest(ctx, testClaims(), imageRequest(fixture(t, name)))
		if err != nil {
			t.Fatalf("ingest %s: %v", name, err)
		}
		if !res.Evidence.Created || res.Evidence.SHA256 == "" {
			t.Fatalf("ingest %s: %+v", name, res.Evidence)
		}
	}

	page, err := st.ListFindings(ctx, store.FindingFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	byVuln := map[string]store.FindingRecord{}
	for _, r := range page.Findings {
		byVuln[r.Finding.Vulnerability.ID] = r
	}
	if len(byVuln) != 4 {
		t.Fatalf("findings = %d (%v)", len(page.Findings), byVuln)
	}
	// x/text: reported by both tools, merged; govulncheck says called → KEV override to P1.
	text := byVuln["CVE-2022-32149"]
	if text.Status != store.StatusOpen || text.Finding.Reachability != evidence.ReachabilityCalled ||
		!slices.Equal(toolNames(text), []string{"govulncheck", "grype"}) || text.Risk == nil || text.Risk.Tier != store.TierP1 {
		t.Fatalf("x/text finding = %+v risk=%+v", text, text.Risk)
	}
	var expl risk.Result
	if err := json.Unmarshal(text.Risk.Explanation, &expl); err != nil || !expl.HasFlag(risk.FlagKEVOverride) || expl.Score != 76 {
		t.Fatalf("x/text explanation = %+v (%v)", expl, err)
	}
	// x/net: govulncheck's VEX (percent-encoded package URLs) suppresses both findings.
	for _, id := range []string{"CVE-2023-39325", "CVE-2026-25681"} {
		r := byVuln[id]
		if r.Status != store.StatusVEXNotAffected || r.Risk == nil || r.Risk.Score != 0 || r.Risk.Tier != store.TierP3 {
			t.Errorf("%s = status %s risk %+v, want vex_not_affected / 0 / P3", id, r.Status, r.Risk)
		}
	}
	// tar: info severity but CVSS 10 (NVD), reachability unknown → 100×0.4×0.7 = 28 → P3.
	if tar := byVuln["CVE-2005-2541"]; tar.Risk == nil || tar.Risk.Score != 28 || tar.Risk.Tier != store.TierP3 {
		t.Errorf("tar = %+v", tar.Risk)
	}
	// Ordered by risk.
	if page.Findings[0].Finding.Vulnerability.ID != "CVE-2022-32149" {
		t.Errorf("first finding = %s", page.Findings[0].Finding.Vulnerability.ID)
	}

	// A replay of the same evidence is idempotent.
	res, err := svc.Ingest(ctx, testClaims(), imageRequest(fixture(t, "grype-image-handbuilt.json")))
	if err != nil || res.Evidence.Created || res.Counts.FindingsNew != 0 || res.Counts.FindingsSeen != 2 {
		t.Fatalf("replay = %+v, %v", res, err)
	}

	// The same run re-recorded with another commit is a conflict.
	c := testClaims()
	c.SHA = "fedcba9876543210fedcba9876543210fedcba98"
	req := imageRequest(fixture(t, "grype-image-handbuilt.json"))
	req.Commit = c.SHA
	if _, err := svc.Ingest(context.WithoutCancel(ctx), c, req); KindOf(err) != KindConflict {
		t.Fatalf("conflicting run = %v, want conflict", err)
	}
}

func toolNames(r store.FindingRecord) []string {
	out := make([]string, 0, len(r.Finding.Tools))
	for _, tl := range r.Finding.Tools {
		out = append(out, tl.Name)
	}
	return out
}
