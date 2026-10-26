package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/auth/ghoidc"
	"github.com/imadboulyakine/aegisflow/internal/config"
	"github.com/imadboulyakine/aegisflow/internal/ingest"
	"github.com/imadboulyakine/aegisflow/internal/ingest/ingesttest"
	"github.com/imadboulyakine/aegisflow/internal/risk"
)

// TestEndToEnd exercises the Phase 2 vertical slice over real HTTP: a JWKS-signed GitHub Actions
// token, real PostgreSQL, the normalizers, the risk engine and the read API. It runs only when
// AEGISFLOW_TEST_DATABASE_URL is set.
func TestEndToEnd(t *testing.T) {
	t.Parallel()
	st := ingesttest.Store(t)
	iss := ingesttest.NewIssuer(t)
	v, err := ghoidc.NewVerifier(ghoidc.Config{Issuer: iss.URL, Audience: p2Aud, AllowedRepositoryIDs: []int64{101}, AllowedOwnerIDs: []int64{202}})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ingest.New(ingest.Options{
		Store: st,
		// Synthetic intelligence: CVE-2022-32149 is NOT in the real KEV catalogue.
		Intel:    ingesttest.Intel(t, []string{"CVE-2022-32149"}, map[string]float64{"CVE-2022-32149": 0.6, "CVE-2005-2541": 0.02}),
		Exposure: risk.ExposureInternet,
	})
	if err != nil {
		t.Fatal(err)
	}
	s, logs := newP2Server(t, func(c *config.Config) { c.DevReadOnlyAPI = true },
		Options{Static: testFS(), Verifier: v, Ingester: svc, Findings: st, Ready: st.Ping})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	token := iss.Mint(t, iss.Claims(p2Aud, 101, 202, p2SHA))

	upload := func(name string) (int, ingest.Result) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("..", "evidence", "normalize", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{
			"artifact": map[string]string{"kind": "container-image", "name": "ghcr.io/octo/demo", "digest": p2Digest},
			"commit":   p2SHA,
			"evidence": base64.StdEncoding.EncodeToString(raw),
		})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+ingestPath, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var out ingest.Result
		if res.StatusCode < 300 {
			if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
		}
		return res.StatusCode, out
	}

	code, grype := upload("grype-image-handbuilt.json")
	if code != http.StatusCreated || grype.Counts.FindingsNew != 2 || grype.Scored != 2 {
		t.Fatalf("grype upload = %d %+v", code, grype)
	}
	code, govuln := upload("govulncheck-source.json")
	if code != http.StatusCreated || !govuln.Evidence.StreamWrapped || govuln.Counts.FindingsNew != 2 || govuln.Counts.FindingsSeen != 1 {
		t.Fatalf("govulncheck upload = %d %+v", code, govuln)
	}
	if govuln.TopFindings[0].VulnID != "CVE-2022-32149" || govuln.TopFindings[0].Tier != risk.TierP1 {
		t.Fatalf("govulncheck top finding = %+v", govuln.TopFindings[0])
	}
	code, vex := upload("openvex-govulncheck.json")
	if code != http.StatusCreated || vex.Counts.VEXStatusChanges != 2 {
		t.Fatalf("openvex upload = %d %+v", code, vex)
	}
	if code, replay := upload("openvex-govulncheck.json"); code != http.StatusOK || replay.Evidence.Created {
		t.Fatalf("replay = %d %+v", code, replay)
	}

	get := func(path string, out any) int {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode == http.StatusOK && out != nil {
			if err := json.NewDecoder(res.Body).Decode(out); err != nil {
				t.Fatal(err)
			}
		}
		return res.StatusCode
	}

	type item struct {
		ID            int64  `json:"id"`
		Status        string `json:"status"`
		Reachability  string `json:"reachability"`
		Vulnerability struct {
			ID string `json:"id"`
		} `json:"vulnerability"`
		Component struct {
			PURL string `json:"purl"`
		} `json:"component"`
		Tools []string `json:"tools"`
		Risk  *struct {
			Score       float64  `json:"score"`
			Tier        string   `json:"tier"`
			Reason      string   `json:"reason"`
			Flags       []string `json:"flags"`
			Explanation *struct {
				Factors []struct {
					Name         string  `json:"name"`
					Contribution float64 `json:"contribution"`
				} `json:"factors"`
			} `json:"explanation"`
		} `json:"risk"`
	}
	var page struct {
		Findings   []item `json:"findings"`
		NextCursor string `json:"nextCursor"`
	}
	if code := get("/api/v1/findings", &page); code != http.StatusOK || len(page.Findings) != 4 || page.NextCursor != "" {
		t.Fatalf("list = %d %+v", code, page)
	}
	want := []struct {
		vuln, tier, status string
		score              float64
	}{
		{"CVE-2022-32149", "P1", "open", 76},            // CVSS 7.5, EPSS 0.6, KEV, called, internet (+ KEV override)
		{"CVE-2005-2541", "P3", "open", 28.49},          // CVSS 10 (NVD), EPSS 0.02, unknown reachability
		{"CVE-2023-39325", "P3", "vex_not_affected", 0}, // equal scores: higher finding ID first
		{"CVE-2026-25681", "P3", "vex_not_affected", 0},
	}
	for i, w := range want {
		got := page.Findings[i]
		if got.Vulnerability.ID != w.vuln || got.Risk == nil || got.Risk.Tier != w.tier || got.Status != w.status || got.Risk.Score != w.score {
			t.Errorf("finding %d = %s %s %s %+v, want %+v", i, got.Vulnerability.ID, got.Status, got.Reachability, got.Risk, w)
		}
	}
	top := page.Findings[0]
	if top.Reachability != "called" || len(top.Tools) != 2 || top.Component.PURL != "pkg:golang/golang.org/x/text@v0.3.7" {
		t.Errorf("top finding = %+v", top)
	}

	var p1 struct {
		Findings []item `json:"findings"`
	}
	if code := get("/api/v1/findings?tier=P1&status=open&kind=vulnerability", &p1); code != http.StatusOK || len(p1.Findings) != 1 {
		t.Fatalf("P1 filter = %d %+v", code, p1)
	}
	var paged struct {
		Findings   []item `json:"findings"`
		NextCursor string `json:"nextCursor"`
	}
	if code := get("/api/v1/findings?limit=3", &paged); code != http.StatusOK || len(paged.Findings) != 3 || paged.NextCursor == "" {
		t.Fatalf("page 1 = %d %+v", code, paged)
	}
	var rest struct {
		Findings []item `json:"findings"`
	}
	if code := get("/api/v1/findings?limit=3&cursor="+paged.NextCursor, &rest); code != http.StatusOK || len(rest.Findings) != 1 ||
		rest.Findings[0].Vulnerability.ID != "CVE-2026-25681" {
		t.Fatalf("page 2 = %d %+v", code, rest)
	}

	var detail item
	if code := get("/api/v1/findings/"+strconv.FormatInt(top.ID, 10), &detail); code != http.StatusOK {
		t.Fatalf("detail = %d", code)
	}
	if detail.Risk == nil || detail.Risk.Explanation == nil || len(detail.Risk.Explanation.Factors) != 7 {
		t.Fatalf("detail risk = %+v", detail.Risk)
	}
	var sum float64
	for _, f := range detail.Risk.Explanation.Factors {
		sum += f.Contribution
	}
	if sum < 75.9 || sum > 76.1 {
		t.Errorf("factor contributions sum to %.2f, want 76", sum)
	}
	if code := get("/api/v1/findings/999999", nil); code != http.StatusNotFound {
		t.Errorf("missing finding = %d", code)
	}
	if code := get("/readyz", nil); code != http.StatusOK {
		t.Errorf("readyz = %d", code)
	}

	// Wrong commit: 403 and nothing stored.
	other := iss.Claims(p2Aud, 101, 202, p2SHA)
	other["sha"] = "fedcba9876543210fedcba9876543210fedcba98"
	token = iss.Mint(t, other)
	if code, _ := upload("grype-image-handbuilt.json"); code != http.StatusForbidden {
		t.Errorf("commit mismatch = %d", code)
	}
	if bytes.Contains([]byte(logs.String()), []byte(token)) {
		t.Error("token leaked into logs")
	}
}
