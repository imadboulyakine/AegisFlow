package intel

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func seedFile(f *testing.F, name string) {
	f.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
}

func FuzzParseKEV(f *testing.F) {
	seedFile(f, "kev_trimmed.json")
	f.Add([]byte(minimalKEV))
	f.Add([]byte(`{"catalogVersion":"v","dateReleased":"2026-01-02T03:04:05Z","count":1,"vulnerabilities":[{"cveID":"CVE-2024-3400","dateAdded":"2024-04-12"}]}`))
	f.Add([]byte(`{"count":-1,"vulnerabilities":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		cat, err := ParseKEV(bytes.NewReader(b))
		if err != nil {
			return
		}
		if cat.Count != len(cat.Vulnerabilities) || cat.Count == 0 {
			t.Fatalf("count %d, %d entries", cat.Count, len(cat.Vulnerabilities))
		}
		seen := map[string]bool{}
		for _, e := range cat.Vulnerabilities {
			if id, ok := NormalizeCVE(e.CVEID); !ok || id != e.CVEID || seen[id] || e.DateAdded.IsZero() {
				t.Fatalf("invalid entry accepted: %+v", e)
			}
			seen[e.CVEID] = true
		}
		if _, err := NewSnapshot().WithKEV(cat, "fuzz", fetchedAt); err != nil {
			t.Fatalf("parsed catalogue rejected by snapshot: %v", err)
		}
	})
}

func validScore(s EPSSScore) bool {
	id, ok := NormalizeCVE(s.CVE)
	return ok && id == s.CVE && !math.IsNaN(s.EPSS) && s.EPSS >= 0 && s.EPSS <= 1 &&
		!math.IsNaN(s.Percentile) && s.Percentile >= 0 && s.Percentile <= 1
}

func FuzzParseEPSSResponse(f *testing.F) {
	seedFile(f, "epss_api_response.json")
	f.Add([]byte(`{"status":"OK","status-code":200,"data":[{"cve":"CVE-2024-3400","epss":0.5,"percentile":"1","date":"2026-10-25"}]}`))
	f.Add([]byte(`{"status":"OK","status-code":200,"data":[{"cve":"CVE-2024-3400","epss":"1e-3","percentile":"0x1p-2","date":"2026-10-25"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		resp, err := ParseEPSSResponse(bytes.NewReader(b))
		if err != nil {
			return
		}
		for _, s := range resp.Data {
			if !validScore(s) || s.Date.IsZero() {
				t.Fatalf("invalid score accepted: %+v", s)
			}
		}
	})
}

func FuzzParseEPSSCSV(f *testing.F) {
	seedFile(f, "epss_scores.csv")
	f.Add([]byte("cve,epss,percentile\nCVE-2024-3400,0.9,0.99\n"))
	f.Add([]byte("#model_version:v4,score_date:2026-10-25\n\"cve\",epss,percentile\n\"CVE-2024-3400\",\"0.9\",0.99"))
	f.Add([]byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ds, err := parseEPSSCSV(bytes.NewReader(b), 1<<20)
		if err != nil {
			return
		}
		if len(ds.Scores) == 0 {
			t.Fatal("empty dataset accepted")
		}
		seen := map[string]bool{}
		for _, s := range ds.Scores {
			if !validScore(s) || seen[s.CVE] {
				t.Fatalf("invalid or duplicate score accepted: %+v", s)
			}
			seen[s.CVE] = true
		}
		if _, err := NewSnapshot().WithEPSS(ds, "fuzz", fetchedAt); err != nil {
			t.Fatalf("parsed dataset rejected by snapshot: %v", err)
		}
	})
}

func FuzzReadSnapshot(f *testing.F) {
	seedFile(f, "snapshot_subset.golden.json")
	f.Add([]byte(`{"formatVersion":1,"feeds":[],"records":[]}`))
	f.Add([]byte(`{"formatVersion":1,"feeds":[{"name":"epss","entries":1}],"records":[{"cve":"CVE-2024-3400","epss":0,"percentile":0}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ReadSnapshot(bytes.NewReader(b))
		if err != nil {
			return
		}
		// Whatever is accepted must re-export and re-import to a byte-identical file.
		var first, second bytes.Buffer
		if err := s.WriteJSON(&first); err != nil {
			t.Fatal(err)
		}
		back, err := ReadSnapshot(bytes.NewReader(first.Bytes()))
		if err != nil {
			t.Fatalf("re-read of exported snapshot failed: %v\n%s", err, first.String())
		}
		if err := back.WriteJSON(&second); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Fatalf("export not stable:\n%s\n---\n%s", first.String(), second.String())
		}
	})
}

func FuzzNormalizeCVE(f *testing.F) {
	for _, s := range []string{"CVE-2021-44228", " cve-2026-114625 ", "CVE-2021-123", "ＣＶＥ-2021-44228"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, ok := NormalizeCVE(s)
		if !ok {
			return
		}
		if again, ok2 := NormalizeCVE(id); !ok2 || again != id {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, id, again)
		}
		if len(id) < 13 || len(id) > 28 {
			t.Fatalf("length %d out of bounds: %q", len(id), id)
		}
	})
}
