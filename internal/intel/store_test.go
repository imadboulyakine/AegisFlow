package intel

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

var fetchedAt = time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)

// fixtureSnapshot builds a snapshot from the KEV and EPSS CSV fixtures.
func fixtureSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	cat, err := ParseKEV(bytes.NewReader(readFixture(t, "kev_trimmed.json")))
	if err != nil {
		t.Fatal(err)
	}
	ds, err := ParseEPSSCSV(bytes.NewReader(readFixture(t, "epss_scores.csv")))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSnapshot().WithKEV(cat, KEVMirrorURL, fetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	s, err = s.WithEPSS(ds, "testdata/epss_scores.csv", fetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSnapshotLookup(t *testing.T) {
	t.Parallel()
	s := fixtureSnapshot(t)
	scoreDate := mustDate(t, "2026-10-25")
	tests := []struct {
		name string
		cve  string
		want Intel
	}{
		{"kev and epss", "cve-2021-44228", Intel{
			CVE: "CVE-2021-44228", EPSSKnown: true, EPSS: 0.94401, Percentile: 0.9997, ScoreDate: scoreDate,
			ModelVersion: "v2025.03.14", KEVChecked: true, KEV: true, KEVDateAdded: mustDate(t, "2021-12-10"),
			KEVDueDate: mustDate(t, "2021-12-24"), KEVRansomware: true,
		}},
		{"kev no ransomware", "CVE-2023-44487", Intel{
			CVE: "CVE-2023-44487", EPSSKnown: true, EPSS: 0.81715, Percentile: 0.9912, ScoreDate: scoreDate,
			ModelVersion: "v2025.03.14", KEVChecked: true, KEV: true, KEVDateAdded: mustDate(t, "2023-10-10"),
			KEVDueDate: mustDate(t, "2023-10-31"),
		}},
		{"epss only", "CVE-2024-24790", Intel{
			CVE: "CVE-2024-24790", EPSSKnown: true, EPSS: 0.00087, Percentile: 0.2537, ScoreDate: scoreDate,
			ModelVersion: "v2025.03.14", KEVChecked: true,
		}},
		{"unknown", "CVE-2099-0001", Intel{CVE: "CVE-2099-0001", KEVChecked: true}},
		{"invalid", "GHSA-xxxx", Intel{KEVChecked: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := s.Lookup(tt.cve); got != tt.want {
				t.Errorf("Lookup(%q) =\n%+v\nwant\n%+v", tt.cve, got, tt.want)
			}
		})
	}
	if got := NewSnapshot().Lookup("CVE-2021-44228"); got != (Intel{CVE: "CVE-2021-44228"}) {
		t.Errorf("empty snapshot lookup = %+v", got)
	}
}

func TestSnapshotLookupAll(t *testing.T) {
	t.Parallel()
	s := fixtureSnapshot(t)
	// CVE-2021-45046 (KEV 2023-05-01, EPSS 0.94167) and CVE-2021-44228 (KEV 2021-12-10, EPSS 0.94401).
	got := s.LookupAll([]string{"bogus", "CVE-2021-45046", "CVE-2099-0001", "CVE-2021-44228"})
	if got.CVE != "CVE-2021-45046" || !got.KEV || !got.KEVDateAdded.Equal(mustDate(t, "2021-12-10")) ||
		!got.KEVDueDate.Equal(mustDate(t, "2021-12-24")) || !got.KEVRansomware || got.EPSS != 0.94401 || got.Percentile != 0.9997 {
		t.Errorf("LookupAll = %+v", got)
	}
	if got := s.LookupAll(nil); got != (Intel{KEVChecked: true}) {
		t.Errorf("LookupAll(nil) = %+v", got)
	}
	// Order independence of the merged facts.
	a := s.LookupAll([]string{"CVE-2021-44228", "CVE-2021-45046"})
	b := s.LookupAll([]string{"CVE-2021-45046", "CVE-2021-44228"})
	a.CVE, b.CVE = "", ""
	if a != b {
		t.Errorf("merge depends on order:\n%+v\n%+v", a, b)
	}
}

func TestSnapshotImmutableAndFeeds(t *testing.T) {
	t.Parallel()
	s := fixtureSnapshot(t)
	feeds := s.Feeds()
	if len(feeds) != 2 || feeds[0].Name != FeedKEV || feeds[0].Version != "2026.10.23" || feeds[0].Entries != 21 ||
		feeds[1].Name != FeedEPSS || feeds[1].Version != "v2025.03.14" || feeds[1].Entries != 20 || !feeds[1].FetchedAt.Equal(fetchedAt) {
		t.Fatalf("feeds = %+v", feeds)
	}
	feeds[0].Version = "mutated"
	if s.Feeds()[0].Version != "2026.10.23" {
		t.Error("Feeds exposes internal state")
	}

	cat := &KEVCatalog{CatalogVersion: "x", Vulnerabilities: []KEVEntry{{CVEID: "CVE-2099-0001", DateAdded: fetchedAt}}}
	s2, err := s.WithKEV(cat, "other", fetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Lookup("CVE-2021-44228").KEV || s.Lookup("CVE-2099-0001").KEV {
		t.Error("WithKEV modified the receiver")
	}
	if s2.Lookup("CVE-2021-44228").KEV || !s2.Lookup("CVE-2099-0001").KEV || !s2.Lookup("CVE-2021-44228").EPSSKnown {
		t.Error("WithKEV result wrong")
	}
	if NewSnapshot().Feeds() != nil {
		t.Error("empty snapshot has feeds")
	}
}

func TestSnapshotWithErrors(t *testing.T) {
	t.Parallel()
	s := NewSnapshot()
	kevs := map[string]*KEVCatalog{
		"nil":       nil,
		"empty":     {},
		"bad id":    {Vulnerabilities: []KEVEntry{{CVEID: "nope"}}},
		"duplicate": {Vulnerabilities: []KEVEntry{{CVEID: "CVE-2024-3400"}, {CVEID: "cve-2024-3400"}}},
	}
	for name, cat := range kevs {
		if _, err := s.WithKEV(cat, "", time.Time{}); err == nil {
			t.Errorf("WithKEV(%s) accepted", name)
		}
	}
	sets := map[string]*EPSSDataset{
		"nil":       nil,
		"bad id":    {Scores: []EPSSScore{{CVE: "nope"}}},
		"epss":      {Scores: []EPSSScore{{CVE: "CVE-2024-3400", EPSS: 2}}},
		"pct":       {Scores: []EPSSScore{{CVE: "CVE-2024-3400", Percentile: -1}}},
		"duplicate": {Scores: []EPSSScore{{CVE: "CVE-2024-3400"}, {CVE: "CVE-2024-3400"}}},
	}
	for name, ds := range sets {
		if _, err := s.WithEPSS(ds, "", time.Time{}); err == nil {
			t.Errorf("WithEPSS(%s) accepted", name)
		}
	}
	if _, err := s.WithEPSS(&EPSSDataset{}, "api", time.Time{}); err != nil {
		t.Errorf("empty EPSS dataset rejected: %v", err)
	}
}

func TestSnapshotSubsetGoldenRoundTrip(t *testing.T) {
	t.Parallel()
	full := fixtureSnapshot(t)
	cves := []string{"CVE-2021-44228", "CVE-2023-44487", "CVE-2024-24790", "CVE-2016-3081", "CVE-2099-0001", "junk"}
	sub := full.Subset(cves)

	var buf bytes.Buffer
	if err := sub.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "snapshot_subset.golden.json")
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run go test -update): %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("snapshot JSON differs from %s:\n%s", golden, buf.String())
	}

	back, err := ReadSnapshot(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadSnapshot: %v", err)
	}
	for _, c := range cves {
		if got, want := back.Lookup(c), full.Lookup(c); got != want {
			t.Errorf("round trip %s:\n%+v\nwant\n%+v", c, got, want)
		}
	}
	if f := back.Feeds(); len(f) != 2 || f[0].Entries != 3 || f[1].Entries != 3 || !f[0].Date.Equal(full.Feeds()[0].Date) {
		t.Errorf("feeds after round trip = %+v", f)
	}
	var again bytes.Buffer
	if err := back.WriteJSON(&again); err != nil || !bytes.Equal(again.Bytes(), buf.Bytes()) {
		t.Errorf("re-export not byte-identical (err %v)", err)
	}

	var empty bytes.Buffer
	if err := NewSnapshot().WriteJSON(&empty); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadSnapshot(&empty); err != nil || s.Feeds() != nil {
		t.Errorf("empty round trip: %v", err)
	}
}

func TestReadSnapshotErrors(t *testing.T) {
	t.Parallel()
	const feeds = `"feeds":[{"name":"kev","entries":1},{"name":"epss","entries":1}]`
	tests := []struct{ name, in, want string }{
		{"not json", "x", "invalid character"},
		{"version", `{"formatVersion":2}`, "formatVersion"},
		{"unknown field", `{"formatVersion":1,"feeds":[],"records":[],"extra":1}`, "unknown field"},
		{"trailing data", `{"formatVersion":1,"feeds":[],"records":[]} {}`, "trailing data"},
		{"feed date range", `{"formatVersion":1,"feeds":[{"name":"kev","date":"9999-12-31T23:00:00-05:00"}]}`, "out of range"},
		{"unknown feed", `{"formatVersion":1,"feeds":[{"name":"nvd"}]}`, "unknown or duplicate feed"},
		{"duplicate feed", `{"formatVersion":1,"feeds":[{"name":"kev"},{"name":"kev"}]}`, "unknown or duplicate feed"},
		{"bad cve", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"x"}]}`, "invalid cve"},
		{"empty record", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400"}]}`, "no data"},
		{"duplicate", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","kev":true,"kevDateAdded":"2024-04-12"},{"cve":"CVE-2024-3400","kev":true,"kevDateAdded":"2024-04-12"}]}`, "duplicate"},
		{"kev without feed", `{"formatVersion":1,"feeds":[],"records":[{"cve":"CVE-2024-3400","kev":true,"kevDateAdded":"2024-04-12"}]}`, "without a kev feed"},
		{"kev false with data", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","kevRansomware":true}]}`, "kev=true"},
		{"kev date", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","kev":true,"kevDateAdded":"x"}]}`, "kevDateAdded"},
		{"kev due", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","kev":true,"kevDateAdded":"2024-04-12","kevDueDate":"x"}]}`, "kevDueDate"},
		{"epss without pct", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","epss":0.1}]}`, "percentile"},
		{"epss range", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","epss":1.1,"percentile":0.1}]}`, "outside"},
		{"pct range", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","epss":0.1,"percentile":1.1}]}`, "outside"},
		{"score date", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","epss":0.1,"percentile":0.1,"scoreDate":"x"}]}`, "scoreDate"},
		{"kev entries mismatch", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","epss":0.1,"percentile":0.1}]}`, "kev feed declares"},
		{"epss entries mismatch", `{"formatVersion":1,` + feeds + `,"records":[{"cve":"CVE-2024-3400","kev":true,"kevDateAdded":"2024-04-12"}]}`, "epss feed declares"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ReadSnapshot(strings.NewReader(tt.in))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestMemoryStore(t *testing.T) {
	t.Parallel()
	var zero MemoryStore
	if got := zero.Lookup("CVE-2021-44228"); got.KEV || got.KEVChecked {
		t.Errorf("zero store lookup = %+v", got)
	}

	full := fixtureSnapshot(t)
	m := NewMemoryStore(nil)
	cat, err := ParseKEV(bytes.NewReader(readFixture(t, "kev_trimmed.json")))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateKEV(cat, "kev", fetchedAt); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateEPSS(nil, "bad", fetchedAt); err == nil {
		t.Error("UpdateEPSS(nil) accepted")
	}
	if err := m.UpdateKEV(nil, "bad", fetchedAt); err == nil {
		t.Error("UpdateKEV(nil) accepted")
	}
	if got := m.Lookup("CVE-2021-44228"); !got.KEV || got.EPSSKnown {
		t.Errorf("after KEV update = %+v", got)
	}
	ds, err := ParseEPSSCSV(bytes.NewReader(readFixture(t, "epss_scores.csv")))
	if err != nil {
		t.Fatal(err)
	}

	// Concurrent readers while a writer updates: run with -race.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				in := m.LookupAll([]string{"CVE-2021-44228"})
				if !in.KEV {
					t.Error("KEV lost during update")
					return
				}
				_ = m.Feeds()
			}
		})
	}
	if err := m.UpdateEPSS(ds, "epss", fetchedAt); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if got, want := m.Lookup("CVE-2021-44228"), full.Lookup("CVE-2021-44228"); got != want {
		t.Errorf("after EPSS update = %+v, want %+v", got, want)
	}
	m.Replace(nil)
	if len(m.Feeds()) != 0 {
		t.Error("Replace(nil) kept feeds")
	}
	m.Replace(full)
	if m.Snapshot() != full {
		t.Error("Replace did not install snapshot")
	}
}
