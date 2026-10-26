package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testBearer is a dummy value for the fake API; it only has to be recognisable in outputs.
const testBearer = "unit-test"

var (
	shaA = strings.Repeat("a", 40)
	shaB = strings.Repeat("b", 40)
	shaC = strings.Repeat("c", 40)
	t0   = time.Date(2026, time.October, 1, 10, 0, 0, 0, time.UTC)
)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func mkRun(id int64, sha, status, conclusion string, startSec int) Run {
	return Run{
		ID: id, HeadSHA: sha, Event: "pull_request", Status: status, Conclusion: conclusion, RunAttempt: 1,
		CreatedAt: at(startSec), RunStartedAt: at(startSec), UpdatedAt: at(startSec + 600),
	}
}

func mkJob(id int64, name string, start, end int) Job {
	return Job{
		ID: id, Name: name, Status: "completed", Conclusion: "success",
		StartedAt: at(start), CompletedAt: at(end), Labels: []string{"ubuntu-latest"},
	}
}

// fakeGitHub serves the three endpoints E4 uses, with pagination on the baseline run list and
// on the jobs of run 101. Every request must carry the bearer token and the event filter.
type fakeGitHub struct {
	t        *testing.T
	runs     map[string][]Run // workflow -> runs, newest first
	jobs     map[int64][]Job
	requests int
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	return &fakeGitHub{
		t: t,
		runs: map[string][]Run{
			"ci.yml": {
				mkRun(101, shaA, "completed", "success", 0),
				mkRun(100, shaA, "completed", "success", -3600), // older run on the same SHA: de-duplicated
				mkRun(102, shaB, "completed", "success", 3600),
				mkRun(103, shaC, "completed", "success", 7200),
			},
			"code-security.yml": {
				mkRun(201, shaA, "completed", "success", 2),
				mkRun(202, shaB, "completed", "cancelled", 3605), // newest for B but cancelled: skipped
				mkRun(203, shaB, "completed", "failure", 3602),
			},
		},
		jobs: map[int64][]Job{
			101: {mkJob(1, "go", 10, 190), mkJob(2, "web", 5, 65), mkJob(3, "container", 20, 141)},
			102: {mkJob(4, "go", 3610, 3790), mkJob(5, "web", 3605, 3665), mkJob(6, "container", 3620, 3741)},
			103: {mkJob(7, "go", 7210, 7400), mkJob(8, "web", 7205, 7265), mkJob(9, "container", 7220, 7340)},
			201: {mkJob(10, "gitleaks", 12, 42), mkJob(11, "semgrep", 12, 252)},
			203: {mkJob(12, "gitleaks", 3612, 3642), mkJob(13, "semgrep", 3612, 3900)},
		},
	}
}

func (f *fakeGitHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/widgets/actions/workflows/{wf}/runs", func(w http.ResponseWriter, r *http.Request) {
		runs, ok := f.runs[r.PathValue("wf")]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		if q.Get("event") != "pull_request" {
			f.t.Errorf("missing event filter: %s", r.URL.RawQuery)
		}
		if sha := q.Get("head_sha"); sha != "" {
			var filtered []Run
			for _, run := range runs {
				if run.HeadSHA == sha {
					filtered = append(filtered, run)
				}
			}
			writeJSON(w, map[string]any{"total_count": len(filtered), "workflow_runs": filtered})
			return
		}
		if q.Get("status") != "success" {
			f.t.Errorf("baseline list without status=success: %s", r.URL.RawQuery)
		}
		// Two runs per page, with a Link header to the next page.
		page, _ := strconv.Atoi(q.Get("page"))
		page = max(page, 1)
		lo, hi := (page-1)*2, min(page*2, len(runs))
		if hi < len(runs) {
			next := *r.URL
			nq := next.Query()
			nq.Set("page", strconv.Itoa(page+1))
			next.RawQuery = nq.Encode()
			w.Header().Set("Link", `<http://`+r.Host+next.String()+`>; rel="next"`)
		}
		writeJSON(w, map[string]any{"total_count": len(runs), "workflow_runs": runs[lo:hi]})
	})
	mux.HandleFunc("GET /repos/acme/widgets/actions/runs/{id}/jobs", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		jobs := f.jobs[id]
		if id == 101 && r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", `<http://`+r.Host+r.URL.Path+`?filter=latest&per_page=100&page=2>; rel="next"`)
			jobs = jobs[:2]
		} else if id == 101 {
			jobs = jobs[2:]
		}
		writeJSON(w, map[string]any{"total_count": len(jobs), "jobs": jobs})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests++
		if r.Header.Get("Authorization") != "Bearer "+testBearer {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func env(token string) func(string) string {
	return func(k string) string {
		if k == "GITHUB_TOKEN" {
			return token
		}
		return ""
	}
}

func readCSV(t *testing.T, path string) []map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	for _, row := range rows[1:] {
		m := map[string]string{}
		for i, h := range rows[0] {
			m[h] = row[i]
		}
		out = append(out, m)
	}
	return out
}

func TestRunEndToEnd(t *testing.T) {
	t.Parallel()
	fake := newFakeGitHub(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	outDir := filepath.Join(t.TempDir(), "e4")

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"-repo", "acme/widgets", "-api", srv.URL, "-runs", "3", "-event", "pull_request",
		"-workflows", "ci.yml,code-security.yml,supply-chain.yml", "-out", outDir,
	}, env(testBearer), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr.String())
	}

	pipes := readCSV(t, filepath.Join(outDir, "pipelines.csv"))
	if len(pipes) != 3 {
		t.Fatalf("pipelines = %d, want 3", len(pipes))
	}
	a := pipes[0]
	want := map[string]string{
		"head_sha": shaA, "baseline_run_id": "101",
		"baseline_wall_s": "190.0", "baseline_job_s": "361.0", "baseline_billed_min": "7",
		"full_runs": "2", "full_wall_s": "252.0", "full_job_s": "631.0", "full_billed_min": "12",
		"overhead_wall_s": "62.0", "overhead_wall_pct": "32.6", "overhead_billed_min": "5",
		"missing_workflows": "supply-chain.yml",
	}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("SHA A %s = %q, want %q", k, a[k], v)
		}
	}
	if b := pipes[1]; b["full_runs"] != "2" || !strings.Contains(b["missing_workflows"], "supply-chain.yml") {
		t.Errorf("SHA B should use the non-cancelled run 203: %v", b)
	}
	if c := pipes[2]; c["full_runs"] != "1" || c["missing_workflows"] != "code-security.yml supply-chain.yml" {
		t.Errorf("SHA C should miss both other workflows: %v", c)
	}

	jobs := readCSV(t, filepath.Join(outDir, "jobs.csv"))
	if len(jobs) != 3+2+3+2+3 {
		t.Errorf("jobs.csv rows = %d, want 13 (pagination of run 101 included)", len(jobs))
	}

	summary, err := os.ReadFile(filepath.Join(outDir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"jobs.csv SHA-256 | `sha256:", "| `code-security.yml` | semgrep | 2 |", "Billed minutes per PR", "| `supply-chain.yml` | 0 | 3 |"} {
		if !strings.Contains(string(summary), s) {
			t.Errorf("summary.md lacks %q", s)
		}
	}

	// The token must never leave the Authorization header.
	for name, data := range map[string][]byte{"stdout": stdout.Bytes(), "stderr": stderr.Bytes(), "summary": summary} {
		if bytes.Contains(data, []byte(testBearer)) {
			t.Errorf("token leaked into %s", name)
		}
	}
	for _, f := range []string{"jobs.csv", "pipelines.csv"} {
		data, _ := os.ReadFile(filepath.Join(outDir, f))
		if bytes.Contains(data, []byte(testBearer)) {
			t.Errorf("token leaked into %s", f)
		}
	}
}

func TestRunUsageErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		args  []string
		token string
	}{
		{"no token", []string{"-repo", "acme/widgets"}, ""},
		{"bad repo", []string{"-repo", "acme"}, testBearer},
		{"plain http to a remote host", []string{"-repo", "acme/widgets", "-api", "http://api.example.com"}, testBearer},
		{"bad workflow", []string{"-repo", "acme/widgets", "-workflows", "../x.yml"}, testBearer},
		{"runs out of range", []string{"-repo", "acme/widgets", "-runs", "0"}, testBearer},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			if code := run(context.Background(), tc.args, env(tc.token), io.Discard, &stderr); code != exitUsage {
				t.Errorf("exit %d, want %d (stderr %q)", code, exitUsage, stderr.String())
			}
		})
	}
}

func TestBadCredentialsAndRateLimit(t *testing.T) {
	t.Parallel()
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1798761600")
		http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
	}))
	defer limited.Close()
	fake := httptest.NewServer(newFakeGitHub(t).handler())
	defer fake.Close()

	for name, tc := range map[string]struct{ url, token, want string }{
		"rate limit":      {limited.URL, testBearer, "rate limited until 2027-01-01T00:00:00Z"},
		"bad credentials": {fake.URL, "wrong", "HTTP 401: Bad credentials"},
	} {
		var stderr bytes.Buffer
		code := run(context.Background(), []string{"-repo", "acme/widgets", "-api", tc.url, "-out", t.TempDir()}, env(tc.token), io.Discard, &stderr)
		if code != exitError || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%s: exit %d, stderr %q, want %q", name, code, stderr.String(), tc.want)
		}
	}
}

func TestClientRefusesForeignNextLink(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<https://elsewhere.example/repos/acme/widgets/actions/runs/1/jobs?page=2>; rel="next"`)
		writeJSON(w, map[string]any{"jobs": []Job{{ID: 1}}})
	}))
	defer srv.Close()
	base, err := parseAPIBase(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(base, "acme/widgets", testBearer, slog.New(slog.DiscardHandler))
	if _, err := c.listJobs(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "outside the API origin") {
		t.Fatalf("err = %v, want refusal of a cross-origin next link", err)
	}
}

func TestParseAPIBase(t *testing.T) {
	t.Parallel()
	for raw, ok := range map[string]bool{
		"https://api.github.com":         true,
		"https://ghe.example/api/v3/":    true,
		"http://127.0.0.1:8080":          true,
		"http://localhost:9000":          true,
		"http://api.github.com":          false,
		"ftp://api.github.com":           false,
		"api.github.com":                 false,
		"https://":                       false,
		"http://127.0.0.1.attacker.test": false,
	} {
		if _, err := parseAPIBase(raw); (err == nil) != ok {
			t.Errorf("parseAPIBase(%q) err = %v, want ok=%v", raw, err, ok)
		}
	}
}

func TestBilledMinutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		d      time.Duration
		labels []string
		want   int
	}{
		{0, []string{"ubuntu-latest"}, 0},
		{time.Second, []string{"ubuntu-latest"}, 1},
		{60 * time.Second, []string{"ubuntu-24.04"}, 1},
		{61 * time.Second, []string{"ubuntu-24.04"}, 2},
		{90 * time.Second, []string{"windows-latest"}, 4},
		{30 * time.Second, []string{"macos-15"}, 10},
		{10 * time.Minute, []string{"self-hosted", "linux"}, 0},
	}
	for _, tc := range tests {
		if got := billedMinutes(tc.d, tc.labels); got != tc.want {
			t.Errorf("billedMinutes(%v, %v) = %d, want %d", tc.d, tc.labels, got, tc.want)
		}
	}
}

func TestSummarize(t *testing.T) {
	t.Parallel()
	s := summarize([]float64{10, 1, 9, 2, 8, 3, 7, 4, 6, 5})
	if s.N != 10 || s.Median != 5.5 || math.Abs(s.P90-9.1) > 1e-9 || s.Mean != 5.5 || s.Min != 1 || s.Max != 10 {
		t.Errorf("summarize = %+v", s)
	}
	if one := summarize([]float64{42}); one.Median != 42 || one.P90 != 42 {
		t.Errorf("single value: %+v", one)
	}
	if empty := summarize(nil); empty.N != 0 || !math.IsNaN(empty.Median) || num(empty.Median) != "n/a" {
		t.Errorf("empty: %+v", empty)
	}
}

func TestTotalsWithoutJobsUsesRunTimes(t *testing.T) {
	t.Parallel()
	r := RunSample{Run: Run{CreatedAt: at(0), UpdatedAt: at(45)}}
	if got := totals(r); got.Wall != 45*time.Second || got.BilledMin != 0 || got.Runs != 1 {
		t.Errorf("totals = %+v", got)
	}
}

func TestEndpointEscapesWorkflow(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://ghe.example/api/v3")
	c := newClient(base, "acme/widgets", "", slog.New(slog.DiscardHandler))
	got := c.endpoint("/actions/workflows/a b.yml/runs", url.Values{"per_page": {"1"}})
	if got.String() != "https://ghe.example/api/v3/repos/acme/widgets/actions/workflows/a%20b.yml/runs?per_page=1" {
		t.Errorf("endpoint = %s", got)
	}
}
