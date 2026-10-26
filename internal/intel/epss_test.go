package intel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseEPSSResponseFixture(t *testing.T) {
	t.Parallel()
	resp, err := ParseEPSSResponse(bytes.NewReader(readFixture(t, "epss_api_response.json")))
	if err != nil {
		t.Fatalf("ParseEPSSResponse: %v", err)
	}
	if resp.Total != 4 || len(resp.Data) != 4 || resp.Limit != 100 || resp.StatusCode != http.StatusOK {
		t.Fatalf("resp = %+v", resp)
	}
	got := resp.Data[0]
	want := EPSSScore{CVE: "CVE-2021-44228", EPSS: 0.94401, Percentile: 0.99997, Date: mustDate(t, "2026-10-25")}
	if got != want {
		t.Errorf("data[0] = %+v, want %+v", got, want)
	}
}

func TestParseEPSSResponseNumbers(t *testing.T) {
	t.Parallel()
	in := `{"status":"OK","status-code":200,"total":1,"data":[{"cve":"cve-2024-3400","epss":0.5,"percentile":1,"date":"2026-10-25"}]}`
	resp, err := ParseEPSSResponse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseEPSSResponse: %v", err)
	}
	if s := resp.Data[0]; s.CVE != "CVE-2024-3400" || s.EPSS != 0.5 || s.Percentile != 1 {
		t.Errorf("score = %+v", s)
	}
}

func TestParseEPSSResponseErrors(t *testing.T) {
	t.Parallel()
	row := func(fields string) string {
		return `{"status":"OK","status-code":200,"total":1,"data":[{` + fields + `}]}`
	}
	tests := []struct{ name, in, want string }{
		{"not json", "<html>", "invalid character"},
		{"api error", `{"status":"error","status-code":400,"message":"bad cve"}`, "API status"},
		{"status code", `{"status":"OK","status-code":500}`, "API status"},
		{"negative paging", `{"status":"OK","status-code":200,"offset":-1}`, "negative"},
		{"bad cve", row(`"cve":"CVE-24-1","epss":"0.1","percentile":"0.1","date":"2026-10-25"`), "invalid cve"},
		{"epss > 1", row(`"cve":"CVE-2024-3400","epss":"1.5","percentile":"0.1","date":"2026-10-25"`), "outside [0,1]"},
		{"negative pct", row(`"cve":"CVE-2024-3400","epss":"0.1","percentile":"-0.1","date":"2026-10-25"`), "outside [0,1]"},
		{"nan", row(`"cve":"CVE-2024-3400","epss":"NaN","percentile":"0.1","date":"2026-10-25"`), "outside [0,1]"},
		{"inf", row(`"cve":"CVE-2024-3400","epss":"0.1","percentile":"+Inf","date":"2026-10-25"`), "outside [0,1]"},
		{"not a number", row(`"cve":"CVE-2024-3400","epss":"high","percentile":"0.1","date":"2026-10-25"`), "invalid number"},
		{"bad string", row(`"cve":"CVE-2024-3400","epss":"\u12","percentile":"0.1","date":"2026-10-25"`), "invalid"},
		{"missing pct", row(`"cve":"CVE-2024-3400","epss":"0.1","percentile":null,"date":"2026-10-25"`), "missing"},
		{"bad date", row(`"cve":"CVE-2024-3400","epss":"0.1","percentile":"0.1","date":"25/10/2026"`), "date"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseEPSSResponse(strings.NewReader(tt.in))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParseEPSSCSVFixture(t *testing.T) {
	t.Parallel()
	plain := readFixture(t, "epss_scores.csv")
	for name, in := range map[string][]byte{"plain": plain, "gzip": gzipBytes(t, plain)} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ds, err := ParseEPSSCSV(bytes.NewReader(in))
			if err != nil {
				t.Fatalf("ParseEPSSCSV: %v", err)
			}
			if ds.ModelVersion != "v2025.03.14" || !ds.ScoreDate.Equal(mustDate(t, "2026-10-25")) || len(ds.Scores) != 20 {
				t.Fatalf("dataset = %s %v %d rows", ds.ModelVersion, ds.ScoreDate, len(ds.Scores))
			}
			i := slices.IndexFunc(ds.Scores, func(s EPSSScore) bool { return s.CVE == "CVE-2021-44228" })
			if i < 0 || ds.Scores[i].EPSS != 0.94401 || ds.Scores[i].Percentile != 0.9997 || !ds.Scores[i].Date.Equal(ds.ScoreDate) {
				t.Errorf("log4j row = %+v", ds.Scores[max(i, 0)])
			}
		})
	}
}

func TestParseEPSSCSVVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, model string
		date            time.Time
	}{
		{"no comment", "cve,epss,percentile\nCVE-2024-3400,0.9,0.99\n", "", time.Time{}},
		{"rfc3339 and order", "#score_date:2026-10-25T00:00:00Z,model_version:v4,extra\r\nCVE,EPSS,Percentile\r\nCVE-2024-3400,0.9,0.99\r\n", "v4", time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)},
		{"plain date", "#model_version:v4,score_date:2026-10-25\ncve,epss,percentile\nCVE-2024-3400,0.9,0.99", "v4", time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ds, err := ParseEPSSCSV(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("ParseEPSSCSV: %v", err)
			}
			if ds.ModelVersion != tt.model || !ds.ScoreDate.Equal(tt.date) || len(ds.Scores) != 1 {
				t.Errorf("dataset = %+v", ds)
			}
		})
	}
}

func TestParseEPSSCSVErrors(t *testing.T) {
	t.Parallel()
	const head = "#model_version:v4,score_date:2026-10-25T00:00:00+0000\ncve,epss,percentile\n"
	tests := []struct{ name, in, want string }{
		{"empty", "", "read header"},
		{"comment only", "#model_version:v4", "comment line"},
		{"bad score date", "#score_date:tomorrow\ncve,epss,percentile\nCVE-2024-3400,0.1,0.2\n", "score_date"},
		{"long model", "#model_version:" + strings.Repeat("v", 65) + "\ncve,epss,percentile\n", "too long"},
		{"bad header", "#x\ncve,score,percentile\nCVE-2024-3400,0.1,0.2\n", "unexpected header"},
		{"short header", "cve,epss\n", "wrong number of fields"},
		{"no rows", head, "no rows"},
		{"bad cve", head + "CVE-2024-34x,0.1,0.2\n", "invalid cve"},
		{"bad epss", head + "CVE-2024-3400,abc,0.2\n", "invalid number"},
		{"epss range", head + "CVE-2024-3400,1.01,0.2\n", "outside [0,1]"},
		{"pct range", head + "CVE-2024-3400,0.1,NaN\n", "outside [0,1]"},
		{"extra field", head + "CVE-2024-3400,0.1,0.2,x\n", "wrong number of fields"},
		{"bare quote", head + "CVE-2024-3400,0\"1,0.2\n", "bare \""},
		{"duplicate", head + "CVE-2024-3400,0.1,0.2\ncve-2024-3400,0.1,0.2\n", "duplicate"},
		{"corrupt gzip", "\x1f\x8b\x08garbage", "gzip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseEPSSCSV(strings.NewReader(tt.in))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParseEPSSCSVLimits(t *testing.T) {
	t.Parallel()
	// A highly compressible body (gzip bomb shape) must stop at the decompressed limit.
	var sb strings.Builder
	sb.WriteString("cve,epss,percentile\n")
	for i := range 1000 {
		fmt.Fprintf(&sb, "CVE-2024-%05d,0.1,0.2\n", i)
	}
	body := sb.String()
	_, err := parseEPSSCSV(bytes.NewReader(gzipBytes(t, []byte(body))), 1024)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("gzip: err = %v, want ErrTooLarge", err)
	}
	_, err = parseEPSSCSV(strings.NewReader(body), 1024)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("plain: err = %v, want ErrTooLarge", err)
	}
	// Exactly at the limit is fine.
	small := "cve,epss,percentile\nCVE-2024-3400,0.1,0.2\n"
	if _, err := parseEPSSCSV(strings.NewReader(small), int64(len(small))); err != nil {
		t.Fatalf("at limit: %v", err)
	}
}

// epssAPI is a fake EPSS API v1 serving scores from a map.
type epssAPI struct {
	scores map[string]EPSSScore
	mu     sync.Mutex
	calls  []string // raw queries
	failN  int32    // first failN calls return 429
	failed atomic.Int32
}

func (a *epssAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.calls = append(a.calls, r.URL.RawQuery)
	a.mu.Unlock()
	if a.failed.Add(1) <= a.failN {
		w.Header().Set("Retry-After", "0")
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	var data []map[string]string
	for id := range strings.SplitSeq(r.URL.Query().Get("cve"), ",") {
		if s, ok := a.scores[id]; ok {
			date := formatDate(s.Date)
			if d := r.URL.Query().Get("date"); d != "" {
				date = d
			}
			data = append(data, map[string]string{
				"cve": s.CVE, "epss": fmt.Sprintf("%.9f", s.EPSS), "percentile": fmt.Sprintf("%.9f", s.Percentile), "date": date,
			})
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "OK", "status-code": 200, "version": "1.0", "access": "public",
		"total": len(data), "offset": 0, "limit": 100, "data": data,
	})
}

func newEPSSAPI(t *testing.T) *epssAPI {
	t.Helper()
	ds, err := ParseEPSSCSV(bytes.NewReader(readFixture(t, "epss_scores.csv")))
	if err != nil {
		t.Fatal(err)
	}
	a := &epssAPI{scores: map[string]EPSSScore{}}
	for _, s := range ds.Scores {
		a.scores[s.CVE] = s
	}
	return a
}

func TestEPSSClientScoresBatching(t *testing.T) {
	t.Parallel()
	api := newEPSSAPI(t)
	api.failN = 1
	srv := httptest.NewServer(api)
	defer srv.Close()

	c := &EPSSClient{BaseURL: srv.URL + "/data/v1/epss", BatchSize: 2, ModelVersion: "v2025.03.14", HTTP: HTTPOptions{Retry: fastRetry}}
	cves := []string{"CVE-2021-44228", "cve-2023-44487", "CVE-2021-44228", "CVE-2099-0001", "CVE-2022-27225"}
	ds, err := c.Scores(context.Background(), cves, time.Time{})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	var got []string
	for _, s := range ds.Scores {
		got = append(got, s.CVE)
	}
	if want := []string{"CVE-2021-44228", "CVE-2022-27225", "CVE-2023-44487"}; !slices.Equal(got, want) {
		t.Errorf("CVEs = %v, want %v (sorted, deduplicated, unknown omitted)", got, want)
	}
	if ds.ModelVersion != "v2025.03.14" || !ds.ScoreDate.Equal(mustDate(t, "2026-10-25")) {
		t.Errorf("dataset meta = %q %v", ds.ModelVersion, ds.ScoreDate)
	}
	wantCalls := []string{
		"cve=CVE-2021-44228,CVE-2023-44487", // 429, retried
		"cve=CVE-2021-44228,CVE-2023-44487",
		"cve=CVE-2099-0001,CVE-2022-27225",
	}
	if !slices.Equal(api.calls, wantCalls) {
		t.Errorf("calls = %q, want %q", api.calls, wantCalls)
	}
}

func TestEPSSClientScoresDateAndQuery(t *testing.T) {
	t.Parallel()
	api := newEPSSAPI(t)
	srv := httptest.NewServer(api)
	defer srv.Close()

	c := &EPSSClient{BaseURL: srv.URL + "/epss?pretty=false"}
	ds, err := c.Scores(context.Background(), []string{"CVE-2021-44228"}, time.Date(2026, 3, 1, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if len(api.calls) != 1 || api.calls[0] != "pretty=false&cve=CVE-2021-44228&date=2026-03-01" {
		t.Errorf("calls = %q", api.calls)
	}
	if !ds.ScoreDate.Equal(mustDate(t, "2026-03-01")) {
		t.Errorf("ScoreDate = %v", ds.ScoreDate)
	}
}

func TestEPSSClientScoresNoInput(t *testing.T) {
	t.Parallel()
	c := &EPSSClient{BaseURL: "https://127.0.0.1:1/never"}
	ds, err := c.Scores(context.Background(), nil, time.Time{})
	if err != nil || len(ds.Scores) != 0 {
		t.Fatalf("Scores(nil) = %+v, %v", ds, err)
	}
}

func TestEPSSClientScoresErrors(t *testing.T) {
	t.Parallel()
	handler := func(body string, status int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}
	tests := []struct {
		name    string
		handler http.HandlerFunc
		cves    []string
		base    string
		want    string
	}{
		{"invalid cve", handler("", 200), []string{"GHSA-1234"}, "", "invalid CVE ID"},
		{"bad base url", handler("", 200), []string{"CVE-2024-3400"}, "http://192.0.2.1/epss", "loopback"},
		{"server error exhausts retries", handler("oops", 502), []string{"CVE-2024-3400"}, "", "502"},
		{"bad payload", handler(`{"status":"OK","status-code":200,"data":[{"cve":"x"}]}`, 200), []string{"CVE-2024-3400"}, "", "invalid cve"},
		{"incomplete", handler(`{"status":"OK","status-code":200,"total":5,"data":[]}`, 200), []string{"CVE-2024-3400"}, "", "incomplete"},
		{"unrequested", handler(`{"status":"OK","status-code":200,"total":1,"data":[{"cve":"CVE-2021-44228","epss":"0.1","percentile":"0.1","date":"2026-10-25"}]}`, 200), []string{"CVE-2024-3400"}, "", "unrequested"},
		{"duplicate row", handler(`{"status":"OK","status-code":200,"total":2,"data":[
			{"cve":"CVE-2024-3400","epss":"0.1","percentile":"0.1","date":"2026-10-25"},
			{"cve":"CVE-2024-3400","epss":"0.1","percentile":"0.1","date":"2026-10-25"}]}`, 200), []string{"CVE-2024-3400"}, "", "duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			base := tt.base
			if base == "" {
				base = srv.URL
			}
			c := &EPSSClient{BaseURL: base, HTTP: HTTPOptions{Retry: fastRetry}}
			_, err := c.Scores(context.Background(), tt.cves, time.Time{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestEPSSClientBulk(t *testing.T) {
	t.Parallel()
	gz := gzipBytes(t, readFixture(t, "epss_scores.csv"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/epss_scores-current.csv.gz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(gz)
	}))
	defer srv.Close()

	c := &EPSSClient{BulkURL: srv.URL + "/epss_scores-current.csv.gz"}
	ds, err := c.Bulk(context.Background())
	if err != nil {
		t.Fatalf("Bulk: %v", err)
	}
	if len(ds.Scores) != 20 || ds.ModelVersion != "v2025.03.14" {
		t.Errorf("dataset = %d rows, model %q", len(ds.Scores), ds.ModelVersion)
	}

	for name, c := range map[string]*EPSSClient{
		"too large": {BulkURL: srv.URL + "/epss_scores-current.csv.gz", BulkMaxBytes: 10},
		"not found": {BulkURL: srv.URL + "/missing.csv.gz"},
		"bad url":   {BulkURL: "file:///etc/passwd"},
	} {
		if _, err := c.Bulk(context.Background()); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
