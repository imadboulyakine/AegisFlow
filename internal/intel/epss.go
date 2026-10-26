package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// EPSS endpoints and limits.
const (
	// DefaultEPSSAPIURL is FIRST's EPSS API v1 endpoint.
	DefaultEPSSAPIURL = "https://api.first.org/data/v1/epss"
	// DefaultEPSSBulkURL is the daily bulk CSV linked from FIRST's EPSS data page (hosted by
	// Empirical Security since 2025). Unverified from the development container, where it is
	// blocked; override it if FIRST moves the file.
	DefaultEPSSBulkURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	// MaxEPSSBatch is the most CVEs requested per API call (the API's default page size).
	MaxEPSSBatch = 100
	// DefaultEPSSResponseMaxBytes bounds one API response (100 rows are ~10 kB).
	DefaultEPSSResponseMaxBytes int64 = 4 << 20
	// DefaultEPSSBulkMaxBytes bounds the downloaded bulk file (compressed size, ~3 MB in 2026).
	DefaultEPSSBulkMaxBytes int64 = 64 << 20
	// MaxEPSSCSVBytes bounds the decompressed bulk CSV (~12 MB for ~300k CVEs in 2026).
	MaxEPSSCSVBytes int64 = 256 << 20
	// MaxEPSSRows bounds the rows of a bulk CSV or snapshot.
	MaxEPSSRows = 2_000_000
)

// EPSSScore is the EPSS estimate for one CVE.
type EPSSScore struct {
	// CVE is the normalized CVE identifier.
	CVE string `json:"cve"`
	// EPSS is the probability (0..1) of exploitation activity in the next 30 days.
	EPSS float64 `json:"epss"`
	// Percentile is the score's rank among all scored CVEs (0..1).
	Percentile float64 `json:"percentile"`
	// Date is the score date (midnight UTC).
	Date time.Time `json:"date"`
}

// EPSSDataset is a set of EPSS scores with the model metadata that produced them.
type EPSSDataset struct {
	// ModelVersion is the EPSS model, e.g. "v2025.03.14" (EPSS v4). The bulk CSV states it; the
	// v1 API does not, so API datasets carry EPSSClient.ModelVersion (possibly "").
	ModelVersion string `json:"modelVersion,omitempty"`
	// ScoreDate is the bulk file's score date, or the latest row date of an API dataset.
	ScoreDate time.Time   `json:"scoreDate,omitzero"`
	Scores    []EPSSScore `json:"scores"`
}

// EPSSResponse is one parsed EPSS API v1 response page.
type EPSSResponse struct {
	Status     string      `json:"status"`
	StatusCode int         `json:"statusCode"`
	Version    string      `json:"version"`
	Total      int         `json:"total"`
	Offset     int         `json:"offset"`
	Limit      int         `json:"limit"`
	Data       []EPSSScore `json:"data"`
}

type epssResponseWire struct {
	Status     string         `json:"status"`
	StatusCode int            `json:"status-code"`
	Version    string         `json:"version"`
	Total      int            `json:"total"`
	Offset     int            `json:"offset"`
	Limit      int            `json:"limit"`
	Data       []epssScoreRaw `json:"data"`
}

type epssScoreRaw struct {
	CVE        string    `json:"cve"`
	EPSS       flexFloat `json:"epss"`
	Percentile flexFloat `json:"percentile"`
	Date       string    `json:"date"`
}

// flexFloat accepts a JSON number or a JSON string holding a number: the API documents strings
// ("0.944010000") but tolerating numbers costs nothing.
type flexFloat struct {
	v   float64
	set bool
}

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := string(bytes.TrimSpace(b))
	if s == "null" {
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return fmt.Errorf("decode number string: %w", err)
		}
		s = strings.TrimSpace(str)
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("invalid number %q", truncate(s, 32))
	}
	f.v, f.set = v, true
	return nil
}

// probability validates an EPSS probability or percentile.
func probability(name string, v float64) (float64, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
		return 0, fmt.Errorf("%s %v outside [0,1]", name, v)
	}
	return v, nil
}

// ParseEPSSResponse parses an EPSS API v1 JSON response of at most DefaultEPSSResponseMaxBytes.
// It fails unless status is "OK" with status-code 200, and validates every row (CVE ID,
// probabilities in [0,1], date). Unknown fields are ignored.
func ParseEPSSResponse(r io.Reader) (*EPSSResponse, error) {
	b, err := readLimited(r, DefaultEPSSResponseMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("parse epss response: %w", err)
	}
	return parseEPSSResponse(b)
}

func parseEPSSResponse(b []byte) (*EPSSResponse, error) {
	var w epssResponseWire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("parse epss response: %w", err)
	}
	if !strings.EqualFold(w.Status, "OK") || w.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("parse epss response: API status %q (code %d)", truncate(w.Status, 64), w.StatusCode)
	}
	if w.Total < 0 || w.Offset < 0 || w.Limit < 0 {
		return nil, errors.New("parse epss response: negative paging field")
	}
	if len(w.Data) > MaxEPSSRows {
		return nil, fmt.Errorf("parse epss response: %d rows exceed the limit of %d", len(w.Data), MaxEPSSRows)
	}
	resp := &EPSSResponse{
		Status: w.Status, StatusCode: w.StatusCode, Version: w.Version,
		Total: w.Total, Offset: w.Offset, Limit: w.Limit,
		Data: make([]EPSSScore, 0, len(w.Data)),
	}
	for i, row := range w.Data {
		s, err := row.toScore()
		if err != nil {
			return nil, fmt.Errorf("parse epss response: data[%d]: %w", i, err)
		}
		resp.Data = append(resp.Data, s)
	}
	return resp, nil
}

func (r epssScoreRaw) toScore() (EPSSScore, error) {
	id, ok := NormalizeCVE(r.CVE)
	if !ok {
		return EPSSScore{}, fmt.Errorf("invalid cve %q", truncate(r.CVE, 40))
	}
	if !r.EPSS.set || !r.Percentile.set {
		return EPSSScore{}, fmt.Errorf("%s: missing epss or percentile", id)
	}
	e, err := probability("epss", r.EPSS.v)
	if err != nil {
		return EPSSScore{}, fmt.Errorf("%s: %w", id, err)
	}
	p, err := probability("percentile", r.Percentile.v)
	if err != nil {
		return EPSSScore{}, fmt.Errorf("%s: %w", id, err)
	}
	d, err := parseDate(r.Date)
	if err != nil {
		return EPSSScore{}, fmt.Errorf("%s: date: %w", id, err)
	}
	return EPSSScore{CVE: id, EPSS: e, Percentile: p, Date: d}, nil
}

// ParseEPSSCSV parses FIRST's daily bulk EPSS file, gzip-compressed or plain (detected from the
// gzip magic bytes). The expected layout is an optional comment line
// "#model_version:v2025.03.14,score_date:2025-03-17T00:00:00+0000", a "cve,epss,percentile"
// header, then one row per CVE. The decompressed size is bounded by MaxEPSSCSVBytes and the
// row count by MaxEPSSRows; an empty file, a malformed row or a duplicate CVE is an error.
func ParseEPSSCSV(r io.Reader) (*EPSSDataset, error) {
	ds, err := parseEPSSCSV(r, MaxEPSSCSVBytes)
	if err != nil {
		return nil, fmt.Errorf("parse epss csv: %w", err)
	}
	return ds, nil
}

func parseEPSSCSV(r io.Reader, maxBytes int64) (*EPSSDataset, error) {
	br := bufio.NewReader(r)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer func() { _ = zr.Close() }()
		br = bufio.NewReader(zr)
	}
	br = bufio.NewReader(&capReader{r: br, n: maxBytes})

	ds := &EPSSDataset{}
	if first, err := br.Peek(1); err == nil && first[0] == '#' {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read comment line: %w", err)
		}
		if err := ds.parseComment(line); err != nil {
			return nil, err
		}
	}

	cr := csv.NewReader(br)
	cr.FieldsPerRecord = 3
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	for i, want := range []string{"cve", "epss", "percentile"} {
		if !strings.EqualFold(strings.TrimSpace(header[i]), want) {
			return nil, fmt.Errorf("unexpected header %q, want cve,epss,percentile", truncate(strings.Join(header, ","), 80))
		}
	}
	seen := make(map[string]struct{})
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read row: %w", err)
		}
		if len(ds.Scores) >= MaxEPSSRows {
			return nil, fmt.Errorf("more than %d rows", MaxEPSSRows)
		}
		line, _ := cr.FieldPos(0)
		s, err := csvScore(rec, ds.ScoreDate)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if _, dup := seen[s.CVE]; dup {
			return nil, fmt.Errorf("line %d: duplicate %s", line, s.CVE)
		}
		seen[s.CVE] = struct{}{}
		ds.Scores = append(ds.Scores, s)
	}
	if len(ds.Scores) == 0 {
		return nil, errors.New("no rows")
	}
	return ds, nil
}

func csvScore(rec []string, date time.Time) (EPSSScore, error) {
	id, ok := NormalizeCVE(rec[0])
	if !ok {
		return EPSSScore{}, fmt.Errorf("invalid cve %q", truncate(rec[0], 40))
	}
	e, err := parseProb("epss", rec[1])
	if err != nil {
		return EPSSScore{}, fmt.Errorf("%s: %w", id, err)
	}
	p, err := parseProb("percentile", rec[2])
	if err != nil {
		return EPSSScore{}, fmt.Errorf("%s: %w", id, err)
	}
	return EPSSScore{CVE: id, EPSS: e, Percentile: p, Date: date}, nil
}

func parseProb(name, s string) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid number %q", name, truncate(s, 32))
	}
	return probability(name, v)
}

// parseComment reads "#model_version:<v>,score_date:<ts>" (keys in any order, others ignored).
func (ds *EPSSDataset) parseComment(line string) error {
	line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
	for field := range strings.SplitSeq(line, ",") {
		key, val, ok := strings.Cut(field, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "model_version":
			if len(val) > 64 {
				return errors.New("model_version too long")
			}
			ds.ModelVersion = val
		case "score_date":
			t, err := parseScoreDate(val)
			if err != nil {
				return fmt.Errorf("score_date: %w", err)
			}
			ds.ScoreDate = t
		}
	}
	return nil
}

// parseScoreDate accepts the bulk file's "2025-03-17T00:00:00+0000", RFC 3339 and plain dates.
func parseScoreDate(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04:05-0700", time.RFC3339, dateLayout} {
		if t, err := time.Parse(layout, s); err == nil {
			if err := checkTime("score_date", t); err != nil {
				return time.Time{}, err
			}
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised date %q", truncate(s, 40))
}

// capReader fails with ErrTooLarge once more than n bytes have been read.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n < 0 {
		return 0, fmt.Errorf("decompressed data %w", ErrTooLarge)
	}
	if int64(len(p)) > c.n+1 {
		p = p[:c.n+1]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	if c.n < 0 {
		return n, fmt.Errorf("decompressed data %w", ErrTooLarge)
	}
	return n, err // unwrapped on purpose: the io.Reader contract requires a bare io.EOF
}

// EPSSClient queries the EPSS API and downloads the bulk file.
type EPSSClient struct {
	// BaseURL of the API; empty uses DefaultEPSSAPIURL.
	BaseURL string
	// BulkURL of the daily CSV; empty uses DefaultEPSSBulkURL.
	BulkURL string
	// BatchSize is the number of CVEs per API request (1..MaxEPSSBatch; 0 means MaxEPSSBatch).
	BatchSize int
	// MaxBytes bounds one API response; 0 uses DefaultEPSSResponseMaxBytes.
	MaxBytes int64
	// BulkMaxBytes bounds the downloaded bulk file; 0 uses DefaultEPSSBulkMaxBytes.
	BulkMaxBytes int64
	// ModelVersion labels API results, which do not state the model (e.g. "v2025.03.14").
	ModelVersion string
	HTTP         HTTPOptions
}

// ErrIncompleteResponse is returned when the API reports more matches than it returned.
var ErrIncompleteResponse = errors.New("incomplete EPSS response")

// Scores fetches scores for cves (normalized and deduplicated; any invalid ID is an error) in
// sequential batches. A zero date asks for the latest scores; otherwise the API's historical
// scores for that day are requested, which keeps experiment inputs reproducible. CVEs without
// a score are simply absent. The result is sorted by CVE.
func (c *EPSSClient) Scores(ctx context.Context, cves []string, date time.Time) (*EPSSDataset, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultEPSSAPIURL
	}
	if _, err := validateFeedURL(base); err != nil {
		return nil, fmt.Errorf("fetch epss: %w", err)
	}
	ids, err := normalizeCVEList(cves)
	if err != nil {
		return nil, fmt.Errorf("fetch epss: %w", err)
	}
	batch := c.BatchSize
	if batch <= 0 || batch > MaxEPSSBatch {
		batch = MaxEPSSBatch
	}
	limit := c.MaxBytes
	if limit <= 0 {
		limit = DefaultEPSSResponseMaxBytes
	}
	ds := &EPSSDataset{ModelVersion: c.ModelVersion, Scores: make([]EPSSScore, 0, len(ids))}
	for chunk := range slices.Chunk(ids, batch) {
		scores, err := c.fetchBatch(ctx, base, chunk, date, limit)
		if err != nil {
			return nil, fmt.Errorf("fetch epss: %w", err)
		}
		ds.Scores = append(ds.Scores, scores...)
	}
	slices.SortFunc(ds.Scores, func(a, b EPSSScore) int { return strings.Compare(a.CVE, b.CVE) })
	for _, s := range ds.Scores {
		if s.Date.After(ds.ScoreDate) {
			ds.ScoreDate = s.Date
		}
	}
	return ds, nil
}

func (c *EPSSClient) fetchBatch(ctx context.Context, base string, chunk []string, date time.Time, limit int64) ([]EPSSScore, error) {
	// CVE IDs are validated ([A-Z0-9-] only), so the comma list needs no escaping.
	q := "cve=" + strings.Join(chunk, ",")
	if !date.IsZero() {
		q += "&date=" + formatDate(date)
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	body, err := c.HTTP.get(ctx, base+sep+q, limit)
	if err != nil {
		return nil, err
	}
	resp, err := parseEPSSResponse(body)
	if err != nil {
		return nil, err
	}
	if resp.Total > len(resp.Data) {
		return nil, fmt.Errorf("%w: %d of %d rows", ErrIncompleteResponse, len(resp.Data), resp.Total)
	}
	want := make(map[string]bool, len(chunk))
	for _, id := range chunk {
		want[id] = true
	}
	for _, s := range resp.Data {
		if !want[s.CVE] {
			return nil, fmt.Errorf("response contains unrequested or duplicate %s", s.CVE)
		}
		want[s.CVE] = false
	}
	return resp.Data, nil
}

// Bulk downloads and parses the daily bulk CSV.
func (c *EPSSClient) Bulk(ctx context.Context) (*EPSSDataset, error) {
	raw := c.BulkURL
	if raw == "" {
		raw = DefaultEPSSBulkURL
	}
	if _, err := validateFeedURL(raw); err != nil {
		return nil, fmt.Errorf("fetch epss bulk: %w", err)
	}
	limit := c.BulkMaxBytes
	if limit <= 0 {
		limit = DefaultEPSSBulkMaxBytes
	}
	body, err := c.HTTP.get(ctx, raw, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch epss bulk: %w", err)
	}
	return ParseEPSSCSV(bytes.NewReader(body))
}

// normalizeCVEList validates, normalizes and deduplicates ids, keeping first-seen order.
func normalizeCVEList(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, raw := range ids {
		id, ok := NormalizeCVE(raw)
		if !ok {
			return nil, fmt.Errorf("invalid CVE ID %q", truncate(raw, 40))
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}
