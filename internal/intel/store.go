package intel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Feed names used in FeedInfo.Name.
const (
	FeedKEV  = "kev"
	FeedEPSS = "epss"
)

// FeedInfo records the provenance of one feed held by a Snapshot.
type FeedInfo struct {
	// Name is FeedKEV or FeedEPSS.
	Name string `json:"name"`
	// Source is where the data came from (URL or file name), free text.
	Source string `json:"source,omitempty"`
	// Version is the KEV catalogVersion or the EPSS model version.
	Version string `json:"version,omitempty"`
	// Date is the KEV dateReleased or the EPSS score date.
	Date time.Time `json:"date,omitzero"`
	// FetchedAt is when AegisFlow obtained the data.
	FetchedAt time.Time `json:"fetchedAt,omitzero"`
	// Entries is the number of records of this feed held by the snapshot.
	Entries int `json:"entries"`
}

// Intel is what a Snapshot knows about one CVE. The zero value means "nothing known".
type Intel struct {
	// CVE is the normalized identifier looked up (for LookupAll, the first valid one).
	CVE string `json:"cve,omitempty"`
	// EPSSKnown is false when no EPSS score is available; EPSS and Percentile are then 0.
	EPSSKnown    bool      `json:"epssKnown"`
	EPSS         float64   `json:"epss"`
	Percentile   float64   `json:"percentile"`
	ScoreDate    time.Time `json:"scoreDate,omitzero"`
	ModelVersion string    `json:"modelVersion,omitempty"`
	// KEVChecked is true when a KEV catalogue was consulted, so KEV=false means "not listed"
	// rather than "unknown".
	KEVChecked    bool      `json:"kevChecked"`
	KEV           bool      `json:"kev"`
	KEVDateAdded  time.Time `json:"kevDateAdded,omitzero"`
	KEVDueDate    time.Time `json:"kevDueDate,omitzero"`
	KEVRansomware bool      `json:"kevRansomware"`
}

// Store answers intelligence lookups by CVE. Snapshot and MemoryStore implement it.
type Store interface {
	// Lookup returns what is known about one CVE; invalid IDs yield no intelligence.
	Lookup(cve string) Intel
	// LookupAll merges the intelligence of several aliases of one vulnerability.
	LookupAll(cves []string) Intel
	// Feeds describes the feeds behind the answers.
	Feeds() []FeedInfo
}

type kevRecord struct {
	added, due time.Time
	ransomware bool
}

type epssRecord struct {
	epss, pct float64
	date      time.Time
}

// Snapshot is an immutable view of the KEV and EPSS feeds at a point in time. The zero value
// and NewSnapshot() are empty snapshots. WithKEV and WithEPSS return new snapshots and never
// modify the receiver, so a Snapshot is safe for concurrent use.
type Snapshot struct {
	kevFeed  *FeedInfo
	epssFeed *FeedInfo
	kev      map[string]kevRecord
	epss     map[string]epssRecord
}

var _ Store = (*Snapshot)(nil)

// NewSnapshot returns an empty snapshot.
func NewSnapshot() *Snapshot { return &Snapshot{} }

// WithKEV returns a copy of s whose KEV data is replaced by cat. An empty catalogue is rejected.
func (s *Snapshot) WithKEV(cat *KEVCatalog, source string, fetchedAt time.Time) (*Snapshot, error) {
	if cat == nil || len(cat.Vulnerabilities) == 0 {
		return nil, errors.New("snapshot: empty KEV catalogue")
	}
	m := make(map[string]kevRecord, len(cat.Vulnerabilities))
	for _, e := range cat.Vulnerabilities {
		id, ok := NormalizeCVE(e.CVEID)
		if !ok {
			return nil, fmt.Errorf("snapshot: invalid KEV cveID %q", truncate(e.CVEID, 40))
		}
		if _, dup := m[id]; dup {
			return nil, fmt.Errorf("snapshot: duplicate KEV entry %s", id)
		}
		if err := errors.Join(checkTime("dateAdded", e.DateAdded), checkTime("dueDate", e.DueDate)); err != nil {
			return nil, fmt.Errorf("snapshot: %s: %w", id, err)
		}
		m[id] = kevRecord{added: day(e.DateAdded), due: day(e.DueDate), ransomware: e.RansomwareKnown()}
	}
	if err := errors.Join(checkTime("dateReleased", cat.DateReleased), checkTime("fetchedAt", fetchedAt)); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	out := s.clone()
	out.kev = m
	out.kevFeed = &FeedInfo{
		Name: FeedKEV, Source: source, Version: cat.CatalogVersion,
		Date: cat.DateReleased.UTC(), FetchedAt: fetchedAt.UTC(), Entries: len(m),
	}
	return out, nil
}

// WithEPSS returns a copy of s whose EPSS data is replaced by ds. An empty dataset is allowed
// (an API query may legitimately match nothing); invalid or duplicate rows are rejected.
func (s *Snapshot) WithEPSS(ds *EPSSDataset, source string, fetchedAt time.Time) (*Snapshot, error) {
	if ds == nil {
		return nil, errors.New("snapshot: nil EPSS dataset")
	}
	m := make(map[string]epssRecord, len(ds.Scores))
	for _, sc := range ds.Scores {
		id, ok := NormalizeCVE(sc.CVE)
		if !ok {
			return nil, fmt.Errorf("snapshot: invalid EPSS cve %q", truncate(sc.CVE, 40))
		}
		if _, err := probability("epss", sc.EPSS); err != nil {
			return nil, fmt.Errorf("snapshot: %s: %w", id, err)
		}
		if _, err := probability("percentile", sc.Percentile); err != nil {
			return nil, fmt.Errorf("snapshot: %s: %w", id, err)
		}
		if _, dup := m[id]; dup {
			return nil, fmt.Errorf("snapshot: duplicate EPSS score %s", id)
		}
		if err := checkTime("date", sc.Date); err != nil {
			return nil, fmt.Errorf("snapshot: %s: %w", id, err)
		}
		m[id] = epssRecord{epss: sc.EPSS, pct: sc.Percentile, date: day(sc.Date)}
	}
	if err := errors.Join(checkTime("scoreDate", ds.ScoreDate), checkTime("fetchedAt", fetchedAt)); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	out := s.clone()
	out.epss = m
	out.epssFeed = &FeedInfo{
		Name: FeedEPSS, Source: source, Version: ds.ModelVersion,
		Date: ds.ScoreDate.UTC(), FetchedAt: fetchedAt.UTC(), Entries: len(m),
	}
	return out, nil
}

// day truncates t to midnight UTC of its UTC calendar date; the zero time stays zero.
func day(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// clone copies the feed metadata; the record maps are shared because they are never mutated.
func (s *Snapshot) clone() *Snapshot {
	out := &Snapshot{kev: s.kev, epss: s.epss}
	if s.kevFeed != nil {
		f := *s.kevFeed
		out.kevFeed = &f
	}
	if s.epssFeed != nil {
		f := *s.epssFeed
		out.epssFeed = &f
	}
	return out
}

// Lookup implements Store.
func (s *Snapshot) Lookup(cve string) Intel {
	in := Intel{KEVChecked: s.kevFeed != nil}
	id, ok := NormalizeCVE(cve)
	if !ok {
		return in
	}
	in.CVE = id
	if r, ok := s.kev[id]; ok {
		in.KEV, in.KEVDateAdded, in.KEVDueDate, in.KEVRansomware = true, r.added, r.due, r.ransomware
	}
	if r, ok := s.epss[id]; ok {
		in.EPSSKnown, in.EPSS, in.Percentile, in.ScoreDate = true, r.epss, r.pct, r.date
		in.ModelVersion = s.epssFeed.Version
	}
	return in
}

// LookupAll implements Store. A vulnerability with several CVE aliases is in KEV if any alias
// is (earliest dateAdded and due date, ransomware if any); its EPSS is the highest alias score.
func (s *Snapshot) LookupAll(cves []string) Intel {
	out := Intel{KEVChecked: s.kevFeed != nil}
	for _, c := range cves {
		in := s.Lookup(c)
		if in.CVE == "" {
			continue
		}
		if out.CVE == "" {
			out.CVE = in.CVE
		}
		mergeIntel(&out, in)
	}
	return out
}

func mergeIntel(out *Intel, in Intel) {
	if in.KEV {
		if !out.KEV || in.KEVDateAdded.Before(out.KEVDateAdded) {
			out.KEVDateAdded = in.KEVDateAdded
		}
		if !in.KEVDueDate.IsZero() && (out.KEVDueDate.IsZero() || in.KEVDueDate.Before(out.KEVDueDate)) {
			out.KEVDueDate = in.KEVDueDate
		}
		out.KEV = true
		out.KEVRansomware = out.KEVRansomware || in.KEVRansomware
	}
	if in.EPSSKnown && (!out.EPSSKnown || in.EPSS > out.EPSS || (in.EPSS == out.EPSS && in.Percentile > out.Percentile)) {
		out.EPSSKnown, out.EPSS, out.Percentile = true, in.EPSS, in.Percentile
		out.ScoreDate, out.ModelVersion = in.ScoreDate, in.ModelVersion
	}
}

// Feeds implements Store: the KEV then the EPSS feed, when present.
func (s *Snapshot) Feeds() []FeedInfo {
	var out []FeedInfo
	for _, f := range []*FeedInfo{s.kevFeed, s.epssFeed} {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// Subset returns a snapshot holding only the records of the given CVEs (invalid IDs are
// ignored), keeping the feed provenance. Use it to freeze the intelligence behind an
// experiment without storing the whole EPSS file.
func (s *Snapshot) Subset(cves []string) *Snapshot {
	out := s.clone()
	out.kev, out.epss = nil, nil
	if s.kevFeed != nil {
		out.kev = map[string]kevRecord{}
	}
	if s.epssFeed != nil {
		out.epss = map[string]epssRecord{}
	}
	for _, c := range cves {
		id, ok := NormalizeCVE(c)
		if !ok {
			continue
		}
		if r, ok := s.kev[id]; ok {
			out.kev[id] = r
		}
		if r, ok := s.epss[id]; ok {
			out.epss[id] = r
		}
	}
	if out.kevFeed != nil {
		out.kevFeed.Entries = len(out.kev)
	}
	if out.epssFeed != nil {
		out.epssFeed.Entries = len(out.epss)
	}
	return out
}

// Snapshot file format and limits.
const (
	// SnapshotFormatVersion is the version written by WriteJSON.
	SnapshotFormatVersion = 1
	// MaxSnapshotBytes bounds a snapshot file read by ReadSnapshot (a full 2026 EPSS snapshot
	// is ~30 MB; experiment subsets are a few kB).
	MaxSnapshotBytes int64 = 256 << 20
)

type snapshotFile struct {
	FormatVersion int              `json:"formatVersion"`
	Feeds         []FeedInfo       `json:"feeds"`
	Records       []snapshotRecord `json:"records"`
}

type snapshotRecord struct {
	CVE           string   `json:"cve"`
	EPSS          *float64 `json:"epss,omitempty"`
	Percentile    *float64 `json:"percentile,omitempty"`
	ScoreDate     string   `json:"scoreDate,omitempty"`
	KEV           bool     `json:"kev,omitempty"`
	KEVDateAdded  string   `json:"kevDateAdded,omitempty"`
	KEVDueDate    string   `json:"kevDueDate,omitempty"`
	KEVRansomware bool     `json:"kevRansomware,omitempty"`
}

// WriteJSON writes the snapshot as deterministic JSON (records sorted by CVE), the format read
// by ReadSnapshot. Experiment results reference such a file to freeze their intelligence.
func (s *Snapshot) WriteJSON(w io.Writer) error {
	ids := make(map[string]struct{}, len(s.kev)+len(s.epss))
	for id := range s.kev {
		ids[id] = struct{}{}
	}
	for id := range s.epss {
		ids[id] = struct{}{}
	}
	f := snapshotFile{FormatVersion: SnapshotFormatVersion, Feeds: s.Feeds(), Records: make([]snapshotRecord, 0, len(ids))}
	if f.Feeds == nil {
		f.Feeds = []FeedInfo{}
	}
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		rec := snapshotRecord{CVE: id}
		if r, ok := s.kev[id]; ok {
			rec.KEV, rec.KEVDateAdded, rec.KEVDueDate, rec.KEVRansomware = true, formatDate(r.added), formatDate(r.due), r.ransomware
		}
		if r, ok := s.epss[id]; ok {
			e, p := r.epss, r.pct
			rec.EPSS, rec.Percentile, rec.ScoreDate = &e, &p, formatDate(r.date)
		}
		f.Records = append(f.Records, rec)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	return nil
}

// ReadSnapshot reads a file written by WriteJSON, validating it as untrusted input: strict
// JSON (unknown fields and trailing data rejected, as this is AegisFlow's own format), format
// version, feed names, CVE IDs, probability ranges, dates, duplicates, and that each feed's
// Entries matches the records present.
func ReadSnapshot(r io.Reader) (*Snapshot, error) {
	b, err := readLimited(r, MaxSnapshotBytes)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	var f snapshotFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("read snapshot: trailing data after JSON document")
	}
	s, err := f.toSnapshot()
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	return s, nil
}

func (f *snapshotFile) toSnapshot() (*Snapshot, error) {
	if f.FormatVersion != SnapshotFormatVersion {
		return nil, fmt.Errorf("unsupported formatVersion %d", f.FormatVersion)
	}
	if len(f.Records) > MaxEPSSRows+MaxKEVEntries {
		return nil, fmt.Errorf("%d records exceed the limit", len(f.Records))
	}
	s := &Snapshot{}
	for _, fi := range f.Feeds {
		if err := errors.Join(checkTime("date", fi.Date), checkTime("fetchedAt", fi.FetchedAt)); err != nil {
			return nil, fmt.Errorf("feed %q: %w", truncate(fi.Name, 32), err)
		}
		fi.Date, fi.FetchedAt = fi.Date.UTC(), fi.FetchedAt.UTC()
		switch {
		case fi.Name == FeedKEV && s.kevFeed == nil:
			s.kevFeed, s.kev = &fi, map[string]kevRecord{}
		case fi.Name == FeedEPSS && s.epssFeed == nil:
			s.epssFeed, s.epss = &fi, map[string]epssRecord{}
		default:
			return nil, fmt.Errorf("unknown or duplicate feed %q", truncate(fi.Name, 32))
		}
	}
	seen := make(map[string]struct{}, len(f.Records))
	for i, rec := range f.Records {
		id, ok := NormalizeCVE(rec.CVE)
		if !ok {
			return nil, fmt.Errorf("records[%d]: invalid cve %q", i, truncate(rec.CVE, 40))
		}
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("records[%d]: duplicate %s", i, id)
		}
		seen[id] = struct{}{}
		if err := s.addRecord(id, rec); err != nil {
			return nil, fmt.Errorf("records[%d] %s: %w", i, id, err)
		}
	}
	if s.kevFeed != nil && s.kevFeed.Entries != len(s.kev) {
		return nil, fmt.Errorf("kev feed declares %d entries, found %d", s.kevFeed.Entries, len(s.kev))
	}
	if s.epssFeed != nil && s.epssFeed.Entries != len(s.epss) {
		return nil, fmt.Errorf("epss feed declares %d entries, found %d", s.epssFeed.Entries, len(s.epss))
	}
	return s, nil
}

func (s *Snapshot) addRecord(id string, rec snapshotRecord) error {
	hasEPSS := rec.EPSS != nil || rec.Percentile != nil || rec.ScoreDate != ""
	hasKEV := rec.KEV || rec.KEVDateAdded != "" || rec.KEVDueDate != "" || rec.KEVRansomware
	if !hasEPSS && !hasKEV {
		return errors.New("record carries no data")
	}
	if hasKEV {
		if s.kevFeed == nil || !rec.KEV {
			return errors.New("KEV data without a kev feed or kev=true")
		}
		added, err := parseDate(rec.KEVDateAdded)
		if err != nil {
			return fmt.Errorf("kevDateAdded: %w", err)
		}
		var due time.Time
		if rec.KEVDueDate != "" {
			if due, err = parseDate(rec.KEVDueDate); err != nil {
				return fmt.Errorf("kevDueDate: %w", err)
			}
		}
		s.kev[id] = kevRecord{added: added, due: due, ransomware: rec.KEVRansomware}
	}
	if hasEPSS {
		if s.epssFeed == nil || rec.EPSS == nil || rec.Percentile == nil {
			return errors.New("EPSS data without an epss feed, epss or percentile")
		}
		e, err := probability("epss", *rec.EPSS)
		if err != nil {
			return err
		}
		p, err := probability("percentile", *rec.Percentile)
		if err != nil {
			return err
		}
		var d time.Time
		if strings.TrimSpace(rec.ScoreDate) != "" {
			if d, err = parseDate(rec.ScoreDate); err != nil {
				return fmt.Errorf("scoreDate: %w", err)
			}
		}
		s.epss[id] = epssRecord{epss: e, pct: p, date: d}
	}
	return nil
}

// MemoryStore holds the current Snapshot and swaps it atomically when feeds are refreshed.
// Readers never block; writers are serialised. The zero value is an empty store.
type MemoryStore struct {
	mu  sync.Mutex // serialises read-modify-write updates
	cur atomic.Pointer[Snapshot]
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns a store holding s (nil means an empty snapshot).
func NewMemoryStore(s *Snapshot) *MemoryStore {
	m := &MemoryStore{}
	if s != nil {
		m.cur.Store(s)
	}
	return m
}

// Snapshot returns the current snapshot (never nil).
func (m *MemoryStore) Snapshot() *Snapshot {
	if s := m.cur.Load(); s != nil {
		return s
	}
	return &Snapshot{}
}

// Replace installs s as the current snapshot (nil installs an empty one).
func (m *MemoryStore) Replace(s *Snapshot) {
	if s == nil {
		s = &Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur.Store(s)
}

// UpdateKEV replaces the KEV data of the current snapshot. On error the store is unchanged.
func (m *MemoryStore) UpdateKEV(cat *KEVCatalog, source string, fetchedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := m.Snapshot().WithKEV(cat, source, fetchedAt)
	if err != nil {
		return err
	}
	m.cur.Store(next)
	return nil
}

// UpdateEPSS replaces the EPSS data of the current snapshot. On error the store is unchanged.
func (m *MemoryStore) UpdateEPSS(ds *EPSSDataset, source string, fetchedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := m.Snapshot().WithEPSS(ds, source, fetchedAt)
	if err != nil {
		return err
	}
	m.cur.Store(next)
	return nil
}

// Lookup implements Store.
func (m *MemoryStore) Lookup(cve string) Intel { return m.Snapshot().Lookup(cve) }

// LookupAll implements Store.
func (m *MemoryStore) LookupAll(cves []string) Intel { return m.Snapshot().LookupAll(cves) }

// Feeds implements Store.
func (m *MemoryStore) Feeds() []FeedInfo { return m.Snapshot().Feeds() }
