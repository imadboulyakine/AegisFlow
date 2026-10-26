package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// KEV feed locations and limits.
const (
	// DefaultKEVURL is CISA's official JSON feed.
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// KEVMirrorURL is CISA's official GitHub mirror of the same catalogue (cisagov/kev-data).
	KEVMirrorURL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	// DefaultKEVMaxBytes bounds the catalogue size (the 2026-10-23 catalogue is ~1.8 MB).
	DefaultKEVMaxBytes int64 = 32 << 20
	// MaxKEVEntries bounds the number of catalogue entries (1,756 on 2026-10-23).
	MaxKEVEntries = 200_000
)

// KEVCatalog is a parsed CISA Known Exploited Vulnerabilities catalogue.
type KEVCatalog struct {
	Title string `json:"title"`
	// CatalogVersion is CISA's version string, e.g. "2026.10.23".
	CatalogVersion string    `json:"catalogVersion"`
	DateReleased   time.Time `json:"dateReleased"`
	// Count equals len(Vulnerabilities); ParseKEV rejects catalogues where they differ.
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// KEVEntry is one catalogue entry. Dates are midnight UTC.
type KEVEntry struct {
	// CVEID is the normalized CVE identifier.
	CVEID             string    `json:"cveID"`
	VendorProject     string    `json:"vendorProject"`
	Product           string    `json:"product"`
	VulnerabilityName string    `json:"vulnerabilityName"`
	DateAdded         time.Time `json:"dateAdded"`
	ShortDescription  string    `json:"shortDescription"`
	RequiredAction    string    `json:"requiredAction"`
	// DueDate is the remediation deadline for US federal agencies; zero when absent.
	DueDate time.Time `json:"dueDate,omitzero"`
	// KnownRansomwareCampaignUse is "Known" or "Unknown" as published by CISA.
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes,omitempty"`
	CWEs                       []string `json:"cwes,omitempty"`
}

// RansomwareKnown reports whether CISA lists known use in ransomware campaigns.
func (e KEVEntry) RansomwareKnown() bool {
	return strings.EqualFold(strings.TrimSpace(e.KnownRansomwareCampaignUse), "Known")
}

// kevWire mirrors the published JSON. Unknown fields are ignored on purpose: CISA adds fields
// over time (e.g. "forensicTriage" in 2026) and additive changes must not break ingestion.
type kevWire struct {
	Title           *string        `json:"title"`
	CatalogVersion  string         `json:"catalogVersion"`
	DateReleased    string         `json:"dateReleased"`
	Count           *int           `json:"count"`
	Vulnerabilities []kevEntryWire `json:"vulnerabilities"`
}

type kevEntryWire struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// ParseKEV parses a KEV catalogue of at most DefaultKEVMaxBytes.
//
// It is strict about what the risk engine relies on and lenient about the rest: every entry
// needs a valid CVE ID and dateAdded, CVE IDs must be unique, count must match the number of
// entries, and an empty catalogue is rejected (it would silently erase exploitation signal).
// Unknown fields are ignored for forward compatibility.
func ParseKEV(r io.Reader) (*KEVCatalog, error) {
	b, err := readLimited(r, DefaultKEVMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("parse kev: %w", err)
	}
	return parseKEV(b)
}

func parseKEV(b []byte) (*KEVCatalog, error) {
	var w kevWire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("parse kev: %w", err)
	}
	if strings.TrimSpace(w.CatalogVersion) == "" {
		return nil, errors.New("parse kev: missing catalogVersion")
	}
	released, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(w.DateReleased))
	if err == nil {
		err = checkTime("dateReleased", released)
	}
	if err != nil {
		return nil, fmt.Errorf("parse kev: dateReleased: %w", err)
	}
	if w.Count == nil {
		return nil, errors.New("parse kev: missing count")
	}
	n := len(w.Vulnerabilities)
	switch {
	case n == 0:
		return nil, errors.New("parse kev: catalogue has no entries")
	case n > MaxKEVEntries:
		return nil, fmt.Errorf("parse kev: %d entries exceed the limit of %d", n, MaxKEVEntries)
	case *w.Count != n:
		return nil, fmt.Errorf("parse kev: count %d does not match %d entries", *w.Count, n)
	}
	cat := &KEVCatalog{
		CatalogVersion:  strings.TrimSpace(w.CatalogVersion),
		DateReleased:    released.UTC(),
		Count:           n,
		Vulnerabilities: make([]KEVEntry, 0, n),
	}
	if w.Title != nil {
		cat.Title = *w.Title
	}
	seen := make(map[string]struct{}, n)
	for i, e := range w.Vulnerabilities {
		entry, err := e.toEntry()
		if err != nil {
			return nil, fmt.Errorf("parse kev: vulnerabilities[%d]: %w", i, err)
		}
		if _, dup := seen[entry.CVEID]; dup {
			return nil, fmt.Errorf("parse kev: vulnerabilities[%d]: duplicate %s", i, entry.CVEID)
		}
		seen[entry.CVEID] = struct{}{}
		cat.Vulnerabilities = append(cat.Vulnerabilities, entry)
	}
	return cat, nil
}

func (e kevEntryWire) toEntry() (KEVEntry, error) {
	id, ok := NormalizeCVE(e.CVEID)
	if !ok {
		return KEVEntry{}, fmt.Errorf("invalid cveID %q", truncate(e.CVEID, 40))
	}
	added, err := parseDate(e.DateAdded)
	if err != nil {
		return KEVEntry{}, fmt.Errorf("%s: dateAdded: %w", id, err)
	}
	var due time.Time
	if strings.TrimSpace(e.DueDate) != "" {
		if due, err = parseDate(e.DueDate); err != nil {
			return KEVEntry{}, fmt.Errorf("%s: dueDate: %w", id, err)
		}
	}
	return KEVEntry{
		CVEID:                      id,
		VendorProject:              e.VendorProject,
		Product:                    e.Product,
		VulnerabilityName:          e.VulnerabilityName,
		DateAdded:                  added,
		ShortDescription:           e.ShortDescription,
		RequiredAction:             e.RequiredAction,
		DueDate:                    due,
		KnownRansomwareCampaignUse: strings.TrimSpace(e.KnownRansomwareCampaignUse),
		Notes:                      e.Notes,
		CWEs:                       e.CWEs,
	}, nil
}

// truncate shortens s to at most n bytes (dropping any split rune) for error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// KEVClient downloads the KEV catalogue.
type KEVClient struct {
	// URL of the JSON catalogue; empty uses DefaultKEVURL. KEVMirrorURL is an alternative.
	URL string
	// MaxBytes bounds the response size; 0 uses DefaultKEVMaxBytes.
	MaxBytes int64
	HTTP     HTTPOptions
}

// Fetch downloads and parses the catalogue.
func (c *KEVClient) Fetch(ctx context.Context) (*KEVCatalog, error) {
	raw := c.URL
	if raw == "" {
		raw = DefaultKEVURL
	}
	if _, err := validateFeedURL(raw); err != nil {
		return nil, fmt.Errorf("fetch kev: %w", err)
	}
	limit := c.MaxBytes
	if limit <= 0 {
		limit = DefaultKEVMaxBytes
	}
	body, err := c.HTTP.get(ctx, raw, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch kev: %w", err)
	}
	return parseKEV(body)
}
