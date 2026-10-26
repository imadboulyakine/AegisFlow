package store

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

var cveRE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// maxIntelBatch bounds one RecordVulnIntel / LatestVulnIntel call (the KEV catalogue has ~1.5k
// entries; EPSS syncs are limited to CVEs AegisFlow has seen).
const maxIntelBatch = 100_000

// VulnIntel is one dated threat-intelligence snapshot for a CVE. Nil fields were not provided by
// the sync that produced the snapshot (EPSS and KEV are synced independently and merged per day).
type VulnIntel struct {
	CVE string
	// Date is the snapshot day (EPSS score date / KEV catalogue date); only the UTC date is used.
	Date           time.Time
	EPSS           *float64 // probability [0, 1]
	EPSSPercentile *float64 // [0, 1]
	KEV            *bool    // listed in CISA KEV
	KEVDateAdded   time.Time
	KEVRansomware  *bool // knownRansomwareCampaignUse == "Known"
}

type intelRow struct {
	CVE            string   `json:"cve_id"`
	Date           string   `json:"snapshot_date"`
	EPSS           *float64 `json:"epss"`
	EPSSPercentile *float64 `json:"epss_percentile"`
	KEV            *bool    `json:"kev"`
	KEVDateAdded   *string  `json:"kev_date_added"`
	KEVRansomware  *bool    `json:"kev_ransomware"`
}

func validProbability(p *float64) bool { return p == nil || (!math.IsNaN(*p) && *p >= 0 && *p <= 1) }

// RecordVulnIntel upserts snapshots by (CVE, date); fields already recorded for that day are kept
// when the new snapshot leaves them nil. Returns the number of rows written.
func (s *Store) RecordVulnIntel(ctx context.Context, snapshots []VulnIntel) (int, error) {
	if len(snapshots) > maxIntelBatch {
		return 0, invalid("vuln intel: %d snapshots exceed the batch limit of %d", len(snapshots), maxIntelBatch)
	}
	rows := make([]intelRow, 0, len(snapshots))
	seen := make(map[[2]string]bool, len(snapshots))
	for i, v := range snapshots {
		switch {
		case !cveRE.MatchString(v.CVE):
			return 0, invalid("vuln intel %d: invalid CVE ID", i)
		case v.Date.IsZero():
			return 0, invalid("vuln intel %d: missing snapshot date", i)
		case !validProbability(v.EPSS) || !validProbability(v.EPSSPercentile):
			return 0, invalid("vuln intel %d: EPSS values must be within [0, 1]", i)
		}
		r := intelRow{
			CVE: v.CVE, Date: v.Date.UTC().Format(time.DateOnly), EPSS: v.EPSS, EPSSPercentile: v.EPSSPercentile,
			KEV: v.KEV, KEVRansomware: v.KEVRansomware,
		}
		if !v.KEVDateAdded.IsZero() {
			d := v.KEVDateAdded.UTC().Format(time.DateOnly)
			r.KEVDateAdded = &d
		}
		key := [2]string{r.CVE, r.Date}
		if seen[key] {
			return 0, invalid("vuln intel %d: duplicate snapshot for %s on %s", i, r.CVE, r.Date)
		}
		seen[key] = true
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	slices.SortFunc(rows, func(a, b intelRow) int {
		if a.CVE != b.CVE {
			if a.CVE < b.CVE {
				return -1
			}
			return 1
		}
		if a.Date < b.Date {
			return -1
		}
		if a.Date > b.Date {
			return 1
		}
		return 0
	})
	payload, err := json.Marshal(rows)
	if err != nil {
		return 0, fmt.Errorf("store: record vuln intel: encode: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
INSERT INTO vuln_intel AS i (cve_id, snapshot_date, epss, epss_percentile, kev, kev_date_added, kev_ransomware)
SELECT x.cve_id, x.snapshot_date, x.epss, x.epss_percentile, x.kev, x.kev_date_added, x.kev_ransomware
FROM jsonb_to_recordset($1::jsonb) AS x(cve_id text, snapshot_date date, epss double precision,
    epss_percentile double precision, kev boolean, kev_date_added date, kev_ransomware boolean)
ORDER BY x.cve_id COLLATE "C", x.snapshot_date
ON CONFLICT (cve_id, snapshot_date) DO UPDATE SET
    epss            = coalesce(EXCLUDED.epss, i.epss),
    epss_percentile = coalesce(EXCLUDED.epss_percentile, i.epss_percentile),
    kev             = coalesce(EXCLUDED.kev, i.kev),
    kev_date_added  = coalesce(EXCLUDED.kev_date_added, i.kev_date_added),
    kev_ransomware  = coalesce(EXCLUDED.kev_ransomware, i.kev_ransomware),
    fetched_at      = now()`, payload)
	if err != nil {
		return 0, fmt.Errorf("store: record vuln intel: %w", classify(err))
	}
	return int(tag.RowsAffected()), nil
}

// LatestIntel is the most recent known EPSS and KEV data for a CVE (each from its own latest
// snapshot that provided it).
type LatestIntel struct {
	CVE            string
	EPSS           *float64
	EPSSPercentile *float64
	EPSSDate       time.Time // zero when no EPSS data
	KEV            *bool
	KEVDateAdded   time.Time
	KEVRansomware  *bool
	KEVDate        time.Time // zero when no KEV data
}

// LatestVulnIntel returns the latest intel for each requested CVE that has any (keyed by CVE).
func (s *Store) LatestVulnIntel(ctx context.Context, cves []string) (map[string]LatestIntel, error) {
	if len(cves) > maxIntelBatch {
		return nil, invalid("vuln intel: %d CVEs exceed the batch limit of %d", len(cves), maxIntelBatch)
	}
	out := make(map[string]LatestIntel, len(cves))
	if len(cves) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
WITH e AS (
    SELECT DISTINCT ON (cve_id) cve_id, snapshot_date, epss, epss_percentile
    FROM vuln_intel WHERE cve_id = ANY ($1::text[]) AND epss IS NOT NULL
    ORDER BY cve_id, snapshot_date DESC
), k AS (
    SELECT DISTINCT ON (cve_id) cve_id, snapshot_date, kev, kev_date_added, kev_ransomware
    FROM vuln_intel WHERE cve_id = ANY ($1::text[]) AND kev IS NOT NULL
    ORDER BY cve_id, snapshot_date DESC
)
SELECT coalesce(e.cve_id, k.cve_id), e.epss, e.epss_percentile, e.snapshot_date,
       k.kev, k.kev_date_added, k.kev_ransomware, k.snapshot_date
FROM e FULL JOIN k ON k.cve_id = e.cve_id`, cves)
	if err != nil {
		return nil, fmt.Errorf("store: latest vuln intel: %w", classify(err))
	}
	// Fresh scan targets per row: pointer fields must not be shared between results.
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (LatestIntel, error) {
		var (
			li                          LatestIntel
			epssDate, kevAdded, kevDate *time.Time
		)
		err := row.Scan(&li.CVE, &li.EPSS, &li.EPSSPercentile, &epssDate, &li.KEV, &kevAdded, &li.KEVRansomware, &kevDate)
		li.EPSSDate, li.KEVDateAdded, li.KEVDate = timeOrZero(epssDate), timeOrZero(kevAdded), timeOrZero(kevDate)
		return li, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: latest vuln intel: %w", classify(err))
	}
	for _, li := range list {
		out[li.CVE] = li
	}
	return out, nil
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
