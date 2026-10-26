package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// MaxLookupIDs bounds the IDs accepted by one GetFindings or ApplicableVEX call; callers with
// more IDs (e.g. after a large ingest) split them into batches.
const MaxLookupIDs = 1000

func validLookupIDs(what string, ids []int64) error {
	if len(ids) > MaxLookupIDs {
		return invalid("%s: %d IDs exceed the limit of %d", what, len(ids), MaxLookupIDs)
	}
	for _, id := range ids {
		if id <= 0 {
			return invalid("%s: IDs must be positive", what)
		}
	}
	return nil
}

// GetFinding returns one finding (ErrNotFound if it does not exist).
func (s *Store) GetFinding(ctx context.Context, id int64) (FindingRecord, error) {
	recs, err := s.GetFindings(ctx, []int64{id})
	if err != nil {
		return FindingRecord{}, err
	}
	if len(recs) == 0 {
		return FindingRecord{}, fmt.Errorf("%w: finding %d", ErrNotFound, id)
	}
	return recs[0], nil
}

// GetFindings returns the findings with the given IDs, ordered by ID; unknown IDs are skipped.
// At most MaxLookupIDs IDs per call.
func (s *Store) GetFindings(ctx context.Context, ids []int64) ([]FindingRecord, error) {
	if err := validLookupIDs("get findings", ids); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []FindingRecord{}, nil
	}
	rows, err := s.pool.Query(ctx, selectFindingsSQL+`
WHERE f.id = ANY ($1::bigint[])
ORDER BY f.id`, ids)
	if err != nil {
		return nil, fmt.Errorf("store: get findings: %w", classify(err))
	}
	records, err := pgx.CollectRows(rows, scanFinding)
	if err != nil {
		return nil, fmt.Errorf("store: get findings: %w", classify(err))
	}
	return records, nil
}

// ApplicableVEX returns, for each given finding that has one, the VEX statement that IngestDocument
// applies to it: the latest statement (by statement time, then insertion order) of the finding's
// project whose vulnerability is the finding's vulnerability ID or one of its aliases and whose
// product is the artifact digest or the component's package URL. Products holds the matching
// product only. The risk engine uses it so that scores agree with the stored status.
// At most MaxLookupIDs IDs per call.
func (s *Store) ApplicableVEX(ctx context.Context, findingIDs []int64) (map[int64]evidence.VEXStatement, error) {
	if err := validLookupIDs("applicable vex", findingIDs); err != nil {
		return nil, err
	}
	out := make(map[int64]evidence.VEXStatement)
	if len(findingIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT DISTINCT ON (f.id) f.id, s.vuln_id, s.product, s.status, s.justification, s.impact_statement,
       s.author, s.statement_time
FROM findings AS f
JOIN artifacts AS a ON a.id = f.artifact_id
JOIN vulnerabilities AS v ON v.id = f.vulnerability_id
LEFT JOIN components AS c ON c.id = f.component_id
JOIN vex_statements AS s ON s.project_id = a.project_id
    AND (s.vuln_id = v.vuln_id OR s.vuln_id = ANY (v.aliases))
    AND (s.product = a.digest OR s.product = c.purl)
WHERE f.id = ANY ($1::bigint[])
ORDER BY f.id, s.statement_time DESC NULLS LAST, s.id DESC`, findingIDs)
	if err != nil {
		return nil, fmt.Errorf("store: applicable vex: %w", classify(err))
	}
	var (
		id                                                  int64
		vulnID, product, status, justification, impact, who string
		at                                                  *time.Time
	)
	_, err = pgx.ForEachRow(rows, []any{&id, &vulnID, &product, &status, &justification, &impact, &who, &at},
		func() error {
			st := evidence.VEXStatement{
				VulnID: vulnID, Products: []string{product}, Status: evidence.VEXStatus(status),
				Justification: justification, ImpactStatement: impact, Author: who,
			}
			if at != nil {
				st.Timestamp = at.UTC()
			}
			out[id] = st
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("store: applicable vex: %w", classify(err))
	}
	return out, nil
}
