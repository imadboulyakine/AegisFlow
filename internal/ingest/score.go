package ingest

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/risk"
	"github.com/imadboulyakine/aegisflow/internal/store"
)

// scoredFinding pairs a stored finding with its new risk result.
type scoredFinding struct {
	rec    store.FindingRecord
	result risk.Result
}

func (sf scoredFinding) top() TopFinding {
	t := TopFinding{
		ID: sf.rec.ID, Status: sf.rec.Status, Score: sf.result.Score, Tier: sf.result.Tier, Reason: sf.result.Reason,
	}
	if v := sf.rec.Finding.Vulnerability; v != nil {
		t.VulnID = v.ID
	}
	if c := sf.rec.Finding.Component; c != nil {
		t.PURL = c.PURL
	}
	return t
}

// scorable reports whether the risk engine applies to a stored finding: vulnerability findings
// that are open or suppressed by VEX. Fixed and accepted findings keep their last score.
func scorable(r store.FindingRecord) bool {
	return r.Finding.Kind == evidence.FindingVulnerability && r.Finding.Vulnerability != nil &&
		(r.Status == store.StatusOpen || r.Status == store.StatusVEXNotAffected)
}

// score (re-)scores the given findings and stores the results atomically per batch. The VEX
// statement passed to the engine is the one the store applied (ApplicableVEX), so the score and
// the stored status always agree. Results are returned ranked: tier, then score descending,
// then finding ID.
func (s *Service) score(ctx context.Context, ids []int64) ([]scoredFinding, error) {
	var out []scoredFinding
	for batch := range slices.Chunk(ids, store.MaxLookupIDs) {
		recs, err := s.store.GetFindings(ctx, batch)
		if err != nil {
			return nil, storeError("findings", err)
		}
		recs = slices.DeleteFunc(recs, func(r store.FindingRecord) bool { return !scorable(r) })
		if len(recs) == 0 {
			continue
		}
		vulnIDs := make([]int64, len(recs))
		for i, r := range recs {
			vulnIDs[i] = r.ID
		}
		vex, err := s.store.ApplicableVEX(ctx, vulnIDs)
		if err != nil {
			return nil, storeError("findings", err)
		}
		updates := make([]store.RiskUpdate, 0, len(recs))
		for _, r := range recs {
			var st *evidence.VEXStatement
			if v, ok := vex[r.ID]; ok {
				st = &v
			}
			res := s.engine.Score(risk.NewInput(r.Finding, s.intel, s.exposure, st))
			explanation, err := json.Marshal(res)
			if err != nil {
				return nil, fail(KindInternal, err, "encode risk explanation")
			}
			updates = append(updates, store.RiskUpdate{FindingID: r.ID, Risk: store.Risk{
				Score: res.Score, Tier: store.RiskTier(res.Tier), Explanation: explanation,
			}})
			out = append(out, scoredFinding{rec: r, result: res})
		}
		if err := s.store.UpdateFindingRisks(ctx, updates); err != nil {
			return nil, storeError("risk scores", err)
		}
	}
	slices.SortStableFunc(out, func(a, b scoredFinding) int {
		return cmp.Or(
			cmp.Compare(tierOrder(a.result.Tier), tierOrder(b.result.Tier)),
			cmp.Compare(b.result.Score, a.result.Score),
			cmp.Compare(a.rec.ID, b.rec.ID),
		)
	})
	return out, nil
}

func tierOrder(t risk.Tier) int {
	switch t {
	case risk.TierP1:
		return 1
	case risk.TierP2:
		return 2
	default:
		return 3
	}
}
