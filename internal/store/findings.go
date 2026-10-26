package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// FindingStatus is the lifecycle state of a finding.
type FindingStatus string

// Finding statuses.
const (
	StatusOpen           FindingStatus = "open"
	StatusFixed          FindingStatus = "fixed"            // no longer reported by any tool
	StatusVEXNotAffected FindingStatus = "vex_not_affected" // suppressed by a VEX statement
	StatusAccepted       FindingStatus = "accepted"         // risk accepted by the owner
)

func (s FindingStatus) valid() bool {
	switch s {
	case StatusOpen, StatusFixed, StatusVEXNotAffected, StatusAccepted:
		return true
	}
	return false
}

// RiskTier is the priority tier derived from the risk score (ADR-012).
type RiskTier string

// Risk tiers: P1 ≥ 70 (block), P2 40–69 (warn), P3 < 40.
const (
	TierP1 RiskTier = "P1"
	TierP2 RiskTier = "P2"
	TierP3 RiskTier = "P3"
)

func (t RiskTier) valid() bool { return t == TierP1 || t == TierP2 || t == TierP3 }

// Risk is a finding's computed risk. Explanation is the risk engine's JSON object describing
// every factor (ARCHITECTURE.md §7) so the dashboard can show why.
type Risk struct {
	Score       float64
	Tier        RiskTier
	Explanation json.RawMessage
	// ScoredAt is set by the database on update (read-only).
	ScoredAt time.Time
}

// maxExplanationSize bounds the stored risk explanation.
const maxExplanationSize = 64 << 10

func (r *Risk) validate() error {
	switch {
	case math.IsNaN(r.Score) || r.Score < 0 || r.Score > 100:
		return invalid("risk: score must be within [0, 100]")
	case !r.Tier.valid():
		return invalid("risk: unknown tier %q", r.Tier)
	case len(r.Explanation) > maxExplanationSize:
		return invalid("risk: explanation exceeds %d bytes", maxExplanationSize)
	case !isJSONObject(r.Explanation):
		return invalid("risk: explanation must be a JSON object")
	}
	return nil
}

// RiskUpdate pairs a finding with its new risk, for UpdateFindingRisks.
type RiskUpdate struct {
	FindingID int64
	Risk      Risk
}

const updateRiskSQL = `
UPDATE findings SET risk_score = $2, risk_tier = $3, risk_explanation = $4, risk_scored_at = now(), updated_at = now()
WHERE id = $1`

// UpdateFindingRisk stores the computed risk of one finding (ErrNotFound if it does not exist).
func (s *Store) UpdateFindingRisk(ctx context.Context, findingID int64, r Risk) error {
	return s.UpdateFindingRisks(ctx, []RiskUpdate{{FindingID: findingID, Risk: r}})
}

// UpdateFindingRisks stores many risk results atomically (all or none), e.g. after an ingest.
// It fails with ErrNotFound if any finding does not exist.
func (s *Store) UpdateFindingRisks(ctx context.Context, updates []RiskUpdate) error {
	for i := range updates {
		if updates[i].FindingID <= 0 {
			return invalid("risk update %d: finding ID must be positive", i)
		}
		if err := updates[i].Risk.validate(); err != nil {
			return fmt.Errorf("risk update %d: %w", i, err)
		}
	}
	if len(updates) == 0 {
		return nil
	}
	err := s.inTx(ctx, "update finding risk", func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for _, u := range updates {
			batch.Queue(updateRiskSQL, u.FindingID, u.Risk.Score, string(u.Risk.Tier), []byte(u.Risk.Explanation))
		}
		br := tx.SendBatch(ctx, batch)
		for _, u := range updates {
			tag, err := br.Exec()
			if err != nil {
				_ = br.Close()
				return err
			}
			if tag.RowsAffected() == 0 {
				_ = br.Close()
				return fmt.Errorf("%w: finding %d", ErrNotFound, u.FindingID)
			}
		}
		return br.Close()
	})
	if err != nil {
		return fmt.Errorf("store: update finding risk: %w", classify(err))
	}
	return nil
}

// Page sizes for ListFindings.
const (
	DefaultPageSize = 50
	MaxPageSize     = 500
)

// FindingFilter selects findings for ListFindings. Zero values mean "any".
type FindingFilter struct {
	ProjectID  int64
	ArtifactID int64
	Tier       RiskTier
	Status     FindingStatus
	Kind       evidence.FindingKind
	// Limit is the page size: 0 means DefaultPageSize; values above MaxPageSize are capped.
	Limit int
	// Cursor continues a previous listing (FindingPage.NextCursor); "" starts from the top.
	Cursor string
}

// FindingRecord is a stored finding with its lifecycle and risk data.
type FindingRecord struct {
	ID         int64
	ArtifactID int64
	// Finding is the merged finding. Tools holds tool names only (versions are on the evidence
	// rows); Component.Direct reflects the artifact's dependency graph.
	Finding      evidence.Finding
	Status       FindingStatus
	Risk         *Risk // nil until scored
	FirstSeenRun int64
	LastSeenRun  int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// FindingPage is one page of ListFindings results.
type FindingPage struct {
	Findings []FindingRecord
	// NextCursor is "" on the last page.
	NextCursor string
}

// ListFindings returns findings ordered by risk (highest first, unscored last), then by ID
// descending, using keyset pagination: pass NextCursor back in FindingFilter.Cursor. Pages stay
// stable under concurrent inserts (no OFFSET).
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) (FindingPage, error) {
	switch {
	case f.ProjectID < 0 || f.ArtifactID < 0:
		return FindingPage{}, invalid("findings filter: IDs must not be negative")
	case f.Tier != "" && !f.Tier.valid():
		return FindingPage{}, invalid("findings filter: unknown tier %q", f.Tier)
	case f.Status != "" && !f.Status.valid():
		return FindingPage{}, invalid("findings filter: unknown status %q", f.Status)
	case f.Kind != "" && !validFindingKind(f.Kind):
		return FindingPage{}, invalid("findings filter: unknown kind %q", f.Kind)
	case f.Limit < 0:
		return FindingPage{}, invalid("findings filter: limit must not be negative")
	}
	limit := f.Limit
	if limit == 0 {
		limit = DefaultPageSize
	}
	limit = min(limit, MaxPageSize)
	var afterScore *float64
	var afterID *int64
	if f.Cursor != "" {
		score, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return FindingPage{}, err
		}
		afterScore, afterID = &score, &id
	}

	rows, err := s.pool.Query(ctx, selectFindingsSQL+`
WHERE ($1::bigint IS NULL OR a.project_id = $1)
  AND ($2::bigint IS NULL OR f.artifact_id = $2)
  AND ($3::text IS NULL OR f.risk_tier = $3)
  AND ($4::text IS NULL OR f.status = $4)
  AND ($5::text IS NULL OR f.kind = $5)
  AND ($6::float8 IS NULL OR (coalesce(f.risk_score, -1), f.id) < ($6::float8, $7::bigint))
ORDER BY coalesce(f.risk_score, -1) DESC, f.id DESC
LIMIT $8`,
		nullInt64(f.ProjectID), nullInt64(f.ArtifactID), nullString(string(f.Tier)), nullString(string(f.Status)),
		nullString(string(f.Kind)), afterScore, afterID, limit+1)
	if err != nil {
		return FindingPage{}, fmt.Errorf("store: list findings: %w", classify(err))
	}
	records, err := pgx.CollectRows(rows, scanFinding)
	if err != nil {
		return FindingPage{}, fmt.Errorf("store: list findings: %w", classify(err))
	}
	page := FindingPage{Findings: records}
	if len(records) > limit {
		page.Findings = records[:limit]
		last := page.Findings[limit-1]
		score := -1.0
		if last.Risk != nil {
			score = last.Risk.Score
		}
		page.NextCursor = encodeCursor(score, last.ID)
	}
	return page, nil
}

// selectFindingsSQL is the SELECT … FROM part shared by ListFindings and GetFindings; its column
// list must match scanFinding.
const selectFindingsSQL = `
SELECT f.id, f.artifact_id, f.kind, f.fingerprint, f.title, f.message, f.severity, f.rule_id, f.tools,
       f.fixed_versions, f.reachability, f.location_path, f.location_start_line, f.location_end_line,
       f.status, f.risk_score, f.risk_tier, f.risk_explanation, f.risk_scored_at,
       f.first_seen_run, f.last_seen_run, f.created_at, f.updated_at,
       c.purl, c.name, c.version, c.ecosystem, c.licenses, ac.direct,
       v.vuln_id, v.aliases, v.summary, v.severity, v.cvss, v.cwes, v.published
FROM findings AS f
JOIN artifacts AS a ON a.id = f.artifact_id
LEFT JOIN components AS c ON c.id = f.component_id
LEFT JOIN artifact_components AS ac ON ac.artifact_id = f.artifact_id AND ac.component_id = f.component_id
LEFT JOIN vulnerabilities AS v ON v.id = f.vulnerability_id`

// scanFinding maps one ListFindings row.
func scanFinding(row pgx.CollectableRow) (FindingRecord, error) {
	var (
		r                           FindingRecord
		kind, severity, status      string
		reachability, locPath       *string
		locStart, locEnd            *int32
		riskScore                   *float64
		riskTier                    *string
		riskExplanation             []byte
		riskScoredAt                *time.Time
		purl, cName, cVersion, cEco *string
		licenses                    []string
		direct                      *bool
		vulnID, vSummary, vSeverity *string
		aliases, cwes               []string
		cvss                        []byte
		published                   *time.Time
		tools                       []string
	)
	err := row.Scan(&r.ID, &r.ArtifactID, &kind, &r.Finding.Fingerprint, &r.Finding.Title, &r.Finding.Message,
		&severity, &r.Finding.RuleID, &tools, &r.Finding.FixedVersions, &reachability, &locPath, &locStart, &locEnd,
		&status, &riskScore, &riskTier, &riskExplanation, &riskScoredAt,
		&r.FirstSeenRun, &r.LastSeenRun, &r.CreatedAt, &r.UpdatedAt,
		&purl, &cName, &cVersion, &cEco, &licenses, &direct,
		&vulnID, &aliases, &vSummary, &vSeverity, &cvss, &cwes, &published)
	if err != nil {
		return r, err
	}
	r.Finding.Kind = evidence.FindingKind(kind)
	r.Finding.Severity = evidence.Severity(severity)
	r.Status = FindingStatus(status)
	r.Finding.Tools = make([]evidence.Tool, len(tools))
	for i, t := range tools {
		r.Finding.Tools[i] = evidence.Tool{Name: t}
	}
	if len(r.Finding.FixedVersions) == 0 {
		r.Finding.FixedVersions = nil
	}
	if reachability != nil {
		r.Finding.Reachability = evidence.Reachability(*reachability)
	}
	if locPath != nil {
		r.Finding.Location = &evidence.Location{Path: *locPath}
		if locStart != nil {
			r.Finding.Location.StartLine = int(*locStart)
		}
		if locEnd != nil {
			r.Finding.Location.EndLine = int(*locEnd)
		}
	}
	if riskScore != nil && riskTier != nil && riskScoredAt != nil {
		r.Risk = &Risk{Score: *riskScore, Tier: RiskTier(*riskTier), Explanation: riskExplanation, ScoredAt: *riskScoredAt}
	}
	if purl != nil {
		r.Finding.Component = &evidence.Component{
			PURL: *purl, Name: deref(cName), Version: deref(cVersion), Ecosystem: deref(cEco),
			Licenses: nilIfEmpty(licenses), Direct: direct != nil && *direct,
		}
	}
	if vulnID != nil {
		v := &evidence.Vulnerability{
			ID: *vulnID, Aliases: nilIfEmpty(aliases), Summary: deref(vSummary),
			Severity: evidence.Severity(deref(vSeverity)), CWEs: nilIfEmpty(cwes),
		}
		if published != nil {
			v.Published = published.UTC()
		}
		if len(cvss) > 0 {
			if err := json.Unmarshal(cvss, &v.CVSS); err != nil {
				return r, fmt.Errorf("decode cvss of %s: %w", *vulnID, err)
			}
			if len(v.CVSS) == 0 {
				v.CVSS = nil
			}
		}
		r.Finding.Vulnerability = v
	}
	return r, nil
}

// Cursors are opaque to clients: base64url("v1|<sort score>|<id>"). Tampering is harmless (the
// values are bind parameters) but strictly rejected.
const cursorVersion = "v1"

func encodeCursor(score float64, id int64) string {
	raw := cursorVersion + "|" + strconv.FormatFloat(score, 'g', -1, 64) + "|" + strconv.FormatInt(id, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(c string) (float64, int64, error) {
	bad := invalid("findings filter: malformed cursor")
	if len(c) > 128 {
		return 0, 0, bad
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, 0, bad
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 || parts[0] != cursorVersion {
		return 0, 0, bad
	}
	score, err := strconv.ParseFloat(parts[1], 64)
	if err != nil || math.IsNaN(score) || score < -1 || score > 100 {
		return 0, 0, bad
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || id <= 0 {
		return 0, 0, bad
	}
	return score, id, nil
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
