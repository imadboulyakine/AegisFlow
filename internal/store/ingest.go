package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// ingestLockNamespace is the first key of the two-int4 transaction advisory lock that serializes
// ingests per project ("AF" + 0x0001).
const ingestLockNamespace int32 = 0x41460001

// IngestResult summarizes what IngestDocument changed.
type IngestResult struct {
	// ProjectID is the project of the run (and artifact).
	ProjectID int64
	// Components is the number of distinct valid components in the document (SBOM entries plus
	// packages referenced by findings); SkippedComponents had no valid package URL.
	Components        int
	SkippedComponents int
	// Vulnerabilities is the number of distinct vulnerabilities referenced by findings.
	Vulnerabilities int
	// FindingsNew were first seen in this document; FindingsSeen were already known (including
	// FindingsReopened, which had been fixed); FindingsFixed were open, reported by this
	// document's tools before, and are no longer reported by any tool.
	FindingsNew      int
	FindingsSeen     int
	FindingsReopened int
	FindingsFixed    int
	// VEXStatements is the number of new VEX statement/product rows (duplicates are ignored).
	VEXStatements int
	// VEXStatusChanges counts findings moved between open and vex_not_affected by VEX.
	VEXStatusChanges int
	// FindingIDs lists the findings present in the document (ascending).
	FindingIDs []int64
	// ChangedFindingIDs lists findings whose status was changed by absence (fixed) or by VEX
	// (ascending; may overlap FindingIDs). Re-score FindingIDs ∪ ChangedFindingIDs after an
	// ingest: risk depends on status and on the merged finding data.
	ChangedFindingIDs []int64
}

// IngestDocument merges a normalized evidence document into the derived model, in one
// transaction:
//
//   - components are upserted by package URL and linked to the artifact;
//   - vulnerabilities are upserted by ID (aliases, CWEs and CVSS ratings are unioned, the highest
//     severity and earliest publication date win);
//   - findings are upserted by (artifact, fingerprint): tools are unioned, last_seen_run is set
//     to runID and fixed findings are reopened;
//   - open findings of the artifact that this document's tools reported before but no longer
//     report lose those tools, and become fixed when no tool reports them any more;
//   - VEX statements are stored (per project) and the latest applicable statement moves findings
//     between open and vex_not_affected.
//
// Re-ingesting the same document is idempotent. Ingests are serialized per project with a
// transaction-scoped advisory lock. artifactID may be 0 only for documents that carry nothing but
// VEX statements. The run and the artifact must belong to the same project.
func (s *Store) IngestDocument(ctx context.Context, runID, artifactID int64, doc evidence.Document) (IngestResult, error) {
	if runID <= 0 {
		return IngestResult{}, invalid("ingest: run ID must be positive")
	}
	if artifactID < 0 {
		return IngestResult{}, invalid("ingest: artifact ID must not be negative")
	}
	p, err := prepareDocument(doc)
	if err != nil {
		return IngestResult{}, fmt.Errorf("store: ingest document: %w", err)
	}
	if artifactID == 0 && (len(p.components) > 0 || len(p.findings) > 0) {
		return IngestResult{}, invalid("ingest: components and findings require an artifact")
	}
	var res IngestResult
	err = s.inTx(ctx, "ingest document", func(tx pgx.Tx) error {
		var err error
		res, err = ingestTx(ctx, tx, runID, artifactID, p)
		return err
	})
	if err != nil {
		return IngestResult{}, fmt.Errorf("store: ingest document: %w", classify(err))
	}
	return res, nil
}

func ingestTx(ctx context.Context, tx pgx.Tx, runID, artifactID int64, p *preparedDoc) (IngestResult, error) {
	res := IngestResult{
		Components: len(p.components), SkippedComponents: p.skippedComponents, Vulnerabilities: len(p.vulns),
		FindingIDs: []int64{}, ChangedFindingIDs: []int64{},
	}
	projectID, err := runProject(ctx, tx, runID)
	if err != nil {
		return res, err
	}
	res.ProjectID = projectID
	if artifactID != 0 {
		if err := checkArtifactProject(ctx, tx, artifactID, projectID); err != nil {
			return res, err
		}
	}
	// Project IDs are folded into the int4 key space; a collision only serializes two projects.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int4, ($2::bigint % 2147483647)::int4)`,
		ingestLockNamespace, projectID); err != nil {
		return res, fmt.Errorf("lock project: %w", err)
	}

	componentIDs, err := upsertComponents(ctx, tx, p.components)
	if err != nil {
		return res, err
	}
	if err := linkComponents(ctx, tx, artifactID, runID, p.components, componentIDs); err != nil {
		return res, err
	}
	vulnIDs, err := upsertVulnerabilities(ctx, tx, p.vulns)
	if err != nil {
		return res, err
	}
	if artifactID != 0 {
		if err := upsertFindings(ctx, tx, artifactID, runID, p, componentIDs, vulnIDs, &res); err != nil {
			return res, err
		}
		if err := markAbsentFixed(ctx, tx, artifactID, p.tools, &res); err != nil {
			return res, err
		}
	}
	if len(p.vex) > 0 {
		if err := insertVEX(ctx, tx, projectID, runID, p.vex, &res); err != nil {
			return res, err
		}
	}
	// A VEX document can affect every artifact of the project; a scan document only needs the
	// project's existing statements applied to its own artifact's findings.
	if len(p.vex) > 0 || artifactID != 0 {
		if err := applyVEX(ctx, tx, projectID, artifactID, len(p.vex) > 0, &res); err != nil {
			return res, err
		}
	}
	slices.Sort(res.FindingIDs)
	slices.Sort(res.ChangedFindingIDs)
	res.ChangedFindingIDs = slices.Compact(res.ChangedFindingIDs)
	return res, nil
}

func upsertComponents(ctx context.Context, tx pgx.Tx, rows []componentRow) (map[string]int64, error) {
	ids := make(map[string]int64, len(rows))
	if len(rows) == 0 {
		return ids, nil
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return nil, fmt.Errorf("encode components: %w", err)
	}
	// Rows that would not change are skipped (no write), but still locked by ON CONFLICT.
	if _, err := tx.Exec(ctx, `
INSERT INTO components AS c (purl, name, version, ecosystem, licenses)
SELECT x.purl, x.name, x.version, x.ecosystem, x.licenses
FROM jsonb_to_recordset($1::jsonb) AS x(purl text, name text, version text, ecosystem text, licenses text[])
ORDER BY x.purl COLLATE "C"
ON CONFLICT (purl) DO UPDATE SET
    name       = CASE WHEN c.name = '' THEN EXCLUDED.name ELSE c.name END,
    version    = CASE WHEN c.version = '' THEN EXCLUDED.version ELSE c.version END,
    ecosystem  = CASE WHEN c.ecosystem = '' THEN EXCLUDED.ecosystem ELSE c.ecosystem END,
    licenses   = aegisflow_text_union(c.licenses, EXCLUDED.licenses, 64),
    updated_at = now()
WHERE (c.name = '' AND EXCLUDED.name <> '') OR (c.version = '' AND EXCLUDED.version <> '')
   OR (c.ecosystem = '' AND EXCLUDED.ecosystem <> '')
   OR c.licenses IS DISTINCT FROM aegisflow_text_union(c.licenses, EXCLUDED.licenses, 64)`, payload); err != nil {
		return nil, fmt.Errorf("upsert components: %w", err)
	}
	purls := make([]string, len(rows))
	for i, r := range rows {
		purls[i] = r.PURL
	}
	q, err := tx.Query(ctx, `SELECT purl, id FROM components WHERE purl = ANY($1::text[])`, purls)
	if err != nil {
		return nil, fmt.Errorf("resolve components: %w", err)
	}
	var purl string
	var id int64
	if _, err := pgx.ForEachRow(q, []any{&purl, &id}, func() error { ids[purl] = id; return nil }); err != nil {
		return nil, fmt.Errorf("resolve components: %w", err)
	}
	if len(ids) != len(rows) {
		return nil, fmt.Errorf("resolve components: found %d of %d", len(ids), len(rows))
	}
	return ids, nil
}

func linkComponents(ctx context.Context, tx pgx.Tx, artifactID, runID int64, rows []componentRow, ids map[string]int64) error {
	if artifactID == 0 || len(rows) == 0 {
		return nil
	}
	componentIDs := make([]int64, len(rows))
	direct := make([]bool, len(rows))
	for i, r := range rows {
		componentIDs[i], direct[i] = ids[r.PURL], r.Direct
	}
	_, err := tx.Exec(ctx, `
INSERT INTO artifact_components AS ac (artifact_id, component_id, direct, first_seen_run, last_seen_run)
SELECT $1, x.component_id, x.direct, $2, $2
FROM unnest($3::bigint[], $4::boolean[]) AS x(component_id, direct)
ORDER BY x.component_id
ON CONFLICT (artifact_id, component_id) DO UPDATE SET
    direct        = ac.direct OR EXCLUDED.direct,
    last_seen_run = EXCLUDED.last_seen_run
WHERE ac.last_seen_run <> EXCLUDED.last_seen_run OR (EXCLUDED.direct AND NOT ac.direct)`,
		artifactID, runID, componentIDs, direct)
	if err != nil {
		return fmt.Errorf("link components: %w", err)
	}
	return nil
}

func upsertVulnerabilities(ctx context.Context, tx pgx.Tx, rows []vulnRow) (map[string]int64, error) {
	ids := make(map[string]int64, len(rows))
	if len(rows) == 0 {
		return ids, nil
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return nil, fmt.Errorf("encode vulnerabilities: %w", err)
	}
	q, err := tx.Query(ctx, `
INSERT INTO vulnerabilities AS v (vuln_id, aliases, summary, severity, cvss, cwes, published)
SELECT x.vuln_id, x.aliases, x.summary, x.severity, x.cvss, x.cwes, x.published
FROM jsonb_to_recordset($1::jsonb)
    AS x(vuln_id text, aliases text[], summary text, severity text, cvss jsonb, cwes text[], published timestamptz)
ORDER BY x.vuln_id COLLATE "C"
ON CONFLICT (vuln_id) DO UPDATE SET
    aliases   = aegisflow_text_union(v.aliases, EXCLUDED.aliases, 64),
    summary   = CASE WHEN v.summary = '' THEN EXCLUDED.summary ELSE v.summary END,
    severity  = CASE WHEN aegisflow_severity_rank(EXCLUDED.severity) > aegisflow_severity_rank(v.severity)
                     THEN EXCLUDED.severity ELSE v.severity END,
    cvss      = (SELECT coalesce(jsonb_agg(d.e ORDER BY d.e), '[]'::jsonb)
                 FROM (SELECT DISTINCT e FROM jsonb_array_elements(v.cvss || EXCLUDED.cvss) AS e
                       ORDER BY e LIMIT 16) AS d),
    cwes      = aegisflow_text_union(v.cwes, EXCLUDED.cwes, 64),
    published = least(v.published, EXCLUDED.published),
    updated_at = now()
RETURNING v.vuln_id, v.id`, payload)
	if err != nil {
		return nil, fmt.Errorf("upsert vulnerabilities: %w", err)
	}
	var vulnID string
	var id int64
	if _, err := pgx.ForEachRow(q, []any{&vulnID, &id}, func() error { ids[vulnID] = id; return nil }); err != nil {
		return nil, fmt.Errorf("upsert vulnerabilities: %w", err)
	}
	return ids, nil
}

func upsertFindings(ctx context.Context, tx pgx.Tx, artifactID, runID int64, p *preparedDoc,
	componentIDs, vulnIDs map[string]int64, res *IngestResult,
) error {
	if len(p.findings) == 0 {
		return nil
	}
	rows := slices.Clone(p.findings)
	for i := range rows {
		if id, ok := componentIDs[rows[i].purl]; ok {
			rows[i].ComponentID = &id
		}
		if id, ok := vulnIDs[rows[i].vulnID]; ok {
			rows[i].VulnerabilityID = &id
		}
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("encode findings: %w", err)
	}
	q, err := tx.Query(ctx, `
INSERT INTO findings AS f (artifact_id, fingerprint, kind, title, message, severity, rule_id, tools,
    component_id, vulnerability_id, fixed_versions, reachability, location_path, location_start_line,
    location_end_line, first_seen_run, last_seen_run)
SELECT $1, x.fingerprint, x.kind, x.title, x.message, x.severity, x.rule_id, x.tools,
    x.component_id, x.vulnerability_id, x.fixed_versions, x.reachability, x.location_path,
    x.location_start_line, x.location_end_line, $2, $2
FROM jsonb_to_recordset($3::jsonb) AS x(fingerprint text, kind text, title text, message text,
    severity text, rule_id text, tools text[], component_id bigint, vulnerability_id bigint,
    fixed_versions text[], reachability text, location_path text, location_start_line integer,
    location_end_line integer)
ORDER BY x.fingerprint COLLATE "C"
ON CONFLICT (artifact_id, fingerprint) DO UPDATE SET
    title            = CASE WHEN f.title = '' THEN EXCLUDED.title ELSE f.title END,
    message          = CASE WHEN f.message = '' THEN EXCLUDED.message ELSE f.message END,
    rule_id          = CASE WHEN f.rule_id = '' THEN EXCLUDED.rule_id ELSE f.rule_id END,
    severity         = CASE WHEN aegisflow_severity_rank(EXCLUDED.severity) > aegisflow_severity_rank(f.severity)
                            THEN EXCLUDED.severity ELSE f.severity END,
    -- A fixed finding observed again is reopened with only the tools that report it now.
    tools            = CASE WHEN f.status = 'fixed' THEN EXCLUDED.tools
                            ELSE aegisflow_text_union(f.tools, EXCLUDED.tools, 32) END,
    status           = CASE WHEN f.status = 'fixed' THEN 'open' ELSE f.status END,
    component_id     = coalesce(f.component_id, EXCLUDED.component_id),
    vulnerability_id = coalesce(f.vulnerability_id, EXCLUDED.vulnerability_id),
    fixed_versions   = aegisflow_text_union(f.fixed_versions, EXCLUDED.fixed_versions, 64),
    reachability     = CASE WHEN aegisflow_reachability_rank(EXCLUDED.reachability) > aegisflow_reachability_rank(f.reachability)
                            THEN EXCLUDED.reachability ELSE f.reachability END,
    location_path       = coalesce(f.location_path, EXCLUDED.location_path),
    location_start_line = CASE WHEN f.location_path IS NULL THEN EXCLUDED.location_start_line ELSE f.location_start_line END,
    location_end_line   = CASE WHEN f.location_path IS NULL THEN EXCLUDED.location_end_line ELSE f.location_end_line END,
    last_seen_run    = EXCLUDED.last_seen_run,
    updated_at       = now()
RETURNING f.id, old.id IS NULL, coalesce(old.status, '')`, artifactID, runID, payload)
	if err != nil {
		return fmt.Errorf("upsert findings: %w", err)
	}
	var (
		id        int64
		inserted  bool
		oldStatus string
	)
	_, err = pgx.ForEachRow(q, []any{&id, &inserted, &oldStatus}, func() error {
		res.FindingIDs = append(res.FindingIDs, id)
		switch {
		case inserted:
			res.FindingsNew++
		case oldStatus == "fixed":
			res.FindingsReopened++
			res.FindingsSeen++
		default:
			res.FindingsSeen++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("upsert findings: %w", err)
	}
	return nil
}

// markAbsentFixed removes this document's tools from the artifact's findings that the document
// no longer reports; an open finding left without any reporting tool becomes fixed (and keeps
// its last tools for display). Accepted and VEX-suppressed findings keep their status.
func markAbsentFixed(ctx context.Context, tx pgx.Tx, artifactID int64, tools []string, res *IngestResult) error {
	q, err := tx.Query(ctx, `
WITH gone AS (
    SELECT f.id,
           ARRAY(SELECT t FROM unnest(f.tools) AS t WHERE t <> ALL ($2::text[]) ORDER BY t COLLATE "C") AS remaining
    FROM findings AS f
    WHERE f.artifact_id = $1 AND f.tools && $2::text[] AND f.id <> ALL ($3::bigint[])
)
UPDATE findings AS f SET
    tools      = CASE WHEN cardinality(g.remaining) > 0 THEN g.remaining ELSE f.tools END,
    status     = CASE WHEN cardinality(g.remaining) = 0 AND f.status = 'open' THEN 'fixed' ELSE f.status END,
    updated_at = now()
FROM gone AS g
WHERE f.id = g.id AND (cardinality(g.remaining) > 0 OR f.status = 'open')
RETURNING f.id, old.status, new.status`, artifactID, tools, res.FindingIDs)
	if err != nil {
		return fmt.Errorf("mark absent findings: %w", err)
	}
	var (
		id                   int64
		oldStatus, newStatus string
	)
	_, err = pgx.ForEachRow(q, []any{&id, &oldStatus, &newStatus}, func() error {
		if oldStatus != newStatus {
			res.FindingsFixed++
			res.ChangedFindingIDs = append(res.ChangedFindingIDs, id)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("mark absent findings: %w", err)
	}
	return nil
}

func insertVEX(ctx context.Context, tx pgx.Tx, projectID, runID int64, rows []vexRow, res *IngestResult) error {
	payload, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("encode vex statements: %w", err)
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO vex_statements (project_id, run_id, vuln_id, product, status, justification, impact_statement,
    author, statement_time, dedup_key)
SELECT $1, $2, x.vuln_id, x.product, x.status, x.justification, x.impact_statement, x.author,
    x.statement_time, x.dedup_key
FROM jsonb_to_recordset($3::jsonb) AS x(vuln_id text, product text, status text, justification text,
    impact_statement text, author text, statement_time timestamptz, dedup_key text)
ORDER BY x.dedup_key
ON CONFLICT ON CONSTRAINT vex_statements_dedup_key DO NOTHING`, projectID, runID, payload)
	if err != nil {
		return fmt.Errorf("insert vex statements: %w", err)
	}
	res.VEXStatements = int(tag.RowsAffected())
	return nil
}

// applyVEX moves findings between open and vex_not_affected according to the latest VEX
// statement (by statement time, then insertion order) whose vulnerability matches the finding's
// vulnerability ID or one of its aliases and whose product is the artifact digest or the
// component's package URL. Scope: one artifact, or the whole project when allArtifacts is set.
func applyVEX(ctx context.Context, tx pgx.Tx, projectID, artifactID int64, allArtifacts bool, res *IngestResult) error {
	var scope *int64
	if !allArtifacts {
		scope = &artifactID
	}
	q, err := tx.Query(ctx, `
WITH latest AS (
    SELECT DISTINCT ON (f.id) f.id AS finding_id, s.status AS vex_status
    FROM findings AS f
    JOIN artifacts AS a ON a.id = f.artifact_id
    JOIN vulnerabilities AS v ON v.id = f.vulnerability_id
    LEFT JOIN components AS c ON c.id = f.component_id
    JOIN vex_statements AS s ON s.project_id = a.project_id
        AND (s.vuln_id = v.vuln_id OR s.vuln_id = ANY (v.aliases))
        AND (s.product = a.digest OR s.product = c.purl)
    WHERE a.project_id = $1 AND ($2::bigint IS NULL OR a.id = $2)
    ORDER BY f.id, s.statement_time DESC NULLS LAST, s.id DESC
)
UPDATE findings AS f SET
    status     = CASE WHEN l.vex_status = 'not_affected' THEN 'vex_not_affected' ELSE 'open' END,
    updated_at = now()
FROM latest AS l
WHERE f.id = l.finding_id
  AND ((l.vex_status = 'not_affected' AND f.status = 'open')
    OR (l.vex_status <> 'not_affected' AND f.status = 'vex_not_affected'))
RETURNING f.id`, projectID, scope)
	if err != nil {
		return fmt.Errorf("apply vex: %w", err)
	}
	var id int64
	_, err = pgx.ForEachRow(q, []any{&id}, func() error {
		res.VEXStatusChanges++
		res.ChangedFindingIDs = append(res.ChangedFindingIDs, id)
		return nil
	})
	if err != nil {
		return fmt.Errorf("apply vex: %w", err)
	}
	return nil
}
