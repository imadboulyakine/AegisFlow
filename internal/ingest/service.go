// Package ingest is the evidence-ingestion service behind POST /api/v1/ingest. It turns one
// authenticated CI upload into stored, normalized and risk-scored findings:
//
//	verified OIDC claims + {artifact, commit, format?, evidence bytes}
//	  → commit check → normalize (size/item limits) → project → run → artifact
//	  → raw evidence (append-only, SHA-256, idempotent) → derived model (components,
//	    vulnerabilities, findings, VEX) → risk scores (KEV/EPSS, reachability, exposure, VEX)
//	  → audit entry.
//
// The evidence is parsed before anything is written, so a document the normalizer rejects never
// reaches the append-only evidence table. Every later step is idempotent, so a CI retry after a
// partial failure converges to the same state.
package ingest

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/imadboulyakine/aegisflow/internal/auth/ghoidc"
	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/evidence/normalize"
	"github.com/imadboulyakine/aegisflow/internal/risk"
	"github.com/imadboulyakine/aegisflow/internal/store"
)

// DefaultMaxEvidenceBytes is the largest evidence document Ingest accepts by default (12 MiB:
// the 16 MiB HTTP body limit minus base64 overhead). The normalizer's own default (64 MiB) is
// too generous for an API: encoding/json can allocate many times the input size.
const DefaultMaxEvidenceBytes int64 = 12 << 20

// MaxTopFindings is the number of highest-risk findings returned by Ingest.
const MaxTopFindings = 10

// Store is the subset of *store.Store the service needs (an interface for unit tests).
type Store interface {
	UpsertProject(ctx context.Context, p store.Project) (int64, error)
	RecordRun(ctx context.Context, r store.Run) (int64, error)
	UpsertArtifact(ctx context.Context, projectID, runID int64, a evidence.Artifact) (int64, error)
	AppendEvidence(ctx context.Context, in store.EvidenceInput) (store.EvidenceRecord, error)
	IngestDocument(ctx context.Context, runID, artifactID int64, doc evidence.Document) (store.IngestResult, error)
	GetFindings(ctx context.Context, ids []int64) ([]store.FindingRecord, error)
	ApplicableVEX(ctx context.Context, findingIDs []int64) (map[int64]evidence.VEXStatement, error)
	UpdateFindingRisks(ctx context.Context, updates []store.RiskUpdate) error
	AppendAudit(ctx context.Context, e store.AuditEntry) (int64, error)
}

var _ Store = (*store.Store)(nil)

// Options configures a Service.
type Options struct {
	// Store persists everything. Required.
	Store Store
	// Engine scores vulnerability findings. Nil uses risk.DefaultConfig().
	Engine *risk.Engine
	// Intel supplies KEV/EPSS data (e.g. an *intel.MemoryStore). Nil scores without intelligence
	// (flagged kev-unchecked / epss-unknown in every explanation).
	Intel risk.IntelSource
	// Exposure is the deployment exposure assumed for every artifact ("" = unknown).
	Exposure risk.Exposure
	// MaxEvidenceBytes bounds the evidence document (0 = DefaultMaxEvidenceBytes).
	MaxEvidenceBytes int64
	// Logger receives one line per ingest (never the evidence or the token). Nil discards.
	Logger *slog.Logger
}

// Service ingests CI evidence. It is safe for concurrent use.
type Service struct {
	store    Store
	engine   *risk.Engine
	intel    risk.IntelSource
	exposure risk.Exposure
	maxBytes int64
	log      *slog.Logger
}

// New validates opts and returns a Service.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("ingest: a store is required")
	}
	engine := opts.Engine
	if engine == nil {
		var err error
		if engine, err = risk.NewEngine(risk.DefaultConfig()); err != nil {
			return nil, fmt.Errorf("ingest: risk engine: %w", err)
		}
	}
	exposure, err := risk.ParseExposure(string(opts.Exposure))
	if err != nil {
		return nil, fmt.Errorf("ingest: %w", err)
	}
	maxBytes := opts.MaxEvidenceBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxEvidenceBytes
	}
	if maxBytes > store.MaxEvidenceSize {
		return nil, fmt.Errorf("ingest: max evidence size %d exceeds the store limit %d", maxBytes, store.MaxEvidenceSize)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{store: opts.Store, engine: engine, intel: opts.Intel, exposure: exposure, maxBytes: maxBytes, log: logger}, nil
}

// MaxEvidenceBytes returns the evidence size limit (the HTTP layer sizes its body limit from it).
func (s *Service) MaxEvidenceBytes() int64 { return s.maxBytes }

// Request is one evidence upload. The caller's identity comes from the verified OIDC claims, never
// from the request.
type Request struct {
	// Artifact is what the evidence describes, identified by digest (required).
	Artifact evidence.Artifact
	// Commit is the git commit the evidence was produced from; it must equal the token's sha.
	Commit string
	// Format is the evidence format; "" detects it from the content.
	Format evidence.Format
	// Evidence is the exact evidence file bytes (stored verbatim, hashed with SHA-256).
	Evidence []byte
}

// EvidenceSummary describes the stored raw evidence.
type EvidenceSummary struct {
	ID int64 `json:"id"`
	// SHA256 and Size describe the stored body; UploadSHA256 is the hash of the uploaded file
	// (they differ only for JSON streams, see StreamWrapped).
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	UploadSHA256 string `json:"uploadSha256"`
	// StreamWrapped is true when the upload was a stream of JSON values (govulncheck -json) and
	// was stored as a JSON array of those values, byte for byte, because the evidence store keeps
	// one JSON document per row.
	StreamWrapped bool            `json:"streamWrapped,omitempty"`
	Created       bool            `json:"created"`
	Format        evidence.Format `json:"format"`
	FormatVersion string          `json:"formatVersion,omitempty"`
	Tool          evidence.Tool   `json:"tool"`
}

// Counts summarizes the changes to the derived model.
type Counts struct {
	Components        int `json:"components"`
	SkippedComponents int `json:"skippedComponents"`
	Vulnerabilities   int `json:"vulnerabilities"`
	FindingsNew       int `json:"findingsNew"`
	FindingsSeen      int `json:"findingsSeen"`
	FindingsReopened  int `json:"findingsReopened"`
	FindingsFixed     int `json:"findingsFixed"`
	VEXStatements     int `json:"vexStatements"`
	VEXStatusChanges  int `json:"vexStatusChanges"`
}

// TopFinding is one of the highest-risk findings touched by an ingest.
type TopFinding struct {
	ID     int64               `json:"id"`
	VulnID string              `json:"vulnId"`
	PURL   string              `json:"purl,omitempty"`
	Status store.FindingStatus `json:"status"`
	Score  float64             `json:"score"`
	Tier   risk.Tier           `json:"tier"`
	Reason string              `json:"reason"`
}

// Result is what Ingest returns.
type Result struct {
	ProjectID  int64           `json:"projectId"`
	RunID      int64           `json:"runId"`
	ArtifactID int64           `json:"artifactId"`
	Evidence   EvidenceSummary `json:"evidence"`
	Counts     Counts          `json:"counts"`
	// Scored is the number of vulnerability findings (re-)scored by this ingest.
	Scored int `json:"scored"`
	// Tiers counts the scored findings per tier.
	Tiers map[risk.Tier]int `json:"tiers"`
	// TopFindings are the highest-risk scored findings (at most MaxTopFindings).
	TopFindings []TopFinding `json:"topFindings"`
	// Warnings are non-fatal observations (e.g. a subject digest that differs from the artifact).
	Warnings []string `json:"warnings,omitempty"`
}

var (
	digestRE = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$`)
	commitRE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

func validArtifactKind(k evidence.ArtifactKind) bool {
	switch k {
	case evidence.ArtifactContainerImage, evidence.ArtifactBinary, evidence.ArtifactSource, evidence.ArtifactSBOM:
		return true
	}
	return false
}

// ValidFormat reports whether f is a supported evidence format.
func ValidFormat(f evidence.Format) bool {
	switch f {
	case evidence.FormatCycloneDX, evidence.FormatSPDX, evidence.FormatSARIF, evidence.FormatGrype,
		evidence.FormatGovulncheck, evidence.FormatOpenVEX:
		return true
	}
	return false
}

func validName(s string) bool {
	return s != "" && len(s) <= 1024 && utf8.ValidString(s) &&
		!strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f })
}

func (s *Service) validate(claims *ghoidc.Claims, req *Request) error {
	if claims == nil {
		return fail(KindInternal, nil, "no verified identity")
	}
	a := req.Artifact
	switch {
	case !validArtifactKind(a.Kind):
		return fail(KindInvalidRequest, nil, "artifact.kind must be one of container-image, binary, source, sbom")
	case !digestRE.MatchString(a.Digest):
		return fail(KindInvalidRequest, nil, "artifact.digest must be sha256:<64 lowercase hex> or sha512:<128 lowercase hex>")
	case !validName(a.Name):
		return fail(KindInvalidRequest, nil, "artifact.name must be 1-1024 bytes of printable UTF-8")
	case !commitRE.MatchString(req.Commit):
		return fail(KindInvalidRequest, nil, "commit must be a 40 or 64 character lowercase hex git object ID")
	case req.Format != "" && !ValidFormat(req.Format):
		return fail(KindInvalidRequest, nil, "format must be one of cyclonedx, spdx, sarif, grype, govulncheck, openvex")
	case len(req.Evidence) == 0:
		return fail(KindInvalidRequest, nil, "evidence is empty")
	case int64(len(req.Evidence)) > s.maxBytes:
		return fail(KindTooLarge, nil, "evidence exceeds %d bytes", s.maxBytes)
	}
	if err := claims.CheckCommit(req.Commit); err != nil {
		return fail(KindForbidden, err, "commit does not match the token's sha claim")
	}
	return nil
}

// identity is the provenance taken from the verified token.
type identity struct {
	repoID, ownerID, runID, actorID int64
	runAttempt                      int
}

func parseIdentity(c *ghoidc.Claims) (identity, error) {
	var id identity
	var err error
	parse := func(name, v string, required bool) int64 {
		if err != nil {
			return 0
		}
		if v == "" && !required {
			return 0
		}
		n, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil || n <= 0 {
			err = fail(KindInvalidRequest, perr, "token claim %s is not a positive integer", name)
			return 0
		}
		return n
	}
	id.repoID = parse("repository_id", c.RepositoryID, true)
	id.ownerID = parse("repository_owner_id", c.RepositoryOwnerID, true)
	id.runID = parse("run_id", c.RunID, true)
	id.actorID = parse("actor_id", c.ActorID, false)
	attempt := parse("run_attempt", c.RunAttempt, false)
	if err != nil {
		return identity{}, err
	}
	id.runAttempt = int(cmp.Or(attempt, 1))
	if attempt > 1000 {
		return identity{}, fail(KindInvalidRequest, nil, "token claim run_attempt is out of range")
	}
	return id, nil
}

// Ingest stores and scores one evidence document submitted by the CI identity in claims.
func (s *Service) Ingest(ctx context.Context, claims *ghoidc.Claims, req Request) (Result, error) {
	if err := s.validate(claims, &req); err != nil {
		return Result{}, err
	}
	id, err := parseIdentity(claims)
	if err != nil {
		return Result{}, err
	}

	// 1. Parse before writing anything.
	format := req.Format
	if format == "" {
		if format, err = normalize.Detect(req.Evidence); err != nil {
			return Result{}, normalizeError(err)
		}
	}
	doc, err := normalize.ParseBytes(format, req.Evidence, normalize.Options{MaxBytes: s.maxBytes})
	if err != nil {
		return Result{}, normalizeError(err)
	}
	var warnings []string
	if doc.Subject != nil && doc.Subject.Digest != "" && !strings.EqualFold(doc.Subject.Digest, req.Artifact.Digest) {
		warnings = append(warnings, "the document's subject digest "+safeDetail(doc.Subject.Digest)+
			" differs from artifact.digest; the evidence is recorded for artifact.digest")
	}
	expandVEXProducts(doc.VEX)

	// 2. Provenance: project, run, artifact.
	projectID, err := s.store.UpsertProject(ctx, store.Project{
		RepoID: id.repoID, OwnerID: id.ownerID, RepoFullName: claims.Repository,
	})
	if err != nil {
		return Result{}, storeError("project", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return Result{}, fail(KindInternal, err, "encode claims")
	}
	runID, err := s.store.RecordRun(ctx, store.Run{
		ProjectID: projectID, RunID: id.runID, RunAttempt: id.runAttempt, SHA: strings.ToLower(claims.SHA),
		Ref: claims.Ref, Event: claims.EventName, WorkflowRef: claims.WorkflowRef, ActorID: id.actorID,
		OIDCClaims: claimsJSON,
	})
	if err != nil {
		return Result{}, storeError("run", err)
	}
	artifactID, err := s.store.UpsertArtifact(ctx, projectID, runID, req.Artifact)
	if err != nil {
		return Result{}, storeError("artifact", err)
	}

	// 3. Raw evidence (append-only, idempotent), then the derived model.
	body, wrapped, err := storableJSON(req.Evidence)
	if err != nil {
		return Result{}, fail(KindUnprocessable, err, "evidence is not a JSON document or stream")
	}
	rec, err := s.store.AppendEvidence(ctx, store.EvidenceInput{
		RunID: runID, ArtifactID: artifactID, Format: doc.Format, FormatVersion: doc.FormatVersion,
		Tool: doc.Tool, Body: body,
	})
	if err != nil {
		return Result{}, storeError("evidence", err)
	}
	ing, err := s.store.IngestDocument(ctx, runID, artifactID, *doc)
	if err != nil {
		return Result{}, storeError("document", err)
	}

	// 4. Risk.
	ids := append(slices.Clone(ing.FindingIDs), ing.ChangedFindingIDs...)
	slices.Sort(ids)
	scored, err := s.score(ctx, slices.Compact(ids))
	if err != nil {
		return Result{}, err
	}

	res := Result{
		ProjectID: projectID, RunID: runID, ArtifactID: artifactID,
		Evidence: EvidenceSummary{
			ID: rec.ID, SHA256: rec.SHA256, Size: rec.Size, Created: rec.Created,
			UploadSHA256: sha256Hex(req.Evidence), StreamWrapped: wrapped,
			Format: doc.Format, FormatVersion: doc.FormatVersion, Tool: doc.Tool,
		},
		Counts: Counts{
			Components: ing.Components, SkippedComponents: ing.SkippedComponents, Vulnerabilities: ing.Vulnerabilities,
			FindingsNew: ing.FindingsNew, FindingsSeen: ing.FindingsSeen, FindingsReopened: ing.FindingsReopened,
			FindingsFixed: ing.FindingsFixed, VEXStatements: ing.VEXStatements, VEXStatusChanges: ing.VEXStatusChanges,
		},
		Scored:      len(scored),
		Tiers:       map[risk.Tier]int{risk.TierP1: 0, risk.TierP2: 0, risk.TierP3: 0},
		TopFindings: []TopFinding{},
		Warnings:    warnings,
	}
	for _, sc := range scored {
		res.Tiers[sc.result.Tier]++
	}
	for _, sc := range scored[:min(len(scored), MaxTopFindings)] {
		res.TopFindings = append(res.TopFindings, sc.top())
	}

	// 5. Audit (after the fact: a failure here is reported, the data stays consistent).
	if err := s.audit(ctx, claims, id, req.Artifact, res); err != nil {
		return Result{}, storeError("audit", err)
	}
	s.log.LogAttrs(ctx, slog.LevelInfo, "evidence ingested",
		slog.String("repository", claims.Repository),
		slog.Int64("repository_id", id.repoID),
		slog.Int64("run_id", id.runID),
		slog.Int("run_attempt", id.runAttempt),
		slog.String("artifact_digest", req.Artifact.Digest),
		slog.String("format", string(doc.Format)),
		slog.String("evidence_sha256", rec.SHA256),
		slog.Bool("evidence_created", rec.Created),
		slog.Int("findings_new", ing.FindingsNew),
		slog.Int("findings_fixed", ing.FindingsFixed),
		slog.Int("scored", res.Scored),
		slog.Int("p1", res.Tiers[risk.TierP1]),
	)
	return res, nil
}

// storableJSON returns evidence in a form the store accepts (exactly one JSON document). A stream
// of JSON values, as written by `govulncheck -json`, becomes a JSON array whose elements are the
// original values byte for byte; a single document is returned unchanged.
func storableJSON(b []byte) ([]byte, bool, error) {
	if json.Valid(b) {
		return b, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var out bytes.Buffer
	out.Grow(len(b) + 2)
	out.WriteByte('[')
	for n := 0; ; n++ {
		var v json.RawMessage
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, err
		}
		if n > 0 {
			out.WriteByte(',')
		}
		out.Write(v)
	}
	out.WriteByte(']')
	return out.Bytes(), true, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// expandVEXProducts adds the forms under which the store can match a VEX product: the canonical
// package URL (govulncheck writes "pkg:golang/golang.org%2Fx%2Ftext@v0.3.7" while scanners write
// "…/golang.org/x/text@v0.3.7") and, for "pkg:oci/…@sha256%3A…" image references, the bare
// digest, which the store compares with the artifact digest. Original products are kept.
func expandVEXProducts(stmts []evidence.VEXStatement) {
	for i := range stmts {
		products := stmts[i].Products
		for _, p := range products {
			p = strings.TrimSpace(p)
			if !strings.HasPrefix(p, "pkg:") {
				continue
			}
			for _, extra := range []string{normalize.CanonicalPURL(p), ociDigest(p)} {
				if extra != "" && !slices.Contains(products, extra) {
					products = append(products, extra)
				}
			}
		}
		stmts[i].Products = products
	}
}

// ociDigest returns the digest of a "pkg:oci/name@sha256%3A<hex>" package URL, or "".
func ociDigest(purl string) string {
	if !strings.HasPrefix(strings.ToLower(purl), "pkg:oci/") {
		return ""
	}
	_, version, ok := strings.CutLast(purl, "@")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(version, "?#"); i >= 0 {
		version = version[:i]
	}
	v, err := url.PathUnescape(version)
	if err != nil {
		return ""
	}
	v = strings.ToLower(v)
	if !digestRE.MatchString(v) {
		return ""
	}
	return v
}

func normalizeError(err error) error {
	detail := safeDetail(err.Error())
	switch {
	case errors.Is(err, normalize.ErrTooLarge), errors.Is(err, normalize.ErrLimitExceeded):
		return fail(KindTooLarge, err, "%s", detail)
	default:
		return fail(KindUnprocessable, err, "%s", detail)
	}
}

// storeError maps store errors to kinds. Validation messages written by the store's Go code are
// shown to the caller; database messages (which name tables and constraints) are not.
func storeError(step string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fail(KindInternal, err, "request cancelled while storing the %s", step)
	}
	detail := safeDetail(strings.TrimPrefix(err.Error(), "store: "))
	if strings.Contains(detail, "SQLSTATE") {
		detail = "the " + step + " was rejected by the database"
	}
	switch {
	case errors.Is(err, store.ErrInvalidInput):
		return fail(KindUnprocessable, err, "%s", detail)
	case errors.Is(err, store.ErrConflict):
		return fail(KindConflict, err, "%s", detail)
	case errors.Is(err, store.ErrNotFound):
		return fail(KindConflict, err, "%s", detail)
	default:
		return fail(KindInternal, err, "storing the %s failed", step)
	}
}

func (s *Service) audit(ctx context.Context, c *ghoidc.Claims, id identity, a evidence.Artifact, res Result) error {
	details, err := json.Marshal(map[string]any{
		"repository":       c.Repository,
		"run_id":           id.runID,
		"run_attempt":      id.runAttempt,
		"sha":              c.SHA,
		"ref":              c.Ref,
		"event_name":       c.EventName,
		"workflow_ref":     c.WorkflowRef,
		"job_workflow_ref": c.JobWorkflowRef,
		"actor_id":         c.ActorID,
		"artifact_id":      res.ArtifactID,
		"artifact_kind":    a.Kind,
		"evidence_id":      res.Evidence.ID,
		"evidence_sha256":  res.Evidence.SHA256,
		"evidence_created": res.Evidence.Created,
		"format":           res.Evidence.Format,
		"tool":             res.Evidence.Tool,
		"counts":           res.Counts,
		"scored":           res.Scored,
		"tiers":            res.Tiers,
	})
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	_, err = s.store.AppendAudit(ctx, store.AuditEntry{
		Actor:     "github-repo:" + strconv.FormatInt(id.repoID, 10),
		Action:    "evidence.ingest",
		Target:    "artifact:" + a.Digest,
		ProjectID: res.ProjectID,
		Details:   details,
	})
	return err
}
