package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/store"
)

// FindingsReader reads stored findings (internal/store.Store).
type FindingsReader interface {
	ListFindings(ctx context.Context, f store.FindingFilter) (store.FindingPage, error)
	GetFinding(ctx context.Context, id int64) (store.FindingRecord, error)
}

// readAPI guards the read-only findings API. In Phase 2 it has no user authentication, so it is
// off by default and, when enabled with AEGISFLOW_DEV_READONLY_API=true, answers loopback clients
// only (the address of the TCP peer; forwarding headers are not trusted). Phase 4 puts it behind
// Azure Container Apps authentication with Entra ID.
func (s *Server) readAPI(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !s.cfg.DevReadOnlyAPI:
			writeProblem(w, r, http.StatusNotFound, "No API resource matches this path.")
		case !loopbackPeer(r.RemoteAddr):
			writeProblem(w, r, http.StatusForbidden, "The development read API only answers loopback clients.")
		case s.findings == nil:
			writeProblem(w, r, http.StatusServiceUnavailable, "Persistence is not configured on this server.")
		default:
			next(w, r)
		}
	})
}

func loopbackPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// Query parameters accepted by GET /api/v1/findings.
var findingQueryParams = map[string]bool{"tier": true, "status": true, "kind": true, "artifact": true, "limit": true, "cursor": true}

var (
	validTiers    = map[string]bool{"P1": true, "P2": true, "P3": true}
	validStatuses = map[string]bool{"open": true, "fixed": true, "vex_not_affected": true, "accepted": true}
	validKinds    = map[string]bool{"vulnerability": true, "code": true, "secret": true, "config": true, "dast": true}
)

// parseFindingFilter validates the query string of GET /api/v1/findings.
func parseFindingFilter(q url.Values) (store.FindingFilter, string) {
	var f store.FindingFilter
	for k, v := range q {
		if !findingQueryParams[k] {
			return f, "Unknown query parameter " + strconv.Quote(truncate(k, 64)) + "."
		}
		if len(v) != 1 {
			return f, "Query parameter " + k + " must appear once."
		}
	}
	if v := q.Get("tier"); v != "" {
		if !validTiers[v] {
			return f, "tier must be P1, P2 or P3."
		}
		f.Tier = store.RiskTier(v)
	}
	if v := q.Get("status"); v != "" {
		if !validStatuses[v] {
			return f, "status must be open, fixed, vex_not_affected or accepted."
		}
		f.Status = store.FindingStatus(v)
	}
	if v := q.Get("kind"); v != "" {
		if !validKinds[v] {
			return f, "kind must be vulnerability, code, secret, config or dast."
		}
		f.Kind = evidence.FindingKind(v)
	}
	if v := q.Get("artifact"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			return f, "artifact must be a positive artifact ID."
		}
		f.ArtifactID = id
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > store.MaxPageSize {
			return f, "limit must be between 1 and " + strconv.Itoa(store.MaxPageSize) + "."
		}
		f.Limit = n
	}
	f.Cursor = q.Get("cursor")
	return f, ""
}

// findingsPage is the body of GET /api/v1/findings.
type findingsPage struct {
	Findings []findingJSON `json:"findings"`
	// NextCursor continues the listing (pass it as ?cursor=); "" on the last page.
	NextCursor string `json:"nextCursor"`
}

type componentJSON struct {
	PURL      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Direct    bool   `json:"direct"`
}

type vulnerabilityJSON struct {
	ID        string          `json:"id"`
	Aliases   []string        `json:"aliases"`
	Summary   string          `json:"summary,omitempty"`
	Severity  string          `json:"severity"`
	CVSS      []evidence.CVSS `json:"cvss,omitempty"`
	CWEs      []string        `json:"cwes,omitempty"`
	Published *time.Time      `json:"published,omitempty"`
}

type riskJSON struct {
	Score    float64   `json:"score"`
	Tier     string    `json:"tier"`
	Action   string    `json:"action"`
	Reason   string    `json:"reason"`
	Flags    []string  `json:"flags"`
	ScoredAt time.Time `json:"scoredAt"`
	// Explanation is the risk engine's full result (factors table); detail view only.
	Explanation json.RawMessage `json:"explanation,omitempty"`
}

type findingJSON struct {
	ID            int64              `json:"id"`
	ArtifactID    int64              `json:"artifactId"`
	Kind          string             `json:"kind"`
	Title         string             `json:"title"`
	Message       string             `json:"message,omitempty"`
	Severity      string             `json:"severity"`
	Status        string             `json:"status"`
	RuleID        string             `json:"ruleId,omitempty"`
	Tools         []string           `json:"tools"`
	Vulnerability *vulnerabilityJSON `json:"vulnerability"`
	Component     *componentJSON     `json:"component"`
	FixedVersions []string           `json:"fixedVersions"`
	Reachability  string             `json:"reachability"`
	Location      *evidence.Location `json:"location,omitempty"`
	Risk          *riskJSON          `json:"risk"`
	FirstSeenRun  int64              `json:"firstSeenRun"`
	LastSeenRun   int64              `json:"lastSeenRun"`
	UpdatedAt     time.Time          `json:"updatedAt"`
}

// riskSummary is the part of a stored risk explanation (risk.Result) shown in listings.
type riskSummary struct {
	Action string   `json:"action"`
	Reason string   `json:"reason"`
	Flags  []string `json:"flags"`
}

func toFindingJSON(r store.FindingRecord, detail bool) findingJSON {
	f := r.Finding
	out := findingJSON{
		ID: r.ID, ArtifactID: r.ArtifactID, Kind: string(f.Kind), Title: f.Title, Severity: string(f.Severity),
		Status: string(r.Status), RuleID: f.RuleID, Tools: make([]string, 0, len(f.Tools)),
		FixedVersions: f.FixedVersions, Reachability: string(f.Reachability), Location: f.Location,
		FirstSeenRun: r.FirstSeenRun, LastSeenRun: r.LastSeenRun, UpdatedAt: r.UpdatedAt,
	}
	if out.FixedVersions == nil {
		out.FixedVersions = []string{}
	}
	if out.Reachability == "" && f.Kind == evidence.FindingVulnerability {
		out.Reachability = string(evidence.ReachabilityUnknown)
	}
	for _, t := range f.Tools {
		out.Tools = append(out.Tools, t.Name)
	}
	if detail {
		out.Message = f.Message
	}
	if c := f.Component; c != nil {
		out.Component = &componentJSON{PURL: c.PURL, Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, Direct: c.Direct}
	}
	if v := f.Vulnerability; v != nil {
		vj := &vulnerabilityJSON{ID: v.ID, Aliases: v.Aliases, Severity: string(v.Severity)}
		if vj.Aliases == nil {
			vj.Aliases = []string{}
		}
		if detail {
			vj.Summary, vj.CVSS, vj.CWEs = v.Summary, v.CVSS, v.CWEs
			if !v.Published.IsZero() {
				p := v.Published
				vj.Published = &p
			}
		}
		out.Vulnerability = vj
	}
	if rk := r.Risk; rk != nil {
		rj := &riskJSON{Score: rk.Score, Tier: string(rk.Tier), ScoredAt: rk.ScoredAt, Flags: []string{}}
		var sum riskSummary
		if json.Unmarshal(rk.Explanation, &sum) == nil {
			rj.Action, rj.Reason = sum.Action, sum.Reason
			if sum.Flags != nil {
				rj.Flags = sum.Flags
			}
		}
		if detail {
			rj.Explanation = rk.Explanation
		}
		out.Risk = rj
	}
	return out
}

// handleListFindings serves GET /api/v1/findings: findings ordered by risk (highest first,
// unscored last), keyset-paginated.
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	filter, problemDetail := parseFindingFilter(r.URL.Query())
	if problemDetail != "" {
		writeProblem(w, r, http.StatusBadRequest, problemDetail)
		return
	}
	page, err := s.findings.ListFindings(r.Context(), filter)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	out := findingsPage{Findings: make([]findingJSON, 0, len(page.Findings)), NextCursor: page.NextCursor}
	for _, rec := range page.Findings {
		out.Findings = append(out.Findings, toFindingJSON(rec, false))
	}
	writeJSON(w, http.StatusOK, contentTypeJSON, out)
}

// handleGetFinding serves GET /api/v1/findings/{id} with the full risk explanation.
func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeProblem(w, r, http.StatusNotFound, "No finding matches this ID.")
		return
	}
	rec, err := s.findings.GetFinding(r.Context(), id)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, contentTypeJSON, toFindingJSON(rec, true))
}

func (s *Server) readFailed(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "No finding matches this ID.")
	case errors.Is(err, store.ErrInvalidInput):
		writeProblem(w, r, http.StatusBadRequest, "Invalid filter or cursor.")
	default:
		s.logger.ErrorContext(r.Context(), "findings query failed", "error", err.Error(),
			"request_id", RequestIDFromContext(r.Context()))
		writeProblem(w, r, http.StatusInternalServerError, "An unexpected error occurred.")
	}
}
