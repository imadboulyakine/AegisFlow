package store

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// Per-document limits. Identity fields (package URL, vulnerability ID, fingerprint, VEX product)
// that break their limits are rejected; descriptive text is cleaned and truncated instead.
const (
	maxDocComponents = 200_000 // SBOM components + finding packages
	maxDocFindings   = 100_000
	maxDocVEX        = 50_000 // statement × product pairs
	maxListItems     = 64     // aliases, CWEs, licences, fixed versions
	maxToolsPerItem  = 32
	maxCVSSPerVuln   = 16
)

var (
	purlRE   = regexp.MustCompile(`^pkg:[A-Za-z][A-Za-z0-9.+-]*/`)
	vulnIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]*$`)
)

func validPURL(p string) bool        { return boundedText(p, 5, 2048) && purlRE.MatchString(p) }
func validVulnID(id string) bool     { return len(id) <= 128 && vulnIDRE.MatchString(id) }
func validFingerprint(s string) bool { return boundedText(s, 1, 256) }

// preparedDoc is a validated, cleaned, de-duplicated and deterministically ordered document,
// ready for set-based upserts. Rows are sorted by their natural key so that concurrent
// transactions lock shared rows (components, vulnerabilities) in the same order.
type preparedDoc struct {
	tools             []string // tool names whose absence marks findings fixed (sorted)
	components        []componentRow
	vulns             []vulnRow
	findings          []findingRow
	vex               []vexRow
	skippedComponents int
}

type componentRow struct {
	PURL      string   `json:"purl"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	Licenses  []string `json:"licenses"`
	Direct    bool     `json:"-"`
}

type vulnRow struct {
	VulnID    string          `json:"vuln_id"`
	Aliases   []string        `json:"aliases"`
	Summary   string          `json:"summary"`
	Severity  string          `json:"severity"`
	CVSS      []evidence.CVSS `json:"cvss"`
	CWEs      []string        `json:"cwes"`
	Published *time.Time      `json:"published"`
}

type findingRow struct {
	Fingerprint     string   `json:"fingerprint"`
	Kind            string   `json:"kind"`
	Title           string   `json:"title"`
	Message         string   `json:"message"`
	Severity        string   `json:"severity"`
	RuleID          string   `json:"rule_id"`
	Tools           []string `json:"tools"`
	ComponentID     *int64   `json:"component_id"`
	VulnerabilityID *int64   `json:"vulnerability_id"`
	FixedVersions   []string `json:"fixed_versions"`
	Reachability    *string  `json:"reachability"`
	LocationPath    *string  `json:"location_path"`
	LocationStart   *int32   `json:"location_start_line"`
	LocationEnd     *int32   `json:"location_end_line"`

	purl   string // resolved to ComponentID inside the transaction
	vulnID string // resolved to VulnerabilityID inside the transaction
}

type vexRow struct {
	VulnID          string     `json:"vuln_id"`
	Product         string     `json:"product"`
	Status          string     `json:"status"`
	Justification   string     `json:"justification"`
	ImpactStatement string     `json:"impact_statement"`
	Author          string     `json:"author"`
	StatementTime   *time.Time `json:"statement_time"`
	DedupKey        string     `json:"dedup_key"`
}

func validFindingKind(k evidence.FindingKind) bool {
	switch k {
	case evidence.FindingVulnerability, evidence.FindingCode, evidence.FindingSecret, evidence.FindingConfig, evidence.FindingDAST:
		return true
	}
	return false
}

func validReachability(r evidence.Reachability) bool {
	switch r {
	case evidence.ReachabilityUnknown, evidence.ReachabilityCalled, evidence.ReachabilityImported:
		return true
	}
	return false
}

func reachabilityRank(r *string) int {
	if r == nil {
		return 0
	}
	switch evidence.Reachability(*r) {
	case evidence.ReachabilityCalled:
		return 3
	case evidence.ReachabilityImported:
		return 2
	default:
		return 1
	}
}

func validVEXStatus(s evidence.VEXStatus) bool {
	switch s {
	case evidence.VEXNotAffected, evidence.VEXAffected, evidence.VEXFixed, evidence.VEXUnderInvestigation:
		return true
	}
	return false
}

// OpenVEX 0.2.0 justifications for not_affected.
var vexJustifications = map[string]bool{
	"":                                    true,
	"component_not_present":               true,
	"vulnerable_code_not_present":         true,
	"vulnerable_code_not_in_execute_path": true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

// normSeverity coerces a severity to one of the canonical values (unknown spellings → unknown).
func normSeverity(s evidence.Severity) string { return string(evidence.ParseSeverity(string(s))) }

// sortedList cleans, de-duplicates, caps and sorts (byte order, like aegisflow_text_union).
func sortedList(items []string, maxBytes int) []string {
	out := cleanList(items, maxBytes, maxListItems)
	slices.Sort(out)
	return out
}

// mergeLists unions two sorted lists into a sorted, de-duplicated, capped list.
func mergeLists(a, b []string) []string {
	out := slices.Concat(a, b)
	slices.Sort(out)
	return capList(slices.Compact(out), maxListItems)
}

// capList returns at most n leading elements of list.
// The result is never nil, so it encodes as a JSON array (the columns are NOT NULL).
func capList(list []string, n int) []string {
	if list == nil {
		return []string{}
	}
	return list[:min(len(list), n)]
}

// utcMicro normalizes a timestamp to UTC microseconds (PostgreSQL precision); zero → nil.
func utcMicro(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC().Truncate(time.Microsecond)
	return &u
}

// prepareDocument validates and normalizes a document. It performs no I/O.
func prepareDocument(doc evidence.Document) (*preparedDoc, error) {
	if !validFormat(doc.Format) {
		return nil, invalid("document: unknown format %q", doc.Format)
	}
	docTool := normalizeToolName(doc.Tool.Name)
	if !boundedText(docTool, 1, 128) {
		return nil, invalid("document: tool name must be 1-128 bytes of valid UTF-8")
	}
	switch {
	case len(doc.Components) > maxDocComponents:
		return nil, invalid("document: %d components exceed the limit of %d", len(doc.Components), maxDocComponents)
	case len(doc.Findings) > maxDocFindings:
		return nil, invalid("document: %d findings exceed the limit of %d", len(doc.Findings), maxDocFindings)
	case len(doc.VEX) > maxDocVEX:
		return nil, invalid("document: %d VEX statements exceed the limit of %d", len(doc.VEX), maxDocVEX)
	}

	p := &preparedDoc{}
	comps := map[string]*componentRow{}
	addComponent := func(c evidence.Component) (string, bool) {
		purl := strings.TrimSpace(c.PURL)
		if !validPURL(purl) {
			p.skippedComponents++
			return "", false
		}
		eco := strings.ToLower(cleanText(c.Ecosystem, 64))
		if eco == "" {
			eco = cleanText(evidence.EcosystemFromPURL(purl), 64)
		}
		row := componentRow{
			PURL: purl, Name: cleanText(c.Name, 512), Version: cleanText(c.Version, 256),
			Ecosystem: eco, Licenses: sortedList(c.Licenses, 256), Direct: c.Direct,
		}
		if old, ok := comps[purl]; ok {
			old.Name = cmp.Or(old.Name, row.Name)
			old.Version = cmp.Or(old.Version, row.Version)
			old.Ecosystem = cmp.Or(old.Ecosystem, row.Ecosystem)
			old.Licenses = mergeLists(old.Licenses, row.Licenses)
			old.Direct = old.Direct || row.Direct
			return purl, true
		}
		if len(comps) >= maxDocComponents {
			p.skippedComponents++
			return "", false
		}
		comps[purl] = &row
		return purl, true
	}
	for _, c := range doc.Components {
		addComponent(c)
	}

	vulns := map[string]*vulnRow{}
	addVuln := func(v evidence.Vulnerability) {
		row := vulnRow{
			VulnID: v.ID, Summary: cleanText(v.Summary, 4096), Severity: normSeverity(v.Severity),
			CWEs: sortedList(v.CWEs, 64), Published: utcMicro(v.Published),
		}
		aliases := make([]string, 0, len(v.Aliases))
		for _, a := range v.Aliases {
			if a = strings.TrimSpace(a); a != v.ID && validVulnID(a) {
				aliases = append(aliases, a)
			}
		}
		row.Aliases = sortedList(aliases, 128)
		row.CVSS = cleanCVSS(v.CVSS, nil)
		if old, ok := vulns[v.ID]; ok {
			old.Aliases = mergeLists(old.Aliases, row.Aliases)
			old.Summary = cmp.Or(old.Summary, row.Summary)
			if evidence.Severity(row.Severity).Rank() > evidence.Severity(old.Severity).Rank() {
				old.Severity = row.Severity
			}
			old.CVSS = cleanCVSS(row.CVSS, old.CVSS)
			old.CWEs = mergeLists(old.CWEs, row.CWEs)
			if row.Published != nil && (old.Published == nil || row.Published.Before(*old.Published)) {
				old.Published = row.Published
			}
			return
		}
		vulns[v.ID] = &row
	}

	toolSet := map[string]bool{docTool: true}
	findings := map[string]*findingRow{}
	for i, f := range doc.Findings {
		row, err := prepareFinding(i, f, docTool)
		if err != nil {
			return nil, err
		}
		for _, t := range row.Tools {
			toolSet[t] = true
		}
		if f.Component != nil {
			if purl, ok := addComponent(*f.Component); ok {
				row.purl = purl
			}
		}
		if f.Vulnerability != nil {
			addVuln(*f.Vulnerability)
			row.vulnID = f.Vulnerability.ID
		}
		if old, ok := findings[row.Fingerprint]; ok {
			mergeFinding(old, row)
			continue
		}
		findings[row.Fingerprint] = row
	}

	vex := map[string]vexRow{}
	for i, st := range doc.VEX {
		rows, err := prepareVEX(i, st)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			vex[r.DedupKey] = r
		}
		if len(vex) > maxDocVEX {
			return nil, invalid("document: more than %d VEX statement/product pairs", maxDocVEX)
		}
	}

	p.tools = slices.Sorted(maps.Keys(toolSet))
	p.components = sortedValues(comps, func(r *componentRow) string { return r.PURL })
	p.vulns = sortedValues(vulns, func(r *vulnRow) string { return r.VulnID })
	p.findings = sortedValues(findings, func(r *findingRow) string { return r.Fingerprint })
	p.vex = make([]vexRow, 0, len(vex))
	for _, k := range slices.Sorted(maps.Keys(vex)) {
		p.vex = append(p.vex, vex[k])
	}
	return p, nil
}

// prepareFinding validates one finding (index i, for error messages) and cleans its fields.
func prepareFinding(i int, f evidence.Finding, docTool string) (*findingRow, error) {
	fp := strings.TrimSpace(f.Fingerprint)
	switch {
	case !validFingerprint(fp):
		return nil, invalid("finding %d: fingerprint must be 1-256 bytes of valid UTF-8", i)
	case !validFindingKind(f.Kind):
		return nil, invalid("finding %d: unknown kind %q", i, f.Kind)
	case f.Kind == evidence.FindingVulnerability && f.Vulnerability == nil:
		return nil, invalid("finding %d: vulnerability finding without a vulnerability", i)
	case f.Vulnerability != nil && !validVulnID(f.Vulnerability.ID):
		return nil, invalid("finding %d: invalid vulnerability ID", i)
	case f.Reachability != "" && !validReachability(f.Reachability):
		return nil, invalid("finding %d: unknown reachability %q", i, f.Reachability)
	}
	row := &findingRow{
		Fingerprint: fp, Kind: string(f.Kind), Title: cleanText(f.Title, 1024),
		Message: cleanText(f.Message, 16384), Severity: normSeverity(f.Severity), RuleID: cleanText(f.RuleID, 256),
		FixedVersions: sortedList(f.FixedVersions, 256),
	}
	tools := []string{docTool}
	for _, t := range f.Tools {
		if n := normalizeToolName(t.Name); boundedText(n, 1, 128) {
			tools = append(tools, n)
		}
	}
	slices.Sort(tools)
	row.Tools = capList(slices.Compact(tools), maxToolsPerItem)
	if f.Reachability != "" {
		r := string(f.Reachability)
		row.Reachability = &r
	}
	if f.Location != nil {
		if path := cleanText(f.Location.Path, 4096); path != "" {
			row.LocationPath = &path
			row.LocationStart = lineNumber(f.Location.StartLine)
			row.LocationEnd = lineNumber(f.Location.EndLine)
		}
	}
	return row, nil
}

// lineNumber maps a source line to an int4 column value; 0 or out of range → NULL.
func lineNumber(n int) *int32 {
	if n <= 0 || n > math.MaxInt32 {
		return nil
	}
	v := int32(n)
	return &v
}

// mergeFinding folds a duplicate (same fingerprint) into dst with order-independent rules where
// possible: set unions, maximum severity and most specific reachability; first non-empty text.
func mergeFinding(dst, src *findingRow) {
	dst.Title = cmp.Or(dst.Title, src.Title)
	dst.Message = cmp.Or(dst.Message, src.Message)
	dst.RuleID = cmp.Or(dst.RuleID, src.RuleID)
	if evidence.Severity(src.Severity).Rank() > evidence.Severity(dst.Severity).Rank() {
		dst.Severity = src.Severity
	}
	dst.Tools = capList(mergeLists(dst.Tools, src.Tools), maxToolsPerItem)
	dst.FixedVersions = mergeLists(dst.FixedVersions, src.FixedVersions)
	if reachabilityRank(src.Reachability) > reachabilityRank(dst.Reachability) {
		dst.Reachability = src.Reachability
	}
	if dst.LocationPath == nil {
		dst.LocationPath, dst.LocationStart, dst.LocationEnd = src.LocationPath, src.LocationStart, src.LocationEnd
	}
	dst.purl = cmp.Or(dst.purl, src.purl)
	dst.vulnID = cmp.Or(dst.vulnID, src.vulnID)
}

// cleanCVSS appends valid, distinct ratings from add to base (capped), dropping NaN/out-of-range
// scores that would break JSON encoding or the risk formula.
func cleanCVSS(add, base []evidence.CVSS) []evidence.CVSS {
	out := slices.Clone(base)
	if out == nil {
		out = []evidence.CVSS{}
	}
	for _, c := range add {
		if len(out) == maxCVSSPerVuln {
			break
		}
		if math.IsNaN(c.BaseScore) || c.BaseScore < 0 || c.BaseScore > 10 {
			continue
		}
		c.Version = cleanText(c.Version, 8)
		c.Vector = cleanText(c.Vector, 256)
		if c.Version == "" || slices.Contains(out, c) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// prepareVEX expands a statement into one row per product.
func prepareVEX(i int, st evidence.VEXStatement) ([]vexRow, error) {
	vulnID := strings.TrimSpace(st.VulnID)
	switch {
	case !validVulnID(vulnID):
		return nil, invalid("vex statement %d: invalid vulnerability ID", i)
	case !validVEXStatus(st.Status):
		return nil, invalid("vex statement %d: unknown status %q", i, st.Status)
	case !vexJustifications[st.Justification]:
		return nil, invalid("vex statement %d: unknown justification %q", i, st.Justification)
	case len(st.Products) == 0:
		return nil, invalid("vex statement %d: no products", i)
	case len(st.Products) > maxDocVEX:
		return nil, invalid("vex statement %d: too many products", i)
	}
	base := vexRow{
		VulnID: vulnID, Status: string(st.Status), Justification: st.Justification,
		ImpactStatement: cleanText(st.ImpactStatement, 4096), Author: cleanText(st.Author, 512),
		StatementTime: utcMicro(st.Timestamp),
	}
	rows := make([]vexRow, 0, len(st.Products))
	for _, product := range st.Products {
		product = strings.TrimSpace(product)
		if !boundedText(product, 1, 2048) {
			return nil, invalid("vex statement %d: product must be 1-2048 bytes of valid UTF-8", i)
		}
		r := base
		r.Product = product
		r.DedupKey = vexDedupKey(r)
		rows = append(rows, r)
	}
	return rows, nil
}

// vexDedupKey hashes a statement's identifying fields; NUL separators are unambiguous because no
// field can contain NUL after validation and cleaning.
func vexDedupKey(r vexRow) string {
	ts := ""
	if r.StatementTime != nil {
		ts = r.StatementTime.Format(time.RFC3339Nano)
	}
	h := sha256.New()
	for _, f := range []string{r.VulnID, r.Product, r.Status, r.Justification, r.ImpactStatement, r.Author, ts} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedValues[T any](m map[string]*T, key func(*T) string) []T {
	out := make([]T, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	slices.SortFunc(out, func(a, b T) int { return strings.Compare(key(&a), key(&b)) })
	return out
}
