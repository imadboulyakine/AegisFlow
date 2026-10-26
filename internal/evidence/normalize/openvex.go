package normalize

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// openVEXContext is the only OpenVEX context (specification version) accepted.
const openVEXContext = "https://openvex.dev/ns/v0.2.0"

// openVEXJustifications are the OpenVEX 0.2.0 justification labels.
var openVEXJustifications = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

type openVEXDocument struct {
	Context    string             `json:"@context"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Tooling    string             `json:"tooling"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability struct {
		ID      string   `json:"@id"`
		Name    string   `json:"name"`
		Aliases []string `json:"aliases"`
	} `json:"vulnerability"`
	Products        []openVEXProduct `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification"`
	ImpactStatement string           `json:"impact_statement"`
	Timestamp       string           `json:"timestamp"`
}

type openVEXComponent struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers"`
	Hashes      map[string]string `json:"hashes"`
}

type openVEXProduct struct {
	openVEXComponent
	Subcomponents []openVEXComponent `json:"subcomponents"`
}

// parseOpenVEX normalizes an OpenVEX 0.2.0 document into VEX statements. Statements are validated
// strictly because a VEX "not_affected" suppresses risk: an unknown status or justification, a
// not_affected statement without justification or impact statement, a statement without
// products or an invalid timestamp rejects the whole document.
//
//   - VulnID is canonicalized like Vulnerability.ID (the first CVE among name/@id and aliases),
//     so statements match findings by ID;
//   - Products lists each product identifier (@id, else identifiers.purl, else the sha-256 or
//     sha-512 hash as a digest) followed by its subcomponent identifiers. The model has no
//     product/subcomponent nesting, so consumers must scope statements to the artifact the VEX
//     document was ingested for;
//   - Author is the document author; Timestamp the statement timestamp, else the document's.
func parseOpenVEX(data []byte, b *builder) error {
	var doc openVEXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return invalidf("decode: %v", err)
	}
	if strings.TrimSuffix(doc.Context, "/") != openVEXContext {
		return unsupportedVersion("@context", doc.Context)
	}
	b.doc.FormatVersion = "0.2.0"
	b.doc.Tool = evidence.Tool{Name: firstNonEmpty(strings.TrimSpace(doc.Tooling), "openvex")}
	docTime, hasDocTime := parseTime(doc.Timestamp)
	if doc.Timestamp != "" && !hasDocTime {
		return invalidf("document timestamp is not RFC 3339")
	}
	for i := range doc.Statements {
		stmt, err := openVEXStatementFor(&doc.Statements[i], doc.Author, docTime)
		if err != nil {
			return fmt.Errorf("statement %d: %w", i, err)
		}
		if err := b.addVEX(stmt); err != nil {
			return fmt.Errorf("statement %d: %w", i, err)
		}
	}
	return nil
}

func openVEXStatementFor(s *openVEXStatement, author string, docTime time.Time) (evidence.VEXStatement, error) {
	primary := firstNonEmpty(strings.TrimSpace(s.Vulnerability.Name), vulnIDFromIRI(strings.TrimSpace(s.Vulnerability.ID)))
	if primary == "" {
		return evidence.VEXStatement{}, invalidf("vulnerability name or @id is required")
	}
	vulnID, _ := canonicalVulnID(primary, s.Vulnerability.Aliases)

	status := evidence.VEXStatus(s.Status)
	switch status {
	case evidence.VEXNotAffected, evidence.VEXAffected, evidence.VEXFixed, evidence.VEXUnderInvestigation:
	default:
		return evidence.VEXStatement{}, invalidf("unknown status %q", clip(s.Status, 64))
	}
	if s.Justification != "" && !openVEXJustifications[s.Justification] {
		return evidence.VEXStatement{}, invalidf("unknown justification %q", clip(s.Justification, 64))
	}
	impact := strings.TrimSpace(s.ImpactStatement)
	if status == evidence.VEXNotAffected && s.Justification == "" && impact == "" {
		return evidence.VEXStatement{}, invalidf("not_affected requires a justification or an impact_statement")
	}

	var products []string
	for i := range s.Products {
		p := &s.Products[i]
		id, err := openVEXIdentifier(&p.openVEXComponent)
		if err != nil {
			return evidence.VEXStatement{}, fmt.Errorf("product %d: %w", i, err)
		}
		products = appendUnique(products, id)
		for j := range p.Subcomponents {
			sid, err := openVEXIdentifier(&p.Subcomponents[j])
			if err != nil {
				return evidence.VEXStatement{}, fmt.Errorf("product %d subcomponent %d: %w", i, j, err)
			}
			products = appendUnique(products, sid)
		}
	}
	if len(products) == 0 {
		return evidence.VEXStatement{}, invalidf("at least one product is required")
	}

	ts := docTime
	if s.Timestamp != "" {
		t, ok := parseTime(s.Timestamp)
		if !ok {
			return evidence.VEXStatement{}, invalidf("timestamp is not RFC 3339")
		}
		ts = t
	}
	return evidence.VEXStatement{
		VulnID:          vulnID,
		Products:        products,
		Status:          status,
		Justification:   s.Justification,
		ImpactStatement: clip(impact, maxMessageLen),
		Author:          clip(strings.TrimSpace(author), maxTitleLen),
		Timestamp:       ts,
	}, nil
}

// openVEXIdentifier returns the component's identifier: @id, else identifiers.purl, else a
// digest from hashes (sha-256, then sha-512).
func openVEXIdentifier(c *openVEXComponent) (string, error) {
	if id := strings.TrimSpace(c.ID); id != "" {
		return id, nil
	}
	if p := strings.TrimSpace(c.Identifiers["purl"]); p != "" {
		return p, nil
	}
	for _, alg := range []string{"sha-256", "sha-512"} {
		if h := c.Hashes[alg]; h != "" {
			if d, ok := digestFromChecksum(alg, h); ok {
				return d, nil
			}
		}
	}
	return "", invalidf("component has no @id, purl identifier or supported hash")
}
