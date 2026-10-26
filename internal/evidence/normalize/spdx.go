package normalize

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// spdxSupportedVersions are the SPDX JSON versions accepted. SPDX 2.2 is structurally identical
// for the fields used here; SPDX 3 (JSON-LD) is a different model and is not supported.
var spdxSupportedVersions = map[string]bool{"SPDX-2.2": true, "SPDX-2.3": true}

type spdxDocument struct {
	SPDXVersion  string `json:"spdxVersion"`
	SPDXID       string `json:"SPDXID"`
	CreationInfo *struct {
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
	DocumentDescribes []string           `json:"documentDescribes"`
}

type spdxPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	Checksums        []struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksums"`
	ExternalRefs []struct {
		ReferenceType    string `json:"referenceType"`
		ReferenceLocator string `json:"referenceLocator"`
	} `json:"externalRefs"`
	PrimaryPackagePurpose string `json:"primaryPackagePurpose"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Related string `json:"relatedSpdxElement"`
	Type    string `json:"relationshipType"`
}

// parseSPDX normalizes an SPDX 2.2/2.3 JSON document.
//
//   - creationInfo.creators "Tool: <name>-<version>" → Document.Tool;
//   - the package the document DESCRIBES (relationship, DESCRIBED_BY or documentDescribes) →
//     Subject (digest from a pkg:oci PURL or a SHA-256/384/512 checksum);
//   - other packages with a "purl" external reference → Components, with licenseConcluded and
//     licenseDeclared (NOASSERTION/NONE dropped);
//   - DEPENDS_ON / *DEPENDENCY_OF relationships → Component.Direct.
func parseSPDX(data []byte, b *builder) error {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return invalidf("decode: %v", err)
	}
	if !spdxSupportedVersions[doc.SPDXVersion] {
		return unsupportedVersion("spdxVersion", doc.SPDXVersion)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		return invalidf("SPDXID must be \"SPDXRef-DOCUMENT\"")
	}
	b.doc.FormatVersion = strings.TrimPrefix(doc.SPDXVersion, "SPDX-")
	if doc.CreationInfo != nil {
		b.doc.Tool = spdxTool(doc.CreationInfo.Creators)
	}

	byID := make(map[string]*spdxPackage, len(doc.Packages))
	for i := range doc.Packages {
		p := &doc.Packages[i]
		if p.SPDXID == "" || p.Name == "" {
			return invalidf("package %d: missing SPDXID or name", i)
		}
		byID[p.SPDXID] = p
	}

	described := append([]string(nil), doc.DocumentDescribes...)
	graph := newDependencyGraph()
	for _, r := range doc.Relationships {
		typ := strings.ToUpper(r.Type)
		switch {
		case typ == "DESCRIBES" && r.Element == doc.SPDXID:
			described = appendUnique(described, r.Related)
		case typ == "DESCRIBED_BY" && r.Related == doc.SPDXID:
			described = appendUnique(described, r.Element)
		case typ == "DEPENDS_ON":
			graph.addEdge(r.Element, r.Related)
		case strings.HasSuffix(typ, "DEPENDENCY_OF") && typ != "DEPENDENCY_MANIFEST_OF":
			graph.addEdge(r.Related, r.Element)
		}
	}

	subjectID := ""
	for _, id := range described {
		if p, ok := byID[id]; ok {
			subjectID = id
			b.doc.Subject = spdxSubject(p)
			break
		}
	}
	direct := graph.direct(subjectID, func(id string) bool {
		p, ok := byID[id]
		return ok && (id == subjectID || unversioned(p.VersionInfo))
	})

	for i := range doc.Packages {
		p := &doc.Packages[i]
		if p.SPDXID == subjectID {
			continue
		}
		purl := spdxPURL(p)
		if purl == "" {
			continue
		}
		comp := newComponent(purl, p.Name, spdxVersion(p.VersionInfo), spdxLicenses(p))
		comp.Direct = direct[p.SPDXID]
		if err := b.addComponent(comp); err != nil {
			return err
		}
	}
	return nil
}

// spdxTool extracts the first "Tool: name-version" creator.
func spdxTool(creators []string) evidence.Tool {
	for _, c := range creators {
		rest, ok := strings.CutPrefix(strings.TrimSpace(c), "Tool:")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			continue
		}
		// Split at the last '-' that is followed by a version-looking token.
		for i := len(rest) - 1; i > 0; i-- {
			if rest[i] != '-' || i+1 >= len(rest) {
				continue
			}
			next := rest[i+1:]
			if unicode.IsDigit(rune(next[0])) || (next[0] == 'v' && len(next) > 1 && unicode.IsDigit(rune(next[1]))) {
				return evidence.Tool{Name: rest[:i], Version: next}
			}
		}
		return evidence.Tool{Name: rest}
	}
	return evidence.Tool{}
}

func spdxPURL(p *spdxPackage) string {
	for _, r := range p.ExternalRefs {
		if strings.EqualFold(r.ReferenceType, "purl") && validPURL(strings.TrimSpace(r.ReferenceLocator)) {
			return strings.TrimSpace(r.ReferenceLocator)
		}
	}
	return ""
}

func spdxVersion(v string) string {
	if strings.EqualFold(v, "NOASSERTION") {
		return ""
	}
	return v
}

func spdxLicenses(p *spdxPackage) []string {
	var out []string
	for _, l := range []string{p.LicenseConcluded, p.LicenseDeclared} {
		l = strings.TrimSpace(l)
		if l == "" || strings.EqualFold(l, "NOASSERTION") || strings.EqualFold(l, "NONE") {
			continue
		}
		out = appendUnique(out, l)
	}
	return out
}

func spdxSubject(p *spdxPackage) *evidence.Artifact {
	purl := spdxPURL(p)
	dig, ok := digestFromOCIPURL(purl)
	if !ok {
		for _, c := range p.Checksums {
			if dig, ok = digestFromChecksum(c.Algorithm, c.ChecksumValue); ok {
				break
			}
		}
	}
	return newArtifact(artifactKind(p.PrimaryPackagePurpose, ok), p.Name, dig)
}
