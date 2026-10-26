package store

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// FuzzPrepareDocument feeds arbitrary JSON-decoded documents (normalizer output is derived from
// untrusted CI evidence) through prepareDocument. It must never panic, and every accepted
// document must satisfy the invariants the SQL relies on.
func FuzzPrepareDocument(f *testing.F) {
	seeds := []string{
		`{"format":"grype","tool":{"name":"grype"}}`,
		`{"format":"cyclonedx","tool":{"name":"syft"},"components":[{"purl":"pkg:golang/a@1","licenses":["MIT","MIT"]},{"purl":"x"}]}`,
		`{"format":"grype","tool":{"name":"Grype"},"findings":[{"kind":"vulnerability","fingerprint":"f","severity":"HIGH",
		  "vulnerability":{"id":"CVE-2024-1","aliases":["GHSA-a"],"cvss":[{"version":"3.1","baseScore":9.8}]},
		  "component":{"purl":"pkg:npm/a@1"},"reachability":"called","fixedVersions":["2"]}]}`,
		`{"format":"sarif","tool":{"name":"gosec"},"findings":[{"kind":"code","fingerprint":"ÿ","title":"a\u0000b",
		  "location":{"path":"x.go","startLine":-1,"endLine":99999999999}}]}`,
		`{"format":"openvex","tool":{"name":"vexctl"},"vex":[{"vulnId":"CVE-2024-1","products":["pkg:npm/a@1","sha256:x"],
		  "status":"not_affected","justification":"component_not_present","timestamp":"2026-01-01T00:00:00Z"}]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var doc evidence.Document
		if err := json.Unmarshal(data, &doc); err != nil {
			return
		}
		p, err := prepareDocument(doc)
		if err != nil {
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("prepareDocument() error %v is not ErrInvalidInput", err)
			}
			return
		}
		checkPrepared(t, p)
	})
}

func checkPrepared(t *testing.T, p *preparedDoc) {
	t.Helper()
	text := func(what, s string, maxBytes int) {
		if !utf8.ValidString(s) || strings.ContainsRune(s, 0) || len(s) > maxBytes {
			t.Fatalf("%s %q is not storable text (max %d bytes)", what, s, maxBytes)
		}
	}
	list := func(what string, l []string, maxItems int) {
		if l == nil || len(l) > maxItems || !slices.IsSorted(l) || len(slices.Compact(slices.Clone(l))) != len(l) {
			t.Fatalf("%s %q must be a non-nil, sorted, de-duplicated list of at most %d", what, l, maxItems)
		}
		for _, s := range l {
			text(what, s, 2048)
		}
	}
	if !slices.IsSorted(p.tools) || len(p.tools) == 0 {
		t.Fatalf("tools %q", p.tools)
	}
	for i, c := range p.components {
		if !validPURL(c.PURL) || (i > 0 && p.components[i-1].PURL >= c.PURL) {
			t.Fatalf("component %d purl %q invalid or out of order", i, c.PURL)
		}
		text("name", c.Name, 512)
		text("version", c.Version, 256)
		text("ecosystem", c.Ecosystem, 64)
		list("licenses", c.Licenses, maxListItems)
	}
	for i, v := range p.vulns {
		if !validVulnID(v.VulnID) || (i > 0 && p.vulns[i-1].VulnID >= v.VulnID) {
			t.Fatalf("vuln %d id %q invalid or out of order", i, v.VulnID)
		}
		list("aliases", v.Aliases, maxListItems)
		list("cwes", v.CWEs, maxListItems)
		text("summary", v.Summary, 4096)
		if v.CVSS == nil || len(v.CVSS) > maxCVSSPerVuln || evidence.ParseSeverity(v.Severity) != evidence.Severity(v.Severity) {
			t.Fatalf("vuln %+v", v)
		}
	}
	for i, f := range p.findings {
		if !validFingerprint(f.Fingerprint) || (i > 0 && p.findings[i-1].Fingerprint >= f.Fingerprint) {
			t.Fatalf("finding %d fingerprint %q invalid or out of order", i, f.Fingerprint)
		}
		if !validFindingKind(evidence.FindingKind(f.Kind)) || len(f.Tools) == 0 || len(f.Tools) > maxToolsPerItem {
			t.Fatalf("finding %+v", f)
		}
		if f.Kind == string(evidence.FindingVulnerability) && f.vulnID == "" {
			t.Fatalf("vulnerability finding without vulnerability: %+v", f)
		}
		text("title", f.Title, 1024)
		text("message", f.Message, 16384)
		list("fixed versions", f.FixedVersions, maxListItems)
		if f.LocationStart != nil && *f.LocationStart <= 0 {
			t.Fatalf("line %d", *f.LocationStart)
		}
	}
	for i, v := range p.vex {
		if len(v.DedupKey) != 64 || (i > 0 && p.vex[i-1].DedupKey >= v.DedupKey) || !validVulnID(v.VulnID) || !boundedText(v.Product, 1, 2048) {
			t.Fatalf("vex %d %+v", i, v)
		}
	}
	if len(p.components) > maxDocComponents || len(p.findings) > maxDocFindings || len(p.vex) > maxDocVEX {
		t.Fatal("limits exceeded")
	}
	// Everything must encode for jsonb_to_recordset.
	for _, v := range []any{p.components, p.vulns, p.findings, p.vex} {
		b, err := json.Marshal(v)
		if err != nil || strings.Contains(string(b), `\u0000`) {
			t.Fatalf("payload not encodable: %v", err)
		}
	}
}

// FuzzDecodeCursor checks that arbitrary cursors never panic and that accepted cursors round-trip.
func FuzzDecodeCursor(f *testing.F) {
	f.Add(encodeCursor(-1, 1))
	f.Add(encodeCursor(72.5, 123456789))
	f.Add("djF8MXwx")
	f.Add("")
	f.Fuzz(func(t *testing.T, c string) {
		score, id, err := decodeCursor(c)
		if err != nil {
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("decodeCursor() error %v is not ErrInvalidInput", err)
			}
			return
		}
		if id <= 0 || score < -1 || score > 100 {
			t.Fatalf("decodeCursor(%q) accepted (%v, %d)", c, score, id)
		}
		if s2, id2, err := decodeCursor(encodeCursor(score, id)); err != nil || s2 != score || id2 != id {
			t.Fatalf("round trip of (%v, %d) failed", score, id)
		}
	})
}

// FuzzCleanText checks cleanText's guarantees on arbitrary input.
func FuzzCleanText(f *testing.F) {
	f.Add("  hello  ", 5)
	f.Add("a\x00\xff\xfeé", 3)
	f.Fuzz(func(t *testing.T, s string, maxBytes int) {
		if maxBytes < 0 || maxBytes > 1<<16 {
			return
		}
		got := cleanText(s, maxBytes)
		if len(got) > maxBytes || !utf8.ValidString(got) || strings.ContainsRune(got, 0) {
			t.Fatalf("cleanText(%q, %d) = %q", s, maxBytes, got)
		}
	})
}
