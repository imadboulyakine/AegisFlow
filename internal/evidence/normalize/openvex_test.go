package normalize

import (
	"errors"
	"reflect"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestOpenVEXFixtures(t *testing.T) {
	t.Parallel()
	gv := parseFixture(t, "openvex-govulncheck.json")
	if gv.FormatVersion != "0.2.0" || len(gv.VEX) != 3 || len(gv.Findings) != 0 {
		t.Fatalf("govulncheck VEX = %+v", gv)
	}
	s := gv.VEX[0]
	if s.VulnID != "CVE-2022-32149" || s.Status != evidence.VEXAffected || s.Author != "Unknown Author" ||
		!reflect.DeepEqual(s.Products, []string{"Unknown Product", "pkg:golang/golang.org%2Fx%2Ftext@v0.3.7"}) {
		t.Errorf("statement = %+v", s)
	}
	// The encoded govulncheck PURL matches the syft/grype spelling once canonicalized.
	if CanonicalPURL(s.Products[1]) != "pkg:golang/golang.org/x/text@v0.3.7" {
		t.Errorf("canonical product = %q", CanonicalPURL(s.Products[1]))
	}

	hb := parseFixture(t, "openvex-handbuilt.json")
	if hb.Tool.Name != "vexctl/0.3.0" || len(hb.VEX) != 4 {
		t.Fatalf("handbuilt = %+v", hb)
	}
	if got := hb.VEX[1].Products; !reflect.DeepEqual(got, []string{
		"pkg:deb/debian/tar@1.35%2Bdfsg-3.1?arch=amd64&distro=debian-13",
		"sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99",
	}) {
		t.Errorf("identifiers/hashes products = %v", got)
	}
	if hb.VEX[1].Timestamp.IsZero() || hb.VEX[0].Timestamp.Equal(hb.VEX[1].Timestamp) {
		t.Error("statement timestamp must override the document timestamp")
	}
	if hb.VEX[2].VulnID != "GHSA-xxxx-fixture-0002" {
		t.Errorf("ID from advisory URL = %q", hb.VEX[2].VulnID)
	}
}

func TestOpenVEXErrors(t *testing.T) {
	t.Parallel()
	doc := func(stmt string) string {
		return `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-01-01T00:00:00Z","statements":[` + stmt + `]}`
	}
	ok := mustParse(t, evidence.FormatOpenVEX, doc(`{"vulnerability":{"name":"X-1"},"products":[{"hashes":{"sha-512":"`+
		strings64("a")+strings64("a")+`"}}],"status":"not_affected","impact_statement":"n/a"}`))
	if ok.VEX[0].Products[0] != "sha512:"+strings64("a")+strings64("a") || ok.Tool.Name != "openvex" {
		t.Errorf("sha-512 product / default tool = %+v", ok)
	}
	if empty := mustParse(t, evidence.FormatOpenVEX, `{"@context":"https://openvex.dev/ns/v0.2.0/"}`); len(empty.VEX) != 0 {
		t.Errorf("empty document = %+v", empty)
	}

	cases := []struct {
		name, input string
		want        error
	}{
		{"old context", `{"@context":"https://openvex.dev/ns/v0.0.1","statements":[]}`, ErrUnsupportedVersion},
		{"bad doc timestamp", `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"yesterday"}`, ErrInvalid},
		{"no vulnerability", doc(`{"products":[{"@id":"p"}],"status":"affected"}`), ErrInvalid},
		{"bad status", doc(`{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"p"}],"status":"safe"}`), ErrInvalid},
		{"bad justification", doc(`{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"p"}],"status":"not_affected","justification":"trust_me"}`), ErrInvalid},
		{"not_affected unjustified", doc(`{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"p"}],"status":"not_affected"}`), ErrInvalid},
		{"no products", doc(`{"vulnerability":{"name":"CVE-1"},"status":"affected"}`), ErrInvalid},
		{"product without id", doc(`{"vulnerability":{"name":"CVE-1"},"products":[{"hashes":{"md5":"00"}}],"status":"affected"}`), ErrInvalid},
		{"subcomponent without id", doc(`{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"p","subcomponents":[{}]}],"status":"affected"}`), ErrInvalid},
		{"bad statement timestamp", doc(`{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"p"}],"status":"affected","timestamp":"1/1/2026"}`), ErrInvalid},
		{"vulnerability as string", doc(`{"vulnerability":"CVE-1","products":[{"@id":"p"}],"status":"affected"}`), ErrInvalid},
	}
	for _, c := range cases {
		if _, err := parseString(t, evidence.FormatOpenVEX, c.input); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}
