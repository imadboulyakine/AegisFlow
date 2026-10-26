package normalize

import (
	"testing"
)

// The fingerprint scheme is a stability contract: stored findings are tracked by these values.
// If one of these pinned values changes, the scheme changed and fingerprintDomain must be bumped
// (with a migration plan for stored findings).
func TestFingerprintPinnedValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			"vuln",
			VulnFingerprint("CVE-2022-32149", "pkg:golang/golang.org/x/text@v0.3.7"),
			"4cb2f28bf7a7812b31072d1a39ecfee0eec85bd1914f2ee0e5e0f5200888334e",
		},
		{
			"location with snippet",
			LocationFingerprint("gosec", "G401", "main.go", 12, "sum := md5.Sum([]byte(os.Args[1]))"),
			LocationFingerprint("GoSec", "G401", "./main.go", 12, "  sum := md5.Sum([]byte(os.Args[1]))\r\n"),
		},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: fingerprint = %s, want %s", tt.name, tt.got, tt.want)
		}
	}
	if got, want := LocationFingerprint("gitleaks", "github-pat", "deploy.sh", 3, "REDACTED"),
		"b346e4907f85dee7c4d13442846b0c56e08a308ab0f7961ef7d37d90278833a9"; got != want {
		t.Errorf("location fingerprint = %s, want %s", got, want)
	}
}

func TestVulnFingerprintEquivalence(t *testing.T) {
	t.Parallel()
	base := VulnFingerprint("CVE-2022-32149", "pkg:golang/golang.org/x/text@v0.3.7")
	same := []struct{ id, purl string }{
		{"cve-2022-32149", "pkg:golang/golang.org/x/text@v0.3.7"},
		{" CVE-2022-32149 ", "pkg:golang/golang.org%2Fx%2Ftext@v0.3.7"},
		{"CVE-2022-32149", "PKG:Golang/golang.org/x/text@v0.3.7?type=module#sub/path"},
		{"CVE-2022-32149", "pkg:golang/golang.org/x/text@v0.3.7?goos=linux"},
	}
	for _, s := range same {
		if got := VulnFingerprint(s.id, s.purl); got != base {
			t.Errorf("VulnFingerprint(%q, %q) differs from the canonical form", s.id, s.purl)
		}
	}
	different := []struct{ id, purl string }{
		{"CVE-2022-32148", "pkg:golang/golang.org/x/text@v0.3.7"},
		{"CVE-2022-32149", "pkg:golang/golang.org/x/text@v0.3.8"},
		{"CVE-2022-32149", "pkg:golang/golang.org/x/net@v0.3.7"},
		{"GO-2022-1059", "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	for _, d := range different {
		if VulnFingerprint(d.id, d.purl) == base {
			t.Errorf("VulnFingerprint(%q, %q) collides", d.id, d.purl)
		}
	}
	// Length-prefixed fields: moving a boundary must change the hash.
	if VulnFingerprint("AB", "C") == VulnFingerprint("A", "BC") {
		t.Error("field boundary ambiguity")
	}
}

func TestLocationFingerprint(t *testing.T) {
	t.Parallel()
	base := LocationFingerprint("semgrep", "go.lang.security.audit", "pkg/a.go", 10, "")
	if base != LocationFingerprint("Semgrep", " go.lang.security.audit ", "pkg/./b/../a.go", 10, "") {
		t.Error("tool case, rule whitespace and path cleaning must not matter")
	}
	if base != LocationFingerprint("semgrep", "go.lang.security.audit", `pkg\a.go`, 10, "   ") {
		t.Error("backslashes and blank snippets must not matter")
	}
	if base != LocationFingerprint("semgrep", "go.lang.security.audit", "pkg/a.go", 10, "") {
		t.Error("not deterministic")
	}
	for name, other := range map[string]string{
		"line":    LocationFingerprint("semgrep", "go.lang.security.audit", "pkg/a.go", 11, ""),
		"path":    LocationFingerprint("semgrep", "go.lang.security.audit", "pkg/b.go", 10, ""),
		"rule":    LocationFingerprint("semgrep", "other", "pkg/a.go", 10, ""),
		"tool":    LocationFingerprint("gosec", "go.lang.security.audit", "pkg/a.go", 10, ""),
		"snippet": LocationFingerprint("semgrep", "go.lang.security.audit", "pkg/a.go", 10, "x := 1"),
	} {
		if other == base {
			t.Errorf("changing the %s must change the fingerprint", name)
		}
	}
	if LocationFingerprint("t", "r", "", -5, "") != LocationFingerprint("t", "r", ".", 0, "") {
		t.Error("negative lines and '.' paths must normalize to 0 and empty")
	}
}

func TestCanonicalPURL(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"pkg:golang/golang.org/x/text@v0.3.7", "pkg:golang/golang.org/x/text@v0.3.7"},
		{"pkg:golang/golang.org%2Fx%2Ftext@v0.3.7", "pkg:golang/golang.org/x/text@v0.3.7"},
		{"PKG:GOLANG/golang.org/x/text@v0.3.7?type=module", "pkg:golang/golang.org/x/text@v0.3.7"},
		{"pkg://npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21"},
		{"pkg:npm/%40babel/core@7.0.0", "pkg:npm/@babel/core@7.0.0"},
		{"pkg:npm/@babel/core@7.0.0", "pkg:npm/@babel/core@7.0.0"},
		{"pkg:npm/@babel/core", "pkg:npm/@babel/core"},
		{"pkg:deb/debian/tar@1.35%2Bdfsg-3.1?arch=amd64&distro=debian-13", "pkg:deb/debian/tar@1.35+dfsg-3.1"},
		{"pkg:pypi/Django_Rest@3.0", "pkg:pypi/django-rest@3.0"},
		{"pkg:golang/stdlib@go1.22.1", "pkg:golang/stdlib@1.22.1"},
		{"pkg:golang/stdlib@v1.22.1", "pkg:golang/stdlib@1.22.1"},
		{"pkg:golang/stdlib@1.22.1", "pkg:golang/stdlib@1.22.1"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{"pkg:generic/openssl", "pkg:generic/openssl"},
		{"pkg:generic/bad%zzescape@1", "pkg:generic/bad%25zzescape@1"},
		{"pkg:t/a%40b/c%3Fd@1%2F2%40x", "pkg:t/a%40b/c%3Fd@1%2F2%40x"},
		{"  pkg:npm/a@1  ", "pkg:npm/a@1"},
		{"not-a-purl", "not-a-purl"},
		{"pkg:", "pkg:"},
		{"pkg:npm", "pkg:npm"},
		{"pkg:npm/", "pkg:npm/"},
		{"pkg:/x", "pkg:/x"},
		{"sha256:abc", "sha256:abc"},
	}
	for _, tt := range tests {
		if got := CanonicalPURL(tt.in); got != tt.want {
			t.Errorf("CanonicalPURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
