package ghoidc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseSubject(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		sub     string
		want    Subject
		wantErr bool
	}{
		{name: "previous default", sub: "repo:octo-org/octo-repo:ref:refs/heads/main", want: Subject{
			Owner: "octo-org", Repository: "octo-repo",
			Fields: []SubjectField{{"repo", "octo-org/octo-repo"}, {"ref", "refs/heads/main"}},
		}},
		{name: "immutable default", sub: "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main", want: Subject{
			Owner: "octo-org", Repository: "octo-repo", OwnerID: "123456", RepositoryID: "456789", Immutable: true,
			Fields: []SubjectField{{"repo", "octo-org@123456/octo-repo@456789"}, {"ref", "refs/heads/main"}},
		}},
		{name: "environment", sub: "repo:octo-org/octo-repo:environment:prod", want: Subject{
			Owner: "octo-org", Repository: "octo-repo",
			Fields: []SubjectField{{"repo", "octo-org/octo-repo"}, {"environment", "prod"}},
		}},
		{name: "pull request", sub: "repo:octo-org@1/octo-repo@2:pull_request", want: Subject{
			Owner: "octo-org", Repository: "octo-repo", OwnerID: "1", RepositoryID: "2", Immutable: true,
			Fields: []SubjectField{{"repo", "octo-org@1/octo-repo@2"}, {"pull_request", ""}},
		}},
		{name: "customised with escaped colon", sub: "environment:production%3Aeastus:repository_owner:octo-org", want: Subject{
			Fields: []SubjectField{{"environment", "production:eastus"}, {"repository_owner", "octo-org"}},
		}},
		{name: "customised job workflow", sub: "repo:octo-org/octo-repo:environment:prod:job_workflow_ref:octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main", want: Subject{
			Owner: "octo-org", Repository: "octo-repo",
			Fields: []SubjectField{
				{"repo", "octo-org/octo-repo"}, {"environment", "prod"},
				{"job_workflow_ref", "octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main"},
			},
		}},
		{name: "empty", sub: "", wantErr: true},
		{name: "dangling key", sub: "repo:octo-org/octo-repo:ref", wantErr: true},
		{name: "invalid key", sub: "Repo:octo-org/octo-repo", wantErr: true},
		{name: "empty key", sub: ":x", wantErr: true},
		{name: "repo without slash", sub: "repo:octo-repo:ref:refs/heads/main", wantErr: true},
		{name: "repo with two slashes", sub: "repo:a/b/c:ref:x", wantErr: true},
		{name: "partial immutable", sub: "repo:octo-org@1/octo-repo:ref:x", wantErr: true},
		{name: "non-numeric owner id", sub: "repo:octo-org@x/octo-repo@2:ref:x", wantErr: true},
		{name: "non-numeric repository id", sub: "repo:octo-org@1/octo-repo@02:ref:x", wantErr: true},
		{name: "empty names", sub: "repo:@1/@2:ref:x", wantErr: true},
		{name: "duplicate repo", sub: "repo:a/b:repo:c/d", wantErr: true},
		{name: "too many segments", sub: strings.Repeat("k:v:", maxSubjectSegments+1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseSubject(tt.sub)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseSubject(%q) = %+v, want error", tt.sub, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSubject(%q): %v", tt.sub, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSubject(%q)\n got %+v\nwant %+v", tt.sub, got, tt.want)
			}
		})
	}
	c := &Claims{Subject: "repo:o/r:ref:refs/heads/main"}
	if s, err := c.ParsedSubject(); err != nil || s.Repository != "r" {
		t.Errorf("ParsedSubject = %+v, %v", s, err)
	}
}

func TestParseObject(t *testing.T) {
	t.Parallel()
	ok := []string{`{}`, ` { "a" : 1 , "b" : [1,{"a":1,"a":2}] } `, `{"a":null}`}
	for _, s := range ok {
		if _, err := parseObject([]byte(s)); err != nil {
			t.Errorf("parseObject(%q): %v", s, err)
		}
	}
	bad := []string{``, `null`, `[]`, `"s"`, `{`, `{"a"}`, `{"a":}`, `{"a":1,}`, `{"a":1}x`, `{"a":1}{}`,
		`{"a":1,"a":1}`, `{1:2}`, "{\"\xff\":1}"}
	for _, s := range bad {
		if _, err := parseObject([]byte(s)); err == nil {
			t.Errorf("parseObject(%q) accepted invalid input", s)
		}
	}
	var many strings.Builder
	many.WriteString("{")
	for i := range maxJSONKeys + 1 {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`"k` + strings.Repeat("x", i) + `":0`)
	}
	many.WriteString("}")
	if _, err := parseObject([]byte(many.String())); err == nil {
		t.Error("parseObject accepted more than maxJSONKeys members")
	}
}

func TestClaimsJSONForAudit(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(&Claims{RepositoryID: "74", SHA: testSHA, RunID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"repository_id":"74"`, `"sha":"` + testSHA + `"`, `"run_id":"1"`} {
		if !strings.Contains(s, want) {
			t.Errorf("audit JSON %s lacks %s", s, want)
		}
	}
	if strings.Contains(s, `"nbf"`) || strings.Contains(s, `"environment"`) {
		t.Errorf("audit JSON %s includes empty optional claims", s)
	}
}
