package ghoidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// maxNumericDate is 9999-12-31T23:59:59Z; later dates are treated as malformed.
const maxNumericDate = 253402300799

// Claims are the verified claims of a GitHub Actions OIDC token. Every field comes from a token
// whose signature, issuer, audience, lifetime and allow-lists have been checked. IDs are kept as
// the decimal strings GitHub sends. The JSON form is meant for audit records.
type Claims struct {
	// Registered claims.
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  []string  `json:"aud"`
	ExpiresAt time.Time `json:"exp"`
	NotBefore time.Time `json:"nbf,omitzero"`
	IssuedAt  time.Time `json:"iat"`
	JWTID     string    `json:"jti,omitempty"`

	// GitHub Actions claims.
	Repository           string `json:"repository"`
	RepositoryID         string `json:"repository_id"`
	RepositoryOwner      string `json:"repository_owner"`
	RepositoryOwnerID    string `json:"repository_owner_id"`
	RepositoryVisibility string `json:"repository_visibility,omitempty"`
	Ref                  string `json:"ref,omitempty"`
	RefType              string `json:"ref_type,omitempty"`
	SHA                  string `json:"sha"`
	RunID                string `json:"run_id"`
	RunNumber            string `json:"run_number,omitempty"`
	RunAttempt           string `json:"run_attempt,omitempty"`
	CheckRunID           string `json:"check_run_id,omitempty"`
	Workflow             string `json:"workflow,omitempty"`
	WorkflowRef          string `json:"workflow_ref,omitempty"`
	WorkflowSHA          string `json:"workflow_sha,omitempty"`
	JobWorkflowRef       string `json:"job_workflow_ref,omitempty"`
	JobWorkflowSHA       string `json:"job_workflow_sha,omitempty"`
	EventName            string `json:"event_name,omitempty"`
	HeadRef              string `json:"head_ref,omitempty"`
	BaseRef              string `json:"base_ref,omitempty"`
	Environment          string `json:"environment,omitempty"`
	Actor                string `json:"actor,omitempty"`
	ActorID              string `json:"actor_id,omitempty"`
	RunnerEnvironment    string `json:"runner_environment,omitempty"`
	Enterprise           string `json:"enterprise,omitempty"`
	EnterpriseID         string `json:"enterprise_id,omitempty"`
}

// parseClaims decodes a verified JWT payload. Member names match exactly (no case folding),
// string claims must be JSON strings and dates JSON numbers. Unknown claims are ignored.
func parseClaims(payload []byte) (*Claims, error) {
	m, err := parseObject(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrMalformed, err)
	}
	c := &Claims{}
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"iss", &c.Issuer}, {"sub", &c.Subject}, {"jti", &c.JWTID},
		{"repository", &c.Repository}, {"repository_id", &c.RepositoryID},
		{"repository_owner", &c.RepositoryOwner}, {"repository_owner_id", &c.RepositoryOwnerID},
		{"repository_visibility", &c.RepositoryVisibility},
		{"ref", &c.Ref}, {"ref_type", &c.RefType}, {"sha", &c.SHA},
		{"run_id", &c.RunID}, {"run_number", &c.RunNumber}, {"run_attempt", &c.RunAttempt},
		{"check_run_id", &c.CheckRunID},
		{"workflow", &c.Workflow}, {"workflow_ref", &c.WorkflowRef}, {"workflow_sha", &c.WorkflowSHA},
		{"job_workflow_ref", &c.JobWorkflowRef}, {"job_workflow_sha", &c.JobWorkflowSHA},
		{"event_name", &c.EventName}, {"head_ref", &c.HeadRef}, {"base_ref", &c.BaseRef},
		{"environment", &c.Environment}, {"actor", &c.Actor}, {"actor_id", &c.ActorID},
		{"runner_environment", &c.RunnerEnvironment},
		{"enterprise", &c.Enterprise}, {"enterprise_id", &c.EnterpriseID},
	} {
		s, _, err := stringMember(m, f.name)
		if err != nil {
			return nil, fmt.Errorf("%w: claims: %w", ErrMalformed, err)
		}
		*f.dst = s
	}
	if c.Audience, err = audienceMember(m); err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrMalformed, err)
	}
	for _, f := range []struct {
		name string
		dst  *time.Time
	}{{"exp", &c.ExpiresAt}, {"nbf", &c.NotBefore}, {"iat", &c.IssuedAt}} {
		if *f.dst, err = numericDateMember(m, f.name); err != nil {
			return nil, fmt.Errorf("%w: claims: %w", ErrMalformed, err)
		}
	}
	return c, nil
}

// audienceMember decodes `aud`, which RFC 7519 allows as a string or an array of strings.
func audienceMember(m map[string]json.RawMessage) ([]string, error) {
	raw, ok := m["aud"]
	if !ok || isNull(raw) || len(raw) == 0 {
		return nil, nil
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("aud: %w", err)
		}
		return []string{s}, nil
	case '[':
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("aud: %w", err)
		}
		return list, nil
	default:
		return nil, errors.New("aud must be a string or an array of strings")
	}
}

// numericDateMember decodes an RFC 7519 NumericDate (seconds since the epoch, possibly
// fractional). Absent or null yields the zero time; strings, negatives and absurd values are errors.
func numericDateMember(m map[string]json.RawMessage, name string) (time.Time, error) {
	raw, ok := m[name]
	if !ok || isNull(raw) || len(raw) == 0 {
		return time.Time{}, nil
	}
	if c := raw[0]; c != '-' && (c < '0' || c > '9') {
		return time.Time{}, fmt.Errorf("%s must be a number", name)
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsNaN(f) || f < 0 || f > maxNumericDate {
		return time.Time{}, fmt.Errorf("%s is not a valid NumericDate", name)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), nil
}

// parseID parses a GitHub numeric ID in canonical decimal form (no sign, no leading zeros).
func parseID(s string) (int64, bool) {
	if s == "" || len(s) > 19 || s[0] == '0' {
		return 0, false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n > 0
}

// CheckCommit binds evidence to the token: sha must equal the token's `sha` claim (the commit
// the workflow run built). Both must be full hexadecimal object IDs (40 or 64 characters);
// comparison ignores case. It returns an error matching ErrCommitMismatch and ErrForbidden.
func (c *Claims) CheckCommit(sha string) error {
	if c == nil || !isObjectID(c.SHA) || !isObjectID(sha) || !strings.EqualFold(c.SHA, sha) {
		return fmt.Errorf("%w: evidence commit %s", ErrCommitMismatch, quote(sha))
	}
	return nil
}

func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// SubjectField is one key/value segment of a `sub` claim, with "%3A" unescaped to ":".
type SubjectField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Subject is a decomposed `sub` claim, for audit and display only: authorization always uses the
// dedicated, signed `repository_id`/`repository_owner_id` claims, never the subject string.
//
// GitHub emits several shapes: the previous default "repo:OWNER/REPO:ref:refs/heads/main",
// the immutable default for repositories created (or renamed/transferred) after 2026-07-15
// "repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main", the pull_request form
// "repo:OWNER/REPO:pull_request", and customised templates such as
// "repository_owner:octo-org:environment:prod%3Aeu" that may not contain a repo segment at all.
type Subject struct {
	// Owner and Repository are the names from the `repo` segment, if any.
	Owner      string `json:"owner,omitempty"`
	Repository string `json:"repository,omitempty"`
	// OwnerID and RepositoryID are set only for the immutable format.
	OwnerID      string `json:"owner_id,omitempty"`
	RepositoryID string `json:"repository_id,omitempty"`
	// Immutable reports the immutable "OWNER@ID/REPO@ID" repo segment.
	Immutable bool `json:"immutable"`
	// Fields lists every segment in order, including `repo`.
	Fields []SubjectField `json:"fields"`
}

const maxSubjectSegments = 64

// ParseSubject decomposes a GitHub Actions `sub` claim. Unknown or inconsistent shapes return an
// error rather than a guess; Verify never depends on this function.
func ParseSubject(sub string) (Subject, error) {
	if sub == "" {
		return Subject{}, errors.New("parse subject: empty")
	}
	if strings.Count(sub, ":") >= 2*maxSubjectSegments {
		return Subject{}, fmt.Errorf("parse subject: more than %d segments", maxSubjectSegments)
	}
	parts := strings.Split(sub, ":")
	var s Subject
	seenRepo := false
	for i := 0; i < len(parts); i += 2 {
		key := parts[i]
		if !validSubjectKey(key) {
			return Subject{}, fmt.Errorf("parse subject: invalid key %s", quote(key))
		}
		if i+1 == len(parts) {
			// The default subject of pull_request events ends with a bare "pull_request".
			if key == "pull_request" {
				s.Fields = append(s.Fields, SubjectField{Key: key})
				break
			}
			return Subject{}, fmt.Errorf("parse subject: key %s has no value", quote(key))
		}
		value := strings.ReplaceAll(strings.ReplaceAll(parts[i+1], "%3A", ":"), "%3a", ":")
		if key == "repo" {
			if seenRepo {
				return Subject{}, errors.New("parse subject: duplicate repo segment")
			}
			seenRepo = true
			if err := s.parseRepo(value); err != nil {
				return Subject{}, err
			}
		}
		s.Fields = append(s.Fields, SubjectField{Key: key, Value: value})
	}
	return s, nil
}

// parseRepo parses "OWNER/REPO" or the immutable "OWNER@OWNER_ID/REPO@REPO_ID".
func (s *Subject) parseRepo(v string) error {
	owner, repo, ok := strings.Cut(v, "/")
	if !ok || strings.Contains(repo, "/") {
		return fmt.Errorf("parse subject: repo segment %s is not OWNER/REPO", quote(v))
	}
	ownerName, ownerID, ownerHasID := strings.Cut(owner, "@")
	repoName, repoID, repoHasID := strings.Cut(repo, "@")
	if ownerName == "" || repoName == "" || ownerHasID != repoHasID {
		return fmt.Errorf("parse subject: repo segment %s is malformed", quote(v))
	}
	if ownerHasID {
		if _, ok := parseID(ownerID); !ok {
			return fmt.Errorf("parse subject: owner id %s is not numeric", quote(ownerID))
		}
		if _, ok := parseID(repoID); !ok {
			return fmt.Errorf("parse subject: repository id %s is not numeric", quote(repoID))
		}
		s.OwnerID, s.RepositoryID, s.Immutable = ownerID, repoID, true
	}
	s.Owner, s.Repository = ownerName, repoName
	return nil
}

func validSubjectKey(k string) bool {
	if k == "" || len(k) > 64 {
		return false
	}
	for i := range len(k) {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// ParsedSubject is a convenience for ParseSubject(c.Subject).
func (c *Claims) ParsedSubject() (Subject, error) { return ParseSubject(c.Subject) }
