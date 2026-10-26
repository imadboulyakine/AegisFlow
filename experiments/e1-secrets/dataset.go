package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/rand/v2"
	"strconv"
	"strings"
)

// Character sets used to build synthetic credentials. Every credential in the dataset is
// assembled at runtime from a public format prefix plus seeded pseudo-random characters; no
// credential-shaped literal exists in this source tree (our own gitleaks scans must stay clean).
const (
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	digitChars  = "0123456789"
	alnumChars  = upperChars + lowerChars + digitChars
	base32Chars = upperChars + "234567"
	hexChars    = "0123456789abcdef"
)

// gen is the single source of randomness for a dataset. All choices go through it in a fixed
// order, so the same seed (and Go toolchain) always yields byte-identical fixtures.
type gen struct {
	r     *rand.Rand
	paths map[string]bool
}

func newGen(seed int64) *gen {
	key := sha256.Sum256([]byte("aegisflow/e1-secrets/" + strconv.FormatInt(seed, 10)))
	// Deterministic fixture generation needs a seeded PRNG; nothing here protects a real secret.
	return &gen{r: rand.New(rand.NewChaCha8(key)), paths: map[string]bool{}} //nolint:gosec // G404: seeded PRNG is required for reproducible synthetic fixtures
}

func (g *gen) intn(n int) int { return g.r.IntN(n) }

// between returns a uniform integer in [lo, hi].
func (g *gen) between(lo, hi int) int { return lo + g.r.IntN(hi-lo+1) }

func (g *gen) str(alphabet string, n int) string {
	var sb strings.Builder
	sb.Grow(n)
	for range n {
		sb.WriteByte(alphabet[g.r.IntN(len(alphabet))])
	}
	return sb.String()
}

func (g *gen) bytes(n int) []byte {
	b := make([]byte, 0, n+8)
	for len(b) < n {
		b = binary.LittleEndian.AppendUint64(b, g.r.Uint64())
	}
	return b[:n]
}

func (g *gen) uuid() string {
	h := g.str(hexChars, 32)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:]
}

func pick[T any](g *gen, xs []T) T { return xs[g.r.IntN(len(xs))] }

// path reserves a unique repository path, adding a numeric suffix on collision.
func (g *gen) path(p string) string {
	candidate := p
	for i := 2; g.paths[candidate]; i++ {
		dot := strings.LastIndex(p, ".")
		slash := strings.LastIndex(p, "/")
		if dot > slash+1 {
			candidate = p[:dot] + "_" + strconv.Itoa(i) + p[dot:]
		} else {
			candidate = p + "_" + strconv.Itoa(i)
		}
	}
	g.paths[candidate] = true
	return candidate
}

// fillers returns between lo and hi distinct blocks from corpus, separated by blank lines.
func (g *gen) fillers(corpus []string, lo, hi int) []string {
	n := min(g.between(lo, hi), len(corpus))
	idx := g.r.Perm(len(corpus))[:n]
	var out []string
	for _, i := range idx {
		out = append(out, strings.Split(corpus[i], "\n")...)
		out = append(out, "")
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// Secret types

// field is one key/value assignment of a credential; an AWS key pair has two.
type field struct {
	Key   string // canonical UPPER_SNAKE name, e.g. GITHUB_TOKEN
	Value string // may contain '\n' (PEM blocks)
}

type secretType struct {
	ID          string
	Description string
	generate    func(g *gen) []field
}

func secretTypes() []secretType {
	return []secretType{
		{"aws-access-key", "AWS access key ID + secret access key pair", genAWS},
		{"github-pat-classic", "GitHub classic personal access token", genGitHubClassic},
		{"github-pat-fine-grained", "GitHub fine-grained personal access token", genGitHubFineGrained},
		{"azure-storage-connection-string", "Azure Storage connection string with account key", genAzureStorage},
		{"azure-entra-client-secret", "Microsoft Entra ID application client secret", genEntraSecret},
		{"slack-bot-token", "Slack bot user OAuth token", genSlackBot},
		{"private-key-pem", "PEM private key (RSA, EC or OpenSSH)", genPrivateKey},
		{"jwt", "Signed JSON Web Token (HS256 bearer token)", genJWT},
		{"generic-api-key", "Vendor-neutral high-entropy API key", genGenericAPIKey},
		{"postgres-uri", "PostgreSQL connection URI with embedded password", genPostgresURI},
	}
}

func genAWS(g *gen) []field {
	return []field{
		{"AWS_ACCESS_KEY_ID", "AKIA" + g.str(base32Chars, 16)},
		{"AWS_SECRET_ACCESS_KEY", g.str(alnumChars+"/+", 40)},
	}
}

func genGitHubClassic(g *gen) []field {
	return []field{{"GITHUB_TOKEN", "ghp_" + g.str(alnumChars, 36)}}
}

func genGitHubFineGrained(g *gen) []field {
	return []field{{"GH_PAT", "github_pat_" + g.str(alnumChars, 22) + "_" + g.str(alnumChars, 59)}}
}

func genAzureStorage(g *gen) []field {
	account := "st" + g.str(lowerChars+digitChars, 12)
	accountKey := base64.StdEncoding.EncodeToString(g.bytes(64))
	value := "DefaultEndpointsProtocol=https;AccountName=" + account + ";AccountKey=" + accountKey +
		";EndpointSuffix=core.windows.net"
	return []field{{"AZURE_STORAGE_CONNECTION_STRING", value}}
}

func genEntraSecret(g *gen) []field {
	value := g.str(alnumChars, 3) + g.str(digitChars, 1) + "Q~" + g.str(alnumChars+"_~.-", 34)
	return []field{{"AZURE_CLIENT_SECRET", value}}
}

func genSlackBot(g *gen) []field {
	value := "xoxb-" + g.str(digitChars, 11) + "-" + g.str(digitChars, 13) + "-" + g.str(alnumChars, 24)
	return []field{{"SLACK_BOT_TOKEN", value}}
}

// genPrivateKey builds a PEM block whose base64 body starts like a real DER structure followed
// by random bytes. It is not a usable key; it only has the shape of one.
func genPrivateKey(g *gen) []field {
	switch g.intn(3) {
	case 0:
		der := append([]byte{0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00}, g.bytes(1180)...)
		return []field{{"TLS_PRIVATE_KEY", pemBlock("RSA "+privateKeyLabel, der, 64)}}
	case 1:
		der := append([]byte{0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20}, g.bytes(32)...)
		der = append(der, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04)
		der = append(der, g.bytes(64)...)
		return []field{{"SIGNING_PRIVATE_KEY", pemBlock("EC "+privateKeyLabel, der, 64)}}
	default:
		der := append([]byte("openssh-key-v1\x00"), g.bytes(384)...)
		return []field{{"DEPLOY_SSH_KEY", pemBlock("OPENSSH "+privateKeyLabel, der, 70)}}
	}
}

// privateKeyLabel is assembled so that no PEM boundary line appears literally in this file.
const privateKeyLabel = "PRIVATE" + " " + "KEY"

func pemBlock(label string, der []byte, width int) string {
	dashes := strings.Repeat("-", 5)
	lines := []string{dashes + "BEGIN " + label + dashes}
	body := base64.StdEncoding.EncodeToString(der)
	for len(body) > width {
		lines = append(lines, body[:width])
		body = body[width:]
	}
	lines = append(lines, body, dashes+"END "+label+dashes)
	return strings.Join(lines, "\n")
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func genJWT(g *gen) []field {
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	svc := pick(g, services)
	payload, _ := json.Marshal(map[string]any{
		"aud":   "api." + svc + ".example",
		"exp":   1798761600 + g.intn(86400*30),
		"iat":   1767225600 + g.intn(86400*30),
		"iss":   "https://login.contoso-" + svc + ".example",
		"scope": "admin write",
		"sub":   g.uuid(),
	})
	return []field{{"SERVICE_JWT", b64url(header) + "." + b64url(payload) + "." + b64url(g.bytes(32))}}
}

func genGenericAPIKey(g *gen) []field {
	key := pick(g, []string{"PAYMENTS_API_KEY", "MAPS_API_KEY", "SEARCH_API_KEY", "WEATHER_API_KEY"})
	return []field{{key, g.str(alnumChars, 32)}}
}

func genPostgresURI(g *gen) []field {
	svc := pick(g, services)
	user := pick(g, []string{"app", "aegis", "svc_" + svc})
	pass := g.str(alnumChars+"-_.~", 22)
	host := "psql-" + svc + "-prod.postgres.database.azure.com"
	return []field{{"DATABASE_URL", "postgres://" + user + ":" + pass + "@" + host + ":5432/" + svc + "?sslmode=require"}}
}

// ---------------------------------------------------------------------------------------------
// Variants

const (
	variantPlain   = "plain"   // string literal in source code
	variantConfig  = "config"  // configuration file (.env, YAML, JSON, tfvars, key file)
	variantBase64  = "base64"  // base64-encoded (Kubernetes Secret or opaque blob in code)
	variantSplit   = "split"   // value split across several source lines and concatenated
	variantHistory = "history" // committed, then removed in a later commit (history only)
)

var variants = []string{variantPlain, variantConfig, variantBase64, variantSplit, variantHistory}

var services = []string{
	"billing", "payments", "notifier", "inventory", "search", "accounts", "reports", "gateway",
	"scheduler", "exporter", "ingest", "audit", "catalog", "shipping", "pricing", "webhooks",
}

var environments = []string{"production", "staging", "dev"}

// doc is one generated file: lines before the item, the item itself, lines after it, and the
// lines that replace the item when a later commit removes the credential.
type doc struct {
	path        string
	value       string // the seeded value(s) as written, joined by newlines (secrets only)
	pre         []string
	item        []string
	post        []string
	replacement []string
}

func (d doc) lines() []string { return concatLines(d.pre, d.item, d.post) }

func (d doc) sanitized() []string { return concatLines(d.pre, d.replacement, d.post) }

// span returns the 1-based first and last line of the item.
func (d doc) span() (start, end int) { return len(d.pre) + 1, len(d.pre) + len(d.item) }

func concatLines(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func content(lines []string) string { return strings.Join(lines, "\n") + "\n" }

// renderSecret places the credential of type st into a realistic file for the given variant.
func renderSecret(g *gen, st secretType, variant string) doc {
	fields := st.generate(g)
	svc := pick(g, services)
	multiline := strings.Contains(fields[0].Value, "\n")

	var syn syntax
	switch variant {
	case variantPlain, variantSplit:
		syn = pick(g, []syntax{goSyntax, pythonSyntax, tsSyntax})
	case variantConfig:
		if multiline && g.intn(2) == 0 {
			syn = keyFileSyntax
		} else {
			syn = pick(g, []syntax{dotenvSyntax, yamlSyntax, jsonSyntax, tfvarsSyntax})
		}
	case variantBase64:
		for i := range fields {
			fields[i].Value = base64.StdEncoding.EncodeToString([]byte(fields[i].Value))
		}
		if g.intn(2) == 0 {
			syn = k8sSecretSyntax
		} else {
			syn = goOpaqueSyntax(g)
		}
	case variantHistory:
		syn = pick(g, []syntax{goSyntax, pythonSyntax, tsSyntax, dotenvSyntax, yamlSyntax})
	}

	d := doc{path: syn.path(g, svc)}
	d.pre, d.post = syn.frame(g, svc)
	values := make([]string, 0, len(fields))
	for _, f := range fields {
		values = append(values, f.Value)
		name := syn.ident(f.Key)
		switch {
		case variant == variantSplit:
			d.item = append(d.item, syn.concat(name, splitValue(g, f.Value))...)
		case strings.Contains(f.Value, "\n"):
			d.item = append(d.item, syn.multi(name, f.Value)...)
		default:
			d.item = append(d.item, syn.assign(name, f.Value)...)
		}
		d.replacement = append(d.replacement, syn.envRef(name, f.Key)...)
	}
	d.value = strings.Join(values, "\n")
	return d
}

// splitValue cuts a value into source-code string fragments. Multi-line values (PEM) become one
// fragment per line with an escaped newline; single-line values are cut into 2-3 pieces.
func splitValue(g *gen, v string) []string {
	if strings.Contains(v, "\n") {
		lines := strings.Split(v, "\n")
		for i := range lines {
			lines[i] += `\n`
		}
		return lines
	}
	pieces := 2
	if len(v) > 60 {
		pieces = 3
	}
	var out []string
	rest := v
	for p := pieces; p > 1; p-- {
		minCut := 4
		maxCut := len(rest) - 4*(p-1)
		cut := g.between(minCut, max(minCut, min(maxCut, len(rest)/p+6)))
		out = append(out, rest[:cut])
		rest = rest[cut:]
	}
	return append(out, rest)
}

// valueFingerprint identifies a seeded value in the ground truth without storing it.
func valueFingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hexEncode(sum[:])
}

// firstLine returns s up to the first newline.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// preview keeps the first four characters of a value (a public format prefix such as "ghp_").
func preview(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 4 {
		v = v[:4]
	}
	return v + "..."
}

func hexEncode(b []byte) string {
	var sb strings.Builder
	sb.Grow(2 * len(b))
	for _, c := range b {
		sb.WriteByte(hexChars[c>>4])
		sb.WriteByte(hexChars[c&0x0f])
	}
	return sb.String()
}
