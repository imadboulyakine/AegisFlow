package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
)

// decoyKind is a family of look-alike values that are NOT secrets: documented examples,
// placeholders, references to a secret store, digests, identifiers, public keys and test
// vectors. Any finding on a decoy is a false positive.
type decoyKind struct {
	ID          string
	Description string
	render      func(g *gen, rep int) (doc, string) // returns the file and the type it resembles
}

func decoyKinds() []decoyKind {
	return []decoyKind{
		{"documented-example", "Vendor-documented example credentials (AWS docs, jwt.io)", decoyDocumentedExample},
		{"placeholder", "Template placeholders in example config and READMEs", decoyPlaceholder},
		{"secret-store-reference", "References to environment variables / CI secrets / Kubernetes secretKeyRef", decoySecretReference},
		{"truncated-token", "Malformed tokens with a real prefix but invalid length (validation tests)", decoyTruncated},
		{"image-digest", "Container image digests (sha256)", decoyImageDigest},
		{"commit-sha-pin", "GitHub Action references pinned to commit SHAs", decoyCommitPin},
		{"resource-identifier", "Azure tenant/subscription/client IDs (public identifiers)", decoyResourceID},
		{"integrity-hash", "Subresource-integrity and release checksums", decoyIntegrity},
		{"public-key-material", "Public keys and certificates (PEM, OpenSSH)", decoyPublicKey},
		{"test-vector", "High-entropy test data: digests, ETags, trace IDs, fingerprints", decoyTestVector},
	}
}

// awsDocsKeyID and awsDocsSecret rebuild the example values published in the AWS documentation.
// They are assembled from fragments so that the literal values do not appear in this file.
func awsDocsKeyID() string  { return "AKIA" + "IOSFODNN7" + "EXAMPLE" }
func awsDocsSecret() string { return "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCY" + "EXAMPLEKEY" }

// jwtIOExample recomputes the well-known example token shown on jwt.io (HS256, public signing
// input documented on the site).
func jwtIOExample() string {
	header, _ := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{"HS256", "JWT"})
	payload, _ := json.Marshal(struct {
		Sub  string `json:"sub"`
		Name string `json:"name"`
		Iat  int    `json:"iat"`
	}{"1234567890", "John Doe", 1516239022})
	signingInput := b64url(header) + "." + b64url(payload)
	mac := hmac.New(sha256.New, []byte("your-256-bit-"+"secret"))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64url(mac.Sum(nil))
}

func markdownDoc(g *gen, dir, svc string, intro, code []string, lang string) doc {
	return doc{
		path: g.path(dir + "/" + svc + ".md"),
		pre:  append(append([]string{"# " + upperFirst(svc) + " setup", ""}, intro...), "", "```"+lang),
		item: code,
		post: []string{"```", "", "Real credentials are issued by the platform team and stored in Key Vault."},
	}
}

func goTestDoc(g *gen, svc, name string, item []string) doc {
	pre := []string{
		"package " + svc,
		"",
		`import "testing"`,
		"",
		"func Test" + name + "(t *testing.T) {",
	}
	post := []string{"\tif got == \"\" {", "\t\tt.Fatal(\"empty\")", "\t}", "}"}
	return doc{path: g.path("internal/" + svc + "/" + strings.ToLower(name) + "_test.go"), pre: pre, item: item, post: post}
}

func decoyDocumentedExample(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	switch rep % 3 {
	case 0:
		return markdownDoc(g, "docs", svc,
			[]string{"Configure the AWS CLI. The values below are the documented AWS examples, not real keys:"},
			[]string{"export AWS_ACCESS_KEY_ID=" + awsDocsKeyID(), "export AWS_SECRET_ACCESS_KEY=" + awsDocsSecret()}, "sh"), "aws-access-key"
	case 1:
		return goTestDoc(g, svc, "ParseAccessKeyID", []string{"\tgot := parseKeyID(" + quote(awsDocsKeyID()) + ") // AWS documentation example"}), "aws-access-key"
	default:
		return markdownDoc(g, "docs", svc,
			[]string{"Decode a token locally. Example token from jwt.io:"},
			[]string{"curl -H \"Authorization: Bearer " + jwtIOExample() + "\" http://localhost:8080/api/me"}, "sh"), "jwt"
	}
}

func decoyPlaceholder(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	envExample := func(line string) doc {
		return doc{
			path: g.path("deploy/" + svc + "/.env.example"),
			pre:  []string{"# Copy to .env and fill in real values (never commit .env)", "LOG_LEVEL=info"},
			item: []string{line},
			post: []string{"HTTP_PORT=8080"},
		}
	}
	switch rep % 5 {
	case 0:
		return envExample("GITHUB_TOKEN=ghp_" + strings.Repeat("x", 36)), "github-pat-classic"
	case 1:
		return markdownDoc(g, "docs", svc, []string{"Set the application credentials:"},
			[]string{"export AZURE_CLIENT_SECRET=<your-client-secret>"}, "sh"), "azure-entra-client-secret"
	case 2:
		return doc{
			path: g.path("config/" + svc + ".example.yaml"),
			pre:  []string{"service: " + svc, "credentials:"},
			item: []string{`  slackBotToken: "xoxb-REPLACE-ME"`},
			post: []string{"logging:", "  level: info"},
		}, "slack-bot-token"
	case 3:
		return envExample("DATABASE_URL=postgres://user:password@localhost:5432/app"), "postgres-uri"
	default:
		return doc{
			path: g.path("config/" + svc + ".sample.yaml"),
			pre:  []string{"service: " + svc, "maps:"},
			item: []string{`  apiKey: "YOUR_API_KEY_HERE"`},
			post: []string{"  region: westeurope"},
		}, "generic-api-key"
	}
}

func decoySecretReference(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	switch rep % 5 {
	case 0:
		return doc{
			path: g.path("internal/" + svc + "/env.go"),
			pre:  []string{"package " + svc, "", `import "os"`, "", "func tokenFromEnv() string {"},
			item: []string{`	token := os.Getenv("GITHUB_TOKEN")`},
			post: []string{"\treturn token", "}"},
		}, "github-pat-classic"
	case 1:
		return doc{
			path: g.path(".github/workflows/" + svc + "-deploy.yml"),
			pre:  []string{"name: deploy " + svc, "on: workflow_dispatch", "jobs:", "  deploy:", "    runs-on: ubuntu-latest", "    env:"},
			item: []string{"      AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}"},
			post: []string{"    steps:", "      - run: ./deploy.sh"},
		}, "azure-entra-client-secret"
	case 2:
		return doc{
			path: g.path("deploy/" + svc + "/compose.yaml"),
			pre:  []string{"services:", "  db:", "    image: postgres:17", "    environment:"},
			item: []string{"      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set in .env}"},
			post: []string{"    ports:", `      - "127.0.0.1:5432:5432"`},
		}, "postgres-uri"
	case 3:
		return doc{
			path: g.path("web/src/" + svc + "/notify.ts"),
			pre:  []string{`import { post } from "../http";`, ""},
			item: []string{`const slackToken = process.env.SLACK_BOT_TOKEN ?? "";`},
			post: []string{"", "export const notify = (text: string) => post(\"/notify\", { text, slackToken });"},
		}, "slack-bot-token"
	default:
		return doc{
			path: g.path("deploy/k8s/" + svc + "-deployment.yaml"),
			pre:  []string{"apiVersion: apps/v1", "kind: Deployment", "metadata:", "  name: " + svc, "spec:", "  template:", "    spec:", "      containers:", "        - name: " + svc, "          env:"},
			item: []string{"            - name: PAYMENTS_API_KEY", "              valueFrom:", "                secretKeyRef:", "                  name: " + svc + "-credentials", "                  key: api-key"},
			post: []string{"          image: " + svc + ":latest"},
		}, "generic-api-key"
	}
}

func decoyTruncated(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	cases := []struct{ value, resembles string }{
		{"ghp_" + g.str(alnumChars, 10), "github-pat-classic"},
		{"AKIA" + g.str(base32Chars, 8), "aws-access-key"},
		{"xoxb-" + g.str(digitChars, 4), "slack-bot-token"},
		{"github_pat_" + g.str(alnumChars, 12), "github-pat-fine-grained"},
		{g.str(alnumChars, 3) + "1Q~" + g.str(alnumChars, 6), "azure-entra-client-secret"},
	}
	c := cases[rep%len(cases)]
	return goTestDoc(g, svc, "RejectsMalformedCredential", []string{
		"\tgot := validate(" + quote(c.value) + ") // too short: must be rejected",
	}), c.resembles
}

func decoyImageDigest(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	digest := "sha256:" + g.str(hexChars, 64)
	if rep%2 == 0 {
		return doc{
			path: g.path("build/" + svc + "/Dockerfile"),
			pre:  []string{"# syntax=docker/dockerfile:1"},
			item: []string{"FROM golang:1.27-alpine@" + digest + " AS build"},
			post: []string{"WORKDIR /src", "COPY . .", "RUN go build -o /out/app ./cmd/app"},
		}, "generic-api-key"
	}
	return doc{
		path: g.path("deploy/k8s/" + svc + "-image.yaml"),
		pre:  []string{"apiVersion: apps/v1", "kind: Deployment", "metadata:", "  name: " + svc, "spec:", "  template:", "    spec:", "      containers:", "        - name: " + svc},
		item: []string{"          image: ghcr.io/contoso/" + svc + "@" + digest},
	}, "generic-api-key"
}

func decoyCommitPin(g *gen, _ int) (doc, string) {
	svc := pick(g, services)
	action := pick(g, []string{"actions/checkout", "actions/setup-go", "actions/cache", "docker/build-push-action"})
	return doc{
		path: g.path(".github/workflows/" + svc + "-ci.yml"),
		pre:  []string{"name: " + svc + " ci", "on: [pull_request]", "permissions:", "  contents: read", "jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps:"},
		item: []string{"      - uses: " + action + "@" + g.str(hexChars, 40) + " # v4.2.2"},
		post: []string{"      - run: make test"},
	}, "generic-api-key"
}

func decoyResourceID(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	id := g.uuid()
	switch rep % 5 {
	case 0:
		return doc{
			path: g.path("deploy/" + svc + "/.env.azure"),
			pre:  []string{"# Public identifiers for OIDC login (not secrets)"},
			item: []string{"AZURE_TENANT_ID=" + id},
			post: []string{"AZURE_LOCATION=westeurope"},
		}, "azure-entra-client-secret"
	case 1:
		return doc{
			path: g.path("infra/prod/" + svc + "-ids.auto.tfvars"),
			pre:  []string{`location = "westeurope"`},
			item: []string{"subscription_id = " + quote(id)},
		}, "azure-entra-client-secret"
	case 2:
		return doc{
			path: g.path("src/" + upperFirst(svc) + ".Api/appsettings.json"),
			pre:  []string{"{", `  "AzureAd": {`, `    "Instance": "https://login.microsoftonline.com/",`},
			item: []string{`    "ClientId": ` + quote(id) + ","},
			post: []string{`    "CallbackPath": "/signin-oidc"`, "  }", "}"},
		}, "azure-entra-client-secret"
	case 3:
		return doc{
			path: g.path("infra/" + svc + "-role.json"),
			pre:  []string{"{", `  "roleName": "AcrPull",`},
			item: []string{`  "scope": "/subscriptions/` + id + `/resourceGroups/rg-` + svc + `",`},
			post: []string{`  "principalType": "ServicePrincipal"`, "}"},
		}, "azure-entra-client-secret"
	default:
		return doc{
			path: g.path(".github/workflows/" + svc + "-azure.yml"),
			pre:  []string{"name: " + svc + " azure", "on: workflow_dispatch", "permissions:", "  id-token: write", "jobs:", "  login:", "    runs-on: ubuntu-latest", "    env:"},
			item: []string{"      AZURE_CLIENT_ID: " + id},
			post: []string{"    steps:", "      - run: echo login"},
		}, "azure-entra-client-secret"
	}
}

func decoyIntegrity(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	switch rep % 3 {
	case 0:
		sri := "sha384-" + base64.StdEncoding.EncodeToString(g.bytes(48))
		return doc{
			path: g.path("web/public/" + svc + ".html"),
			pre:  []string{"<!doctype html>", "<html>", "<head>"},
			item: []string{`  <script src="/static/` + svc + `.js" integrity="` + sri + `" crossorigin="anonymous"></script>`},
			post: []string{"</head>", "</html>"},
		}, "generic-api-key"
	case 1:
		return doc{
			path: g.path("dist/" + svc + "-checksums.txt"),
			item: []string{g.str(hexChars, 64) + "  " + svc + "_linux_amd64.tar.gz"},
			post: []string{g.str(hexChars, 64) + "  " + svc + "_linux_arm64.tar.gz"},
		}, "generic-api-key"
	default:
		return doc{
			path: g.path("web/" + svc + "-assets.json"),
			pre:  []string{"{", `  "file": "` + svc + `.wasm",`},
			item: []string{`  "integrity": "sha512-` + base64.StdEncoding.EncodeToString(g.bytes(64)) + `"`},
			post: []string{"}"},
		}, "generic-api-key"
	}
}

func decoyPublicKey(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	switch rep % 3 {
	case 0:
		der := append([]byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04}, g.bytes(64)...)
		return doc{path: g.path("keys/" + svc + "-cosign.pub"), item: strings.Split(pemBlock("PUBLIC KEY", der, 64), "\n")}, "private-key-pem"
	case 1:
		der := append([]byte{0x30, 0x82, 0x03, 0x0d, 0x30, 0x82, 0x01, 0xf5, 0xa0, 0x03, 0x02, 0x01, 0x02}, g.bytes(770)...)
		return doc{path: g.path("deploy/tls/" + svc + "-ca.crt"), item: strings.Split(pemBlock("CERTIFICATE", der, 64), "\n")}, "private-key-pem"
	default:
		blob := binary.BigEndian.AppendUint32(nil, 11)
		blob = append(blob, "ssh-ed25519"...)
		blob = binary.BigEndian.AppendUint32(blob, 32)
		blob = append(blob, g.bytes(32)...)
		return doc{
			path: g.path("ops/ssh/" + svc + "_authorized_keys"),
			pre:  []string{"# Deploy keys allowed to log in to the " + svc + " bastion"},
			item: []string{"ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " deploy@" + svc},
		}, "private-key-pem"
	}
}

func decoyTestVector(g *gen, rep int) (doc, string) {
	svc := pick(g, services)
	var line string
	switch rep % 5 {
	case 0:
		sum := sha256.Sum256([]byte(svc + " fixture"))
		line = "\twant := " + quote(hexEncode(sum[:]))
	case 1:
		line = "\tetag := " + quote(`W/\"`+g.str(hexChars, 32)+`\"`)
	case 2:
		line = "\tfingerprint := " + quote("SHA256:"+base64.RawStdEncoding.EncodeToString(g.bytes(32)))
	case 3:
		line = "\trequestID := " + quote(g.uuid())
	default:
		line = "\ttraceparent := " + quote("00-"+g.str(hexChars, 32)+"-"+g.str(hexChars, 16)+"-01")
	}
	return goTestDoc(g, svc, "Vector", []string{line}), "generic-api-key"
}
