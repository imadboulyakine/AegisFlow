package main

import (
	"strconv"
	"strings"
)

// syntax renders key/value assignments in one file format (a programming language or a config
// format) and frames them with realistic surrounding content.
type syntax struct {
	id     string
	path   func(g *gen, svc string) string
	frame  func(g *gen, svc string) (pre, post []string)
	ident  func(key string) string
	assign func(name, value string) []string
	multi  func(name, value string) []string          // value contains newlines
	concat func(name string, parts []string) []string // value split across lines
	envRef func(name, key string) []string            // replacement once the credential is removed
}

// ---------------------------------------------------------------------------------------------
// Identifier styles

func words(key string) []string { return strings.Split(strings.ToLower(key), "_") }

func camelCase(key string) string {
	w := words(key)
	for i := 1; i < len(w); i++ {
		w[i] = upperFirst(w[i])
	}
	return strings.Join(w, "")
}

func pascalCase(key string) string {
	w := words(key)
	for i := range w {
		w[i] = upperFirst(w[i])
	}
	return strings.Join(w, "")
}

func snakeCase(key string) string { return strings.ToLower(key) }

func identity(key string) string { return key }

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func quote(s string) string { return `"` + s + `"` }

// escapeNewlines renders a multi-line value as a single-line string with \n escapes.
func escapeNewlines(v string) string { return strings.ReplaceAll(v, "\n", `\n`) }

// ---------------------------------------------------------------------------------------------
// Filler corpora (benign code and configuration around the seeded items)

var goFillers = []string{
	`// retryDelay returns the back-off before the given attempt.
func retryDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	return time.Duration(attempt*attempt) * 100 * time.Millisecond
}`,
	`// formatAmount renders minor currency units as a decimal string.
func formatAmount(minor int64) string {
	return fmt.Sprintf("%d.%02d", minor/100, minor%100)
}`,
	`// Client talks to the upstream service.
type Client struct {
	BaseURL string
	Timeout time.Duration
}`,
	`func (c *Client) endpoint(path string) string {
	return c.BaseURL + "/" + path
}`,
	`var defaultRegions = []string{"westeurope", "northeurope", "francecentral"}`,
	`func pageCount(total, size int) int {
	if size <= 0 {
		return 0
	}
	return (total + size - 1) / size
}`,
}

var pythonFillers = []string{
	`def retry_delay(attempt: int) -> float:
    return 0.0 if attempt <= 0 else 0.1 * attempt * attempt`,
	`class Client:
    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self.base_url = base_url
        self.timeout = timeout`,
	`DEFAULT_REGIONS = ["westeurope", "northeurope", "francecentral"]`,
	`def page_count(total: int, size: int) -> int:
    return 0 if size <= 0 else (total + size - 1) // size`,
	`def format_amount(minor: int) -> str:
    return f"{minor // 100}.{minor % 100:02d}"`,
}

var tsFillers = []string{
	`export function retryDelay(attempt: number): number {
  return attempt <= 0 ? 0 : 100 * attempt * attempt;
}`,
	`export interface ClientOptions {
  baseUrl: string;
  timeoutMs: number;
}`,
	`export const defaultRegions = ["westeurope", "northeurope", "francecentral"];`,
	`export function pageCount(total: number, size: number): number {
  return size <= 0 ? 0 : Math.ceil(total / size);
}`,
}

var dotenvFillers = []string{
	"LOG_LEVEL=info", "HTTP_PORT=8080", "FEATURE_EXPORT=true", "REGION=westeurope",
	"REQUEST_TIMEOUT=5s", "MAX_CONNECTIONS=20", "CACHE_TTL=300",
}

var yamlFillers = []string{
	"server:\n  port: 8080\n  readTimeout: 5s",
	"logging:\n  level: info\n  format: json",
	"features:\n  export: true\n  search: false",
	"limits:\n  maxConnections: 20\n  cacheTTL: 300",
}

var tfvarsFillers = []string{
	`location = "westeurope"`, `environment = "prod"`, `sku_name = "B_Standard_B1ms"`,
	`log_retention_days = 30`, `enable_public_access = false`,
}

// ---------------------------------------------------------------------------------------------
// Programming languages

var goSyntax = syntax{
	id: "go",
	path: func(g *gen, svc string) string {
		return g.path("internal/" + svc + "/" + pick(g, []string{"client", "config", "provider", "settings", "store", "notify"}) + ".go")
	},
	frame: func(g *gen, svc string) ([]string, []string) {
		pre := []string{"package " + svc, "", "import (", "\t\"fmt\"", "\t\"os\"", "\t\"time\"", ")", ""}
		pre = append(pre, g.fillers(goFillers, 0, 2)...)
		post := append([]string{""}, g.fillers(goFillers, 1, 2)...)
		return pre, post
	},
	ident:  camelCase,
	assign: func(name, v string) []string { return []string{"var " + name + " = " + quote(v)} },
	multi: func(name, v string) []string {
		ls := strings.Split(v, "\n")
		ls[0] = "var " + name + " = `" + ls[0]
		ls[len(ls)-1] += "`"
		return ls
	},
	concat: func(name string, parts []string) []string {
		out := []string{"var " + name + " = " + quote(parts[0]) + " +"}
		for i, p := range parts[1:] {
			line := "\t" + quote(p)
			if i < len(parts)-2 {
				line += " +"
			}
			out = append(out, line)
		}
		return out
	},
	envRef: func(name, key string) []string { return []string{"var " + name + " = os.Getenv(" + quote(key) + ")"} },
}

// goOpaqueSyntax is Go source where the (base64) value sits in a variable whose name gives no hint
// that it holds a credential.
func goOpaqueSyntax(g *gen) syntax {
	s := goSyntax
	s.id = "go-opaque"
	base := pick(g, []string{"bootstrapBlob", "seedPayload", "initBundle", "fixtureData"})
	n := 0
	s.ident = func(string) string {
		n++
		if n == 1 {
			return base
		}
		return base + strconv.Itoa(n)
	}
	return s
}

var pythonSyntax = syntax{
	id: "python",
	path: func(g *gen, svc string) string {
		return g.path("scripts/" + svc + "_" + pick(g, []string{"sync", "export", "backfill", "report", "notify"}) + ".py")
	},
	frame: func(g *gen, svc string) ([]string, []string) {
		pre := []string{`"""Helpers for the ` + svc + ` service."""`, "", "import os", "import time", "", ""}
		pre = append(pre, g.fillers(pythonFillers, 0, 2)...)
		post := append([]string{"", ""}, g.fillers(pythonFillers, 1, 2)...)
		return pre, post
	},
	ident:  identity,
	assign: func(name, v string) []string { return []string{name + " = " + quote(v)} },
	multi: func(name, v string) []string {
		ls := strings.Split(v, "\n")
		ls[0] = name + ` = """` + ls[0]
		ls[len(ls)-1] += `"""`
		return ls
	},
	concat: func(name string, parts []string) []string {
		out := []string{name + " = ("}
		for _, p := range parts {
			out = append(out, "    "+quote(p))
		}
		return append(out, ")")
	},
	envRef: func(name, key string) []string { return []string{name + ` = os.environ.get(` + quote(key) + `, "")`} },
}

var tsSyntax = syntax{
	id: "typescript",
	path: func(g *gen, svc string) string {
		return g.path("web/src/" + svc + "/" + pick(g, []string{"client", "config", "api", "settings"}) + ".ts")
	},
	frame: func(g *gen, _ string) ([]string, []string) {
		pre := []string{`import { request } from "../http";`, ""}
		pre = append(pre, g.fillers(tsFillers, 0, 2)...)
		post := append([]string{""}, g.fillers(tsFillers, 1, 2)...)
		return pre, post
	},
	ident:  camelCase,
	assign: func(name, v string) []string { return []string{"export const " + name + " = " + quote(v) + ";"} },
	multi: func(name, v string) []string {
		ls := strings.Split(v, "\n")
		ls[0] = "export const " + name + " = `" + ls[0]
		ls[len(ls)-1] += "`;"
		return ls
	},
	concat: func(name string, parts []string) []string {
		out := []string{"export const " + name + " ="}
		for i, p := range parts {
			sep := " +"
			if i == len(parts)-1 {
				sep = ";"
			}
			out = append(out, "  "+quote(p)+sep)
		}
		return out
	},
	envRef: func(name, key string) []string {
		return []string{"export const " + name + " = process.env." + key + ` ?? "";`}
	},
}

// ---------------------------------------------------------------------------------------------
// Configuration formats

var dotenvSyntax = syntax{
	id:   "dotenv",
	path: func(g *gen, svc string) string { return g.path("deploy/" + svc + "/.env." + pick(g, environments)) },
	frame: func(g *gen, svc string) ([]string, []string) {
		pre := []string{"# " + svc + " service configuration"}
		for _, i := range g.r.Perm(len(dotenvFillers))[:g.between(2, 4)] {
			pre = append(pre, dotenvFillers[i])
		}
		post := []string{dotenvFillers[g.intn(len(dotenvFillers))]}
		return pre, post
	},
	ident:  identity,
	assign: func(name, v string) []string { return []string{name + "=" + v} },
	multi:  func(name, v string) []string { return []string{name + "=" + quote(escapeNewlines(v))} },
	envRef: func(name, _ string) []string {
		return []string{"# " + name + " is injected by the deployment pipeline"}
	},
}

var yamlSyntax = syntax{
	id: "yaml",
	path: func(g *gen, svc string) string {
		return g.path("config/" + svc + "." + pick(g, environments) + ".yaml")
	},
	frame: func(g *gen, svc string) ([]string, []string) {
		pre := append([]string{"service: " + svc}, g.fillers(yamlFillers, 1, 2)...)
		pre = append(pre, "credentials:")
		post := g.fillers(yamlFillers, 0, 2)
		return pre, post
	},
	ident:  camelCase,
	assign: func(name, v string) []string { return []string{"  " + name + ": " + quote(v)} },
	multi: func(name, v string) []string {
		out := []string{"  " + name + ": |"}
		for l := range strings.SplitSeq(v, "\n") {
			out = append(out, "    "+l)
		}
		return out
	},
	envRef: func(name, key string) []string { return []string{"  " + name + ": ${" + key + "}"} },
}

var jsonSyntax = syntax{
	id: "json",
	path: func(g *gen, svc string) string {
		return g.path("src/" + upperFirst(svc) + ".Api/appsettings." + upperFirst(pick(g, environments)) + ".json")
	},
	frame: func(_ *gen, svc string) ([]string, []string) {
		pre := []string{
			"{",
			`  "Logging": { "LogLevel": { "Default": "Information" } },`,
			`  "AllowedHosts": "*",`,
			`  "Service": ` + quote(svc) + ",",
			`  "Credentials": {`,
		}
		post := []string{`    "Region": "westeurope"`, "  }", "}"}
		return pre, post
	},
	ident:  pascalCase,
	assign: func(name, v string) []string { return []string{"    " + quote(name) + ": " + quote(v) + ","} },
	multi: func(name, v string) []string {
		return []string{"    " + quote(name) + ": " + quote(escapeNewlines(v)) + ","}
	},
	envRef: func(name, _ string) []string { return []string{"    " + quote(name) + `: "",`} },
}

var tfvarsSyntax = syntax{
	id: "tfvars",
	path: func(g *gen, svc string) string {
		return g.path("infra/" + pick(g, environments) + "/" + svc + ".auto.tfvars")
	},
	frame: func(g *gen, _ string) ([]string, []string) {
		var pre []string
		for _, i := range g.r.Perm(len(tfvarsFillers))[:g.between(2, 4)] {
			pre = append(pre, tfvarsFillers[i])
		}
		post := []string{"", "tags = {", `  owner = "platform"`, "}"}
		return pre, post
	},
	ident:  snakeCase,
	assign: func(name, v string) []string { return []string{name + " = " + quote(v)} },
	multi: func(name, v string) []string {
		out := []string{name + " = <<EOT"}
		out = append(out, strings.Split(v, "\n")...)
		return append(out, "EOT")
	},
	envRef: func(name, _ string) []string { return []string{"# " + name + " is supplied via TF_VAR_" + name} },
}

// keyFileSyntax is a committed key file: the whole file is the item.
var keyFileSyntax = syntax{
	id: "keyfile",
	path: func(g *gen, svc string) string {
		return g.path(pick(g, []string{"deploy/tls/" + svc + ".key", "ops/ssh/" + svc + "_deploy_key"}))
	},
	frame:  func(*gen, string) ([]string, []string) { return nil, nil },
	ident:  identity,
	assign: func(_, v string) []string { return []string{v} },
	multi:  func(_, v string) []string { return strings.Split(v, "\n") },
	envRef: func(string, string) []string { return nil },
}

// k8sSecretSyntax is a Kubernetes Secret manifest; values are expected to be base64 already.
var k8sSecretSyntax = syntax{
	id:   "k8s-secret",
	path: func(g *gen, svc string) string { return g.path("deploy/k8s/" + svc + "-secret.yaml") },
	frame: func(g *gen, svc string) ([]string, []string) {
		pre := []string{
			"apiVersion: v1",
			"kind: Secret",
			"metadata:",
			"  name: " + svc + "-credentials",
			"  namespace: " + pick(g, []string{"apps", "platform", svc}),
			"  labels:",
			"    app.kubernetes.io/name: " + svc,
			"type: Opaque",
			"data:",
		}
		return pre, nil
	},
	ident:  identity,
	assign: func(name, v string) []string { return []string{"  " + name + ": " + v} },
	envRef: func(string, string) []string { return nil },
}
