# AegisFlow — HTTP API and configuration

Contract of the Phase 2 evidence-ingestion and findings API, and every `AEGISFLOW_*` setting.
Architecture context: ARCHITECTURE.md §4, §7, §8; decisions: ADR-016, ADR-020…023.

Last updated: 2026-10-26 (Phase 2)

## 1. API

### `POST /api/v1/ingest`

This is the only route with OIDC, and the only one with a large body limit.

- **Auth:** `Authorization: Bearer <GitHub Actions OIDC token>`, minted with `core.getIDToken('<AEGISFLOW_OIDC_AUDIENCE>')`. Verification uses `ghoidc.Middleware`. Its errors go through the server's `writeProblem`, so the problem body carries `requestId`.
- **Request:** `Content-Type: application/json` (otherwise **415**).
- **Body limits and deadlines:**
  - The body limit is **16 MiB + 64 KiB** on this route only. Every other route keeps the 1 MiB limit through the `limitBody` middleware.
  - Evidence is limited to 12 MiB after decoding (`ingest.DefaultMaxEvidenceBytes`).
  - After authentication, the read deadline becomes 2 min and the write deadline 3 min.

**Envelope.** Decoding is strict: unknown fields, trailing data and a missing artifact are all **400**.

```json
{
  "artifact": {"kind": "container-image|binary|source|sbom", "name": "ghcr.io/o/r", "digest": "sha256:<64 hex>"},
  "commit": "<40|64 lowercase hex — must equal the token's sha>",
  "format": "cyclonedx|spdx|sarif|grype|govulncheck|openvex",   // optional; detected when omitted
  "evidence": "<standard padded base64 of the exact file bytes>",
  "evidenceSha256": "<hex>"                                        // optional integrity assertion (422 on mismatch)
}
```

I chose a base64 envelope over embedded JSON or multipart. The reason is that the stored bytes and their SHA-256 are then exactly what CI produced (`sha256sum file`), which Phase 3 attestations can reference. Example CI command:

```sh
jq -n --rawfile ev grype.json --arg d "$DIGEST" --arg c "$GITHUB_SHA" \
  '{artifact:{kind:"container-image",name:"ghcr.io/o/r",digest:$d},commit:$c,evidence:($ev|@base64)}'
```

**Responses.** The server answers **201** when the evidence row was created and **200** for an idempotent replay. Response body:

```json
{
  "projectId": 1, "runId": 2, "artifactId": 3,
  "evidence": {"id", "sha256", "size", "uploadSha256", "streamWrapped"?, "created", "format", "formatVersion", "tool": {"name", "version"}},
  "counts": {"components", "skippedComponents", "vulnerabilities", "findingsNew", "findingsSeen",
             "findingsReopened", "findingsFixed", "vexStatements", "vexStatusChanges"},
  "scored": 4, "tiers": {"P1": 1, "P2": 0, "P3": 3},
  "topFindings": [{"id", "vulnId", "purl", "status", "score", "tier", "reason"}],
  "warnings": ["the document's subject digest … differs from artifact.digest …"]
}
```

`topFindings` holds at most 10 entries. `warnings` is optional.

**Errors.** All errors are problem JSON.

| Status | Cause |
|---|---|
| 503 | Ingestion is not configured (no database or no OIDC). |
| 401 / 403 / 503 | OIDC middleware rejections. |
| 400 | Bad envelope, artifact, commit or format, or bad claims. |
| 403 | Commit mismatch (`CheckCommit`). |
| 413 | The body is too large, or a normalizer size or limit was exceeded. |
| 415 | Wrong content type. |
| 422 | Unknown or invalid format, store validation failure, or `evidenceSha256` mismatch. |
| 409 | Store conflict (a run re-recorded with another sha, ref or event, or a digest recorded with another kind). |
| 500 | Internal error. The detail is generic; the error is logged. |

### `GET /api/v1/findings`

- **Query parameters:** `tier=P1|P2|P3`, `status=open|fixed|vex_not_affected|accepted`, `kind=vulnerability|code|secret|config|dast`, `artifact=<id>`, `limit=1..500`, `cursor=<nextCursor>`.
- **Validation:** unknown or repeated parameters are **400**. A malformed cursor is **400**.
- **Response:** `{"findings": [...], "nextCursor": ""}`.
- **Order:** risk descending, unscored last, then ID descending (store keyset pagination).
- **Item fields:** `id, artifactId, kind, title, severity, status, ruleId?, tools[], vulnerability{id, aliases[], severity}|null, component{purl, name, version?, ecosystem?, direct}|null, fixedVersions[], reachability, location?, risk{score, tier, action, reason, flags[], scoredAt}|null, firstSeenRun, lastSeenRun, updatedAt`.

### `GET /api/v1/findings/{id}`

- Returns the same object as a list item, plus `message`, `vulnerability.{summary, cvss[], cwes[], published}` and `risk.explanation`.
- `risk.explanation` is the full stored `risk.Result`: scorer, score, tier, action, flags, factors[], reason.
- A non-numeric, zero or unknown ID returns **404**.

### Read API protection

- **Default:** both read routes answer **404**, exactly like an unknown route. They are never exposed unauthenticated by default.
- **With `AEGISFLOW_DEV_READONLY_API=true`:** only loopback TCP peers are served (127.0.0.0/8, ::1, v4-mapped). Others get **403**. Forwarding headers are not trusted.
- **No database:** **503**.
- **Phase 4:** the routes move behind Container Apps / Entra ID auth. This is in the code comments and should go into ARCHITECTURE §8.

### `GET /readyz`

- Unchanged when no database is configured (`{"status":"ready"}`).
- With a database it pings with a 2 s timeout. The answer is `{"status":"ready","checks":{"database":"ok"}}`, or 503 with `"database":"unavailable"`. The error goes only to the log.
- `/healthz` stays dependency-free.

## 2. Configuration

| Variable | Default | Validation / effect |
|---|---|---|
| `AEGISFLOW_DATABASE_URL` | unset | Already existed. When set: store open (30 s timeout) and migrate at startup, **fatal on failure**, read API backend, readiness check. Logged only redacted. |
| `AEGISFLOW_OIDC_AUDIENCE` | unset | At most 256 bytes, no spaces. `ghoidc.NewVerifier` enforces the audience rules (refuses `api://AzureADTokenExchange`, GitHub's default audience, and so on) **before any I/O**; startup fails on error. |
| `AEGISFLOW_OIDC_ALLOWED_REPOSITORY_IDS` / `_OWNER_IDS` | unset | Comma lists of positive canonical decimal int64. Names, `012`, `-5`, `0` and empty entries are refused. At most 64 entries. At least one list is required with the audience. |
| `AEGISFLOW_OIDC_ALLOWED_REFS` / `_ENVIRONMENTS` | unset | Optional exact-match lists. |
| `AEGISFLOW_OIDC_ISSUER` | GitHub | https, or http on loopback only. Used for GHE slugs and tests. |
| `AEGISFLOW_INTEL_KEV_URL` | `intel.DefaultKEVURL` (cisa.gov) | https, or http on loopback; no credentials. `intel.KEVMirrorURL` is the documented alternative. |
| `AEGISFLOW_INTEL_EPSS_URL` | `intel.DefaultEPSSBulkURL` | The EPSS **bulk CSV** URL, same URL rules. |
| `AEGISFLOW_INTEL_REFRESH_INTERVAL` | `24h` | `0` disables the refresher; otherwise between 1m and 168h. |
| `AEGISFLOW_DEFAULT_EXPOSURE` | `unknown` | `internet`, `internal`, `build` or `unknown`. `unknown` scores as 1.0 and is flagged `exposure-unknown`; it never triggers the KEV override. |
| `AEGISFLOW_DEV_READONLY_API` | `false` | Boolean. Enables the loopback-only read API. |

**Gating rules:**
- Ingestion is enabled only with the database plus the audience plus at least one allow-list (`Config.IngestEnabled()`).
- A partial OIDC configuration (lists without an audience or the reverse) is a startup error.
- OIDC configured without a database logs a warning and starts with ingest disabled (503).
- With nothing configured, the server behaves exactly as before.

