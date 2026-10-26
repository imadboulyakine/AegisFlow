# normalize test fixtures

Fixtures are real tool output unless marked **hand-built**. Real outputs were generated on
2026-10-26 in the AegisFlow cloud sandbox, then trimmed to a few KB (fewer components, rules and
OSV fields; JSON re-indented). Local scratch paths were rewritten (`/src/vulnapp`, relative paths)
and gitleaks was run with `--redact`, so no fixture contains a secret value.

| File | Producer | Input |
|---|---|---|
| `cyclonedx-1.4-syft-dir.json`, `cyclonedx-1.5-syft-dir.json`, `cyclonedx-1.7-syft-dir.json` | syft 1.55.0 `-o cyclonedx-json@<v>` | `vulnapp` demo module (golang.org/x/text v0.3.7, old golang.org/x/net) |
| `cyclonedx-1.6-syft-image.json` | syft 1.55.0 (`syft convert … -o cyclonedx-json@1.6`) | `gcr.io/distroless/static-debian13:nonroot@sha256:18f4…2c99` |
| `spdx-2.3-syft-dir.json` | syft 1.55.0 `-o spdx-json` | `vulnapp` demo module |
| `spdx-2.3-syft-image.json` | syft 1.55.0 `-o spdx-json` | distroless image above |
| `govulncheck-source.json` | govulncheck v1.9.0 `-format json` (offline DB built from the OSV Go export; `db` rewritten to `https://vuln.go.dev`) | `vulnapp`: GO-2022-1059 called, GO-2026-5029 package-level, GO-2023-2102 module-level |
| `openvex-govulncheck.json` | govulncheck v1.9.0 `-format openvex` | `vulnapp` |
| `sarif-gitleaks.json` | gitleaks 8.30.1 `dir --redact -f sarif` | runtime-generated synthetic tokens (redacted) |
| `sarif-gosec.json` | gosec 2.30.0 `-fmt sarif` (CWE taxonomy dropped) | small insecure Go program |
| `sarif-zizmor.json` | zizmor 1.16.0 `--offline --format sarif` | insecure GitHub Actions workflow |
| `sarif-trivy-config.json` | trivy 0.76.1 `config --format sarif` (embedded checks) | insecure Dockerfile |
| `grype-image-handbuilt.json` | **hand-built** after Grype's JSON presenter model (`matches`, `ignoredMatches`, `source`, `distro`, `descriptor`); Grype cannot download its DB in the sandbox | — |
| `cyclonedx-1.6-vdr-handbuilt.json` | **hand-built**, Trivy-style CycloneDX 1.6 with a `vulnerabilities` section (VDR/VEX) | — |
| `openvex-handbuilt.json` | **hand-built**, vexctl-style OpenVEX 0.2.0 | — |

Identifiers containing `fixture` or `CVE-2099-` are synthetic. Golden outputs live in `golden/`;
regenerate them with `go test ./internal/evidence/normalize -run TestGolden -update` and review
the diff.
