# Security policy

AegisFlow is a personal final-year engineering project (PFE): a DevSecOps and software supply-chain
security platform. Security reports are welcome and taken seriously, on a best-effort basis.

## Supported versions

Only the `main` branch is supported. There are no released versions yet; fixes land on `main`.

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

- Use GitHub's **private vulnerability reporting**: the repository's *Security* tab →
  *Report a vulnerability*. This creates a private advisory visible only to the maintainer.
- If that option is not available, contact the maintainer through their GitHub profile
  ([@imadboulyakine](https://github.com/imadboulyakine)) and ask for a private channel. Do not send
  exploit details until one is agreed.

Please include the affected component (Go API, web dashboard, container image, CI workflow, Bicep),
reproduction steps, impact, and any suggested fix.

## What to expect

| Step | Target (best effort) |
|---|---|
| Acknowledgement | within 7 days |
| Initial assessment | within 14 days |
| Fix or mitigation for confirmed high/critical issues | as soon as practical, prioritised over feature work |

Reporters are credited in the advisory unless they ask otherwise.

## Scope

In scope: code and configuration in this repository — the `aegisflow` binary and its HTTP API, the
embedded dashboard, the container image built from `Dockerfile`, GitHub Actions workflows, and
infrastructure-as-code once added under `infra/`.

Out of scope: third-party services (GitHub, Azure, Sigstore) and vulnerabilities in upstream
dependencies that are already publicly known — those are tracked by Dependabot and the CI scanners.
Never test against infrastructure you do not own.

## How the project protects itself

The threat model and controls are documented in [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).
Highlights: SHA-pinned GitHub Actions with a read-only `GITHUB_TOKEN`, exact-pinned dependencies with a
release-age cooldown, secret/SAST/SCA/SBOM scanning in CI, a distroless non-root container, and OIDC
workload identity federation (no long-lived cloud secrets in CI).
