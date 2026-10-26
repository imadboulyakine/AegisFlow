# AegisFlow — Azure Cost Model

Estimated monthly cost of the future Azure footprint (ADR-008) under three usage scenarios, plus the
controls that keep a student budget safe. Used to approve (or not) Phase 4, the first billable phase.

Last updated: 2026-10-26 (Phase 0)

> **NOTHING IS DEPLOYED IN PHASE 0.** No Azure resource exists for AegisFlow, no `az login` has been
> run, and no credentials are stored anywhere. Every figure below is a planning estimate.

## 1. How these prices were obtained (read first)

- The **Azure Retail Prices API** (`prices.azure.com`) and `azure.microsoft.com` pricing pages were
  **blocked by the egress proxy** of the research environment on 2026-10-26 (HTTP 403 on CONNECT /
  DNS failure). Prices were therefore taken from web-search extracts of official pages and secondary
  sources, cross-checked where possible (e.g. Azure China list prices show the same 8:1 active:idle
  vCPU ratio as the USD figures). Free grants and billing mechanics were verified in Microsoft's docs.
- Unit prices are **USD list prices, mostly East US references**. France Central / West Europe are
  typically equal or somewhat higher [E]. **All unit prices are [E] unless marked [V].**
- Before Phase 4, re-run (from a machine with access) and paste results into this file:

```text
https://prices.azure.com/api/retail/prices?currencyCode='USD'&$filter=armRegionName eq 'francecentral' and serviceName eq 'Azure Container Apps'
... serviceName eq 'Container Registry' | 'Key Vault' | 'Azure Database for PostgreSQL' | 'Log Analytics'
... | 'Azure Monitor' | 'Microsoft Defender for Cloud' | 'Azure Front Door Service' | 'Bandwidth'
(repeat with armRegionName eq 'westeurope'; serviceName strings themselves to be confirmed)
```

## 2. Resource catalogue and unit prices

| Resource | Purpose | SKU / config | Unit prices (USD) | Free allowance |
|---|---|---|---|---|
| Container Apps | Run `aegisflow` (+ short-lived candidate revisions for E2E/DAST) | Consumption profile, 0.25–0.5 vCPU, 0.5–1 GiB, `minReplicas` 0 (dev) | Active vCPU $0.000024/s; idle vCPU $0.000003/s; memory $0.000003/GiB-s; requests $0.40/million | **180,000 vCPU-s, 360,000 GiB-s, 2 M requests per subscription per month** [V] (S1) |
| Container Apps env | Hosting boundary | Consumption, no VNet, no private endpoint | No base fee for Consumption [V]; private endpoints / planned maintenance trigger the **Dedicated plan management** charge [V] (~$0.10/h [E]) | — |
| Container Registry | Store signed images by digest | **Basic**, admin user disabled | $0.167/day (~$5.1/month), 10 GiB included; Standard ~$0.667/day, 100 GiB | — |
| Key Vault | Runtime secrets (few), optional cosign signing key | Standard, RBAC mode, purge protection | $0.03 per 10,000 operations (secrets, RSA-2048 software keys) | — |
| Log Analytics | Container Apps logs, Activity Log, app logs | Pay-as-you-go Analytics logs, 30-day retention, daily cap | ~$2.30/GB ingestion (East US; EU may be higher) | **5 GB per billing account per month** [E, pricing page extract]; 31 days retention included [V] (M1); Activity Log ingestion free [V] |
| Application Insights | Traces (only if OTel added) | Workspace-based | Billed as Log Analytics ingestion [V] (M1) | Shares the 5 GB |
| PostgreSQL Flexible | System of record (ADR-007) | Burstable **B1ms** (1 vCore, 2 GiB), 32 GiB storage, no HA, 7-day backup | Compute ~$0.017–0.021/h (~$12–15/month if always on); storage ~$0.115–0.13/GiB-month (32 GiB ≈ $3.7–4.2); backup free up to provisioned size [E] | Free account: **750 h B1ms + 32 GB storage + 32 GB backup for 12 months** [V] (P1) — eligibility for a Students subscription unverified |
| Managed identity, Entra workload ID federation | Deploy + runtime identities | User-assigned MI, federated credentials | $0 [E] | — |
| Azure Monitor alerts | Budget, error-rate, canary alerts | 3–5 metric alerts, 1–2 log alerts (15 min) | Metric: $0.10/time series/month; log search: ~$0.50/rule/month at 15 min, ~$1.50 at 5 min [E]; activity-log alerts free [V, secondary] | 10 metric time series; ~1,000 emails/month |
| Cost Management budgets | Spend alerts | Budget at subscription + RG | $0 | — |
| Azure Policy (built-in) | Allowed locations, required tags, audits | Assignments at RG/subscription | $0 for Azure resource policies [E] | — |
| Defender for Cloud | Posture | **Foundational CSPM only** | $0 [V] | — |
| Defender paid plans (optional) | Experiments only | Resource-scoped, time-boxed | Defender CSPM ~$5/billable resource/month; Containers ~$6.87/vCore/month (Kubernetes nodes) + per-digest scans; Key Vault ~$0.25/vault/month; open-source relational DBs ~$15/server/month [E, historical list prices, NOT re-verified] | Usually 30-day trial per plan [E] |
| Front Door (optional) | Custom domain + WAF | **Standard** only | $35/month base (billed hourly) [V, MS doc "illustrative"] + ~$0.009/10k requests + egress [E]; Premium $330/month | — |
| Bandwidth | Internet egress | Microsoft network routing | $0.087/GB after the free tier (Europe) [V, search extract of official page] | **First 100 GB/month free** |

## 3. Scenarios and monthly estimates

Assumptions [E]: one region, one container app, one Postgres server, log volume as stated. Container
Apps free grant is applied either to the active meter (best case) or entirely to the idle meter (worst
case) because the order of application could not be verified — both bounds are shown.

| Line item | (a) Idle / dev | (b) Demo month | (c) Always-on |
|---|---|---|---|
| Usage profile | Scale-to-zero; ~40 h of 0.25 vCPU/0.5 GiB + 30 E2E/DAST candidate revisions × 20 min (0.5/1) | (a) + 7 days `minReplicas=1` (0.5/1), 1 canary day with 2 replicas, ~1.5 M requests, ~30 % active | `minReplicas=1` (0.5/1) 730 h, ~20 % active, ~3 M requests |
| vCPU-s / GiB-s | 54 k / 108 k | 400 k / 799 k | 1,314 k / 2,628 k |
| Container Apps | **$0** (inside free grant) | $0.7–5.3 (vCPU) + $1.3 (memory) ≈ **$2–7** | $5.1–8.9 (vCPU) + $6.8 (memory) + $0.4 (requests) ≈ **$12–16** (≈ $34 if 100 % active) |
| ACR Basic | $5.1 | $5.1 | $5.1 |
| Key Vault | <$0.05 | <$0.10 | ~$0.20 |
| Log Analytics (+ App Insights) | 1–3 GB → **$0** | 6–8 GB → $2.3–6.9 | 10 GB → $11.5 |
| PostgreSQL B1ms | ~60 h running + storage → $4.7–5.5 (**$0** if free offer applies) | ~230 h + storage → $7.6–9.0 | 730 h + storage → $16–19.5 |
| Alerts | ~$0.5 | $1–2 | ~$2 |
| Egress | $0 (<100 GB) | $0 | $0 |
| **Total (core)** | **≈ $6–11 / month** | **≈ $18–30 / month** | **≈ $47–55 / month** (≈ $72 worst case) |
| Optional Front Door Standard | — | +$8 (one week, hourly) | +$35–40 |
| Optional Defender (KV + OSS DB + CSPM) | — | — | +$20–25 [E] |

Budget context: Azure for Students advertises **$100 credit for 12 months, no credit card**, renewable
while a student [V, official page via search extract] (A1). That covers ~9–16 months of scenario (a),
~4 demo months, but only ~1.5–2 months of scenario (c). **Default operating mode: (a), with (b) bursts
around reviews/defence.**

GitHub side (not Azure, but billable): if the repo stays private, Actions minutes beyond 2,000 (Free) /
3,000 (Pro) per month cost $0.006/min (Linux 2-core x64), and usage is **blocked** when no payment
method is on file [V] (G6). Public repos use standard runners for free.

### 3.1 GitHub plan constraints (non-Azure costs while the repo is private)

| Item | Public repo | Private, Free | Private, Pro | Note [V] (G6) |
|---|---|---|---|---|
| Standard hosted runner minutes | Free | 2,000/month | 3,000/month | Overage Linux 2-core x64 $0.006/min; blocked without payment method |
| Artifact storage (shared with Packages) | Free | 500 MB | 1 GB | Use `retention-days: 7` |
| Cache | 10 GB/repo | 10 GB/repo | 10 GB/repo | — |
| Attestations, CodeQL, dependency review, secret scanning | Free | Not available | Not available | Would need GHEC / org Team + paid add-ons — out of budget |
| Self-hosted runner minutes | Free | Free | Free | Not recommended (security, and a VM would cost more than the overage) |

Estimated private-repo usage [E]: PR pipeline ≈ 15–20 billed minutes, `main` pipeline with deploy +
E2E + DAST ≈ 30–40 minutes ⇒ ~100 PR runs + ~30 main runs ≈ 2,700–3,200 minutes/month — at or above
the Pro quota. Mitigations: path filters, `concurrency` cancel-in-progress, DAST nightly, caching
Go/Bun/Grype DB. Making the repo public (ADR-014) removes this cost entirely.

## 4. Cost-control measures (mandatory in Phase 4 Bicep)

| Measure | How | Effect |
|---|---|---|
| Scale to zero | `minReplicas: 0` in dev; `maxReplicas: 2` cap | No compute charge when idle [V] (S1); bounds denial-of-wallet |
| Right-size | 0.25 vCPU / 0.5 GiB default; raise only for load tests | Stays inside free grant |
| Stop Postgres when idle | `az postgres flexible-server stop` after each session; scheduled re-stop (server auto-starts after 7 days [V, docs extract]) | Compute billing stops; storage still billed |
| Log Analytics daily cap + retention | `dailyQuotaGb: 0.15` (dev) / `0.5` (demo); retention 30 days; alert on cap reached | Hard-ish cap (collection stops at cap, may overshoot slightly [V] (M1)) |
| Budgets + action groups | Subscription budget $10/month (dev) with alerts at 50/80/100 % actual and 100 % forecast; RG budget | Early warning (budgets do not stop spend) |
| Single region, single RG | Region per ADR-013; everything in `rg-aegisflow-<env>` | Easy teardown, no cross-region egress |
| Ephemeral DAST/E2E envs | Candidate **revision** (label URL) in the existing app instead of a new environment; deactivate after tests; nightly job deletes revisions/labels older than 24 h | No idle replicas left behind |
| Tag-based cleanup | Tags `project=aegisflow`, `env`, `owner`, `ttl`; scheduled workflow lists resources with expired `ttl` (report first, delete on approval) | Prevents orphaned resources |
| No paid Defender plans subscription-wide | Keep Foundational CSPM; enable a paid plan only per-resource, time-boxed, recorded in an ADR | Avoids per-resource charges on everything |
| Teardown script | `az group delete` for the env RG (owner-run) | Zero residual cost except Entra objects (free) |

### 4.1 Approval checklist before the first billable action (Phase 4)

- [ ] Owner approval recorded in DECISIONS.md (new ADR) with subscription type and monthly ceiling.
- [ ] Unit prices in §2 re-verified with the Retail Prices API for the chosen region (ADR-013).
- [ ] Allowed regions read from the subscription's Azure Policy assignments.
- [ ] Budget + action group deployed **first** (same Bicep deployment, before any compute).
- [ ] `what-if` output reviewed; resource list matches §2 exactly (no extra SKUs).
- [ ] Teardown and Postgres stop scripts tested; owner knows how to delete the resource group.

## 5. Risky cost items to avoid

| Item | Why risky | Indicative cost [E] |
|---|---|---|
| AKS | Node VMs run 24/7; Standard tier control plane; Defender for Containers billed per node vCore | ≥ $70–150/month |
| Container Apps **Dedicated** workload profiles / private endpoints on ACA | Triggers Dedicated plan management fee + instance charges | ~$70+/month |
| Defender plans enabled at subscription scope | Charges every eligible resource, incl. future ones | $5–15 per resource/month |
| Front Door **Premium** | Base fee | $330/month |
| NAT Gateway / Azure Firewall | Hourly + per-GB | NAT ~$32+/month; Firewall far more |
| Microsoft Sentinel on the workspace | Adds per-GB analysis charges on top of ingestion | Several $/GB |
| Log Analytics commitment tier | 100 GB/day minimum, 31-day commitment [V] (M1) | Hundreds of $/month |
| ACR Premium / geo-replication | Daily base fee per region | ~$50/month per region |
| Postgres General Purpose / HA | Always-on vCores, doubled for HA | $100+/month |
| Leaving Postgres or replicas running after a demo | Silent accrual | ~$0.40–0.50/day (B1ms) |

## 6. Sources (accessed 2026-10-26)

- S1 Container Apps billing (free grants, idle/active, Dedicated management charge): https://learn.microsoft.com/azure/container-apps/billing (MicrosoftDocs/azure-docs `articles/container-apps/billing.md`)
- ACA unit rates (secondary, East US, June 2026): https://www.nops.io/blog/azure-container-apps-cost-optimization-guide/ ; https://www.trustradius.com/products/azure-container-apps/pricing ; ratio cross-check https://www.azure.cn/en-us/pricing/details/container-apps/
- ACR SKUs (ms.date 2026-10-15): https://learn.microsoft.com/azure/container-registry/container-registry-skus ; prices: https://azure.microsoft.com/pricing/details/container-registry/ (extract) and https://oneuptime.com/blog/post/2026-07-23-choose-acr-tier/markdown
- Key Vault prices: https://azure.microsoft.com/pricing/details/key-vault/ (values not rendered in extract); https://infisical.com/blog/azure-key-vault-pricing
- M1 Log Analytics cost and daily cap (ms.date 2026-09-02 / 2025-08-29): https://learn.microsoft.com/azure/azure-monitor/logs/cost-logs , https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap ; pricing extract: https://azure.microsoft.com/pricing/details/monitor/
- P1 PostgreSQL free offer: https://learn.microsoft.com/azure/postgresql/flexible-server/how-to-deploy-on-azure-free-account ; B1ms compute (secondary): https://www.bytebase.com/dbcost/azure-flexible/instance/B1ms/ ; stop/7-day restart: https://learn.microsoft.com/azure/postgresql/overview
- Defender for Cloud pricing (plans/billing basis; dollar values not rendered): https://azure.microsoft.com/pricing/details/defender-for-cloud/
- Front Door pricing comparison: https://learn.microsoft.com/azure/frontdoor/understanding-pricing ; billing: https://learn.microsoft.com/azure/frontdoor/billing
- Bandwidth: https://azure.microsoft.com/pricing/details/bandwidth/ (extract: first 100 GB free, $0.087/GB Europe next 10 TB)
- Monitor alert prices (CNY list used for ratio): https://www.azure.cn/en-us/pricing/details/monitor/
- A1 Azure for Students: https://azure.microsoft.com/free/students
- G6 GitHub Actions billing: https://docs.github.com/en/billing/concepts/product-billing/github-actions
