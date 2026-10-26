import { useCallback, useEffect, useState } from "react";
import type { Fetcher } from "../lib/api";
import {
  formatContribution,
  formatScore,
  getFinding,
  listFindings,
  reachabilityLabel,
  statusLabel,
  type ApiOutcome,
  type Finding,
  type FindingStatus,
  type FindingsPage,
  type Tier,
} from "../lib/findings";
import { Link } from "./Link";

export function TierBadge({ tier }: { tier: Tier | null }) {
  if (tier === null) return <span className="tier tier-none">Unscored</span>;
  return (
    <span className={`tier tier-${tier}`} title={`Priority ${tier}`}>
      {tier}
    </span>
  );
}

const noticeTitles: Record<string, string> = {
  disabled: "Read API disabled",
  unavailable: "Persistence not configured",
  forbidden: "Not allowed from this address",
  "not-found": "Not found",
  error: "Could not load findings",
};

const noticeHints: Record<string, string> = {
  disabled:
    "The findings API is off by default. For local development start the server with AEGISFLOW_DEV_READONLY_API=true; Phase 4 serves it behind Entra ID authentication.",
  unavailable: "Set AEGISFLOW_DATABASE_URL so findings can be stored and listed.",
  forbidden: "In development mode the read API only answers loopback clients (open the dashboard via localhost).",
  "not-found": "No finding has this ID, or the read API is disabled.",
  error: "Check that the AegisFlow server is running and try again.",
};

/** Explains why findings cannot be shown (graceful disabled/empty/error states). */
export function ReadApiNotice({ state, message }: { state: string; message: string }) {
  const role = state === "error" ? "alert" : "status";
  return (
    <div className={`notice notice-${state}`} role={role}>
      <strong>{noticeTitles[state] ?? "Unavailable"}</strong>
      <p>{noticeHints[state] ?? message}</p>
      {message && <p className="muted">Server said: {message}</p>}
    </div>
  );
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <p className="empty" role="status">
        No findings match. Upload evidence from CI (POST /api/v1/ingest) to see prioritised vulnerabilities here.
      </p>
    );
  }
  return (
    <div className="table-wrap">
      <table className="findings-table">
        <thead>
          <tr>
            <th scope="col">Risk</th>
            <th scope="col">Vulnerability</th>
            <th scope="col">Component</th>
            <th scope="col">Reachability</th>
            <th scope="col">Status</th>
            <th scope="col">Why</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id}>
              <td className="risk-cell">
                <TierBadge tier={f.risk?.tier ?? null} />
                <span className="score">{f.risk ? formatScore(f.risk.score) : "—"}</span>
              </td>
              <td>
                <Link to={`/vulnerabilities/${f.id}`}>{f.vulnerability?.id ?? f.title}</Link>
              </td>
              <td>
                <code className="purl">{f.component?.purl ?? "—"}</code>
              </td>
              <td>{reachabilityLabel(f.reachability)}</td>
              <td>{statusLabel(f.status)}</td>
              <td className="reason">{f.risk?.reason ?? "Not scored yet"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const tierFilters: ReadonlyArray<{ value: Tier | ""; label: string }> = [
  { value: "", label: "All tiers" },
  { value: "P1", label: "P1 · block" },
  { value: "P2", label: "P2 · warn" },
  { value: "P3", label: "P3 · track" },
];

const statusFilters: ReadonlyArray<{ value: FindingStatus | ""; label: string }> = [
  { value: "open", label: "Open" },
  { value: "", label: "All statuses" },
  { value: "vex_not_affected", label: "Not affected (VEX)" },
  { value: "fixed", label: "Fixed" },
  { value: "accepted", label: "Accepted" },
];

const pageSize = 50;

type ListState = { status: "loading" } | ApiOutcome<FindingsPage>;

export function VulnerabilitiesPage({ fetcher }: { fetcher: Fetcher }) {
  const [tier, setTier] = useState<Tier | "">("");
  const [status, setStatus] = useState<FindingStatus | "">("open");
  const [list, setList] = useState<ListState>({ status: "loading" });
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setList({ status: "loading" });
    const query = { kind: "vulnerability", limit: pageSize, ...(tier ? { tier } : {}), ...(status ? { status } : {}) };
    listFindings(query, fetcher, controller.signal).then(
      (outcome) => {
        if (!controller.signal.aborted) setList(outcome);
      },
      () => {}, // aborted
    );
    return () => controller.abort();
  }, [fetcher, tier, status]);

  const loadMore = useCallback(() => {
    if (!("state" in list) || list.state !== "ok" || !list.value.nextCursor) return;
    const current = list.value;
    setLoadingMore(true);
    const query = {
      kind: "vulnerability",
      limit: pageSize,
      cursor: current.nextCursor,
      ...(tier ? { tier } : {}),
      ...(status ? { status } : {}),
    };
    void listFindings(query, fetcher).then((outcome) => {
      setLoadingMore(false);
      if (outcome.state === "ok") {
        setList({
          state: "ok",
          value: { findings: [...current.findings, ...outcome.value.findings], nextCursor: outcome.value.nextCursor },
        });
      } else {
        setList(outcome);
      }
    });
  }, [list, fetcher, tier, status]);

  return (
    <section className="card" aria-labelledby="vulns-title" aria-busy={"status" in list}>
      <header className="card-header">
        <h2 id="vulns-title">Vulnerabilities</h2>
        <span className="badge badge-available">Risk-ranked</span>
      </header>
      <p className="muted">
        Findings ordered by AegisFlow risk score: CVSS, EPSS, CISA KEV, reachability, exposure and VEX (ADR-012).
      </p>
      <div className="filters">
        <label>
          Tier{" "}
          <select value={tier} onChange={(e) => setTier(e.target.value as Tier | "")}>
            {tierFilters.map((o) => (
              <option key={o.label} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Status{" "}
          <select value={status} onChange={(e) => setStatus(e.target.value as FindingStatus | "")}>
            {statusFilters.map((o) => (
              <option key={o.label} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <FindingsListBody list={list} />
      {"state" in list && list.state === "ok" && list.value.nextCursor && (
        <button type="button" className="button" onClick={loadMore} disabled={loadingMore}>
          {loadingMore ? "Loading…" : "Load more"}
        </button>
      )}
    </section>
  );
}

/** Renders the listing state (exported for SSR tests). */
export function FindingsListBody({ list }: { list: ListState }) {
  if (!("state" in list)) return <p className="muted">Loading findings…</p>;
  if (list.state !== "ok") return <ReadApiNotice state={list.state} message={list.message} />;
  return <FindingsTable findings={list.value.findings} />;
}

export function FindingDetailView({ finding }: { finding: Finding }) {
  const v = finding.vulnerability;
  const c = finding.component;
  const risk = finding.risk;
  const factors = risk?.explanation?.factors ?? [];
  return (
    <section className="card" aria-labelledby="finding-title">
      <header className="card-header">
        <h2 id="finding-title">{v?.id ?? finding.title}</h2>
        <TierBadge tier={risk?.tier ?? null} />
      </header>
      {risk && (
        <p className="reason-line">
          <span className="score score-large">{formatScore(risk.score)}</span> {risk.reason}
        </p>
      )}
      <dl className="facts">
        <div>
          <dt>Status</dt>
          <dd>{statusLabel(finding.status)}</dd>
        </div>
        <div>
          <dt>Component</dt>
          <dd>
            <code className="purl">{c?.purl ?? "—"}</code>
            {c?.direct ? " (direct)" : ""}
          </dd>
        </div>
        <div>
          <dt>Reachability</dt>
          <dd>{reachabilityLabel(finding.reachability)}</dd>
        </div>
        <div>
          <dt>Severity</dt>
          <dd>{finding.severity}</dd>
        </div>
        <div>
          <dt>Fixed in</dt>
          <dd>{finding.fixedVersions.length > 0 ? finding.fixedVersions.join(", ") : "—"}</dd>
        </div>
        <div>
          <dt>Reported by</dt>
          <dd>{finding.tools.join(", ") || "—"}</dd>
        </div>
        {v && v.aliases.length > 0 && (
          <div>
            <dt>Aliases</dt>
            <dd>{v.aliases.join(", ")}</dd>
          </div>
        )}
      </dl>
      {v?.summary && <p>{v.summary}</p>}
      {risk && risk.flags.length > 0 && (
        <ul className="flags" aria-label="Risk flags">
          {risk.flags.map((flag) => (
            <li key={flag} className="flag">
              {flag}
            </li>
          ))}
        </ul>
      )}
      <h3 className="section-title">Risk explanation</h3>
      {factors.length === 0 ? (
        <p className="muted">This finding has not been scored yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="factors-table">
            <thead>
              <tr>
                <th scope="col">Factor</th>
                <th scope="col">Kind</th>
                <th scope="col">Observed</th>
                <th scope="col">Value</th>
                <th scope="col">Weight</th>
                <th scope="col">Points</th>
                <th scope="col">Source</th>
              </tr>
            </thead>
            <tbody>
              {factors.map((f) => (
                <tr key={f.name}>
                  <th scope="row">{f.name}</th>
                  <td>{f.kind}</td>
                  <td>{f.raw}</td>
                  <td>{f.normalized}</td>
                  <td>{f.weight}</td>
                  <td className="points">{formatContribution(f.contribution)}</td>
                  <td>
                    {f.source}
                    {f.note && <span className="note"> — {f.note}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {risk?.explanation && <p className="muted">Scorer {risk.explanation.scorer}.</p>}
      <Link to="/vulnerabilities">← All vulnerabilities</Link>
    </section>
  );
}

type DetailState = { status: "loading" } | ApiOutcome<Finding>;

export function FindingDetailPage({ fetcher, id }: { fetcher: Fetcher; id: number }) {
  const [state, setState] = useState<DetailState>({ status: "loading" });
  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    getFinding(id, fetcher, controller.signal).then(
      (outcome) => {
        if (!controller.signal.aborted) setState(outcome);
      },
      () => {},
    );
    return () => controller.abort();
  }, [fetcher, id]);

  if (!("state" in state)) return <p className="muted">Loading finding…</p>;
  if (state.state !== "ok") {
    return (
      <section className="card">
        <ReadApiNotice state={state.state} message={state.message} />
        <Link to="/vulnerabilities">← All vulnerabilities</Link>
      </section>
    );
  }
  return <FindingDetailView finding={state.value} />;
}
