import {
  deriveState,
  formatBuildDate,
  shortCommit,
  stateLabel,
  type StatusSnapshot,
} from "../lib/status";

interface StatusCardProps {
  snapshot: StatusSnapshot | null;
  onRefresh: () => void;
}

export function StatusCard({ snapshot, onRefresh }: StatusCardProps) {
  const state = deriveState(snapshot);
  const version = snapshot?.version.ok ? snapshot.version.value : null;
  const readiness = snapshot?.readiness.ok ? snapshot.readiness.value : null;
  const errors = snapshot
    ? [snapshot.readiness, snapshot.version].flatMap((o) => (o.ok ? [] : [o.error]))
    : [];

  return (
    <section className="card status-card" aria-labelledby="status-title" aria-busy={state === "loading"}>
      <header className="card-header">
        <h2 id="status-title">Service status</h2>
        <span className={`badge badge-${state}`} data-testid="service-state">
          {stateLabel(state)}
        </span>
      </header>
      <dl className="facts">
        <div>
          <dt>Readiness</dt>
          <dd>{readiness ? readiness.status : "—"}</dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd data-testid="version">{version ? version.version : "—"}</dd>
        </div>
        <div>
          <dt>Commit</dt>
          <dd>
            <code>{version ? shortCommit(version.commit) : "—"}</code>
          </dd>
        </div>
        <div>
          <dt>Built</dt>
          <dd>{version ? formatBuildDate(version.buildDate) : "—"}</dd>
        </div>
        <div>
          <dt>Go runtime</dt>
          <dd>{version ? version.goVersion : "—"}</dd>
        </div>
      </dl>
      {errors.length > 0 && (
        <ul className="errors" role="alert">
          {errors.map((message) => (
            <li key={message}>{message}</li>
          ))}
        </ul>
      )}
      <button type="button" className="button" onClick={onRefresh} disabled={state === "loading"}>
        Refresh
      </button>
    </section>
  );
}
