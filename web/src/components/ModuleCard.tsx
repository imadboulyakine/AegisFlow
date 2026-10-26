import type { PlatformModule } from "../lib/modules";
import { Link } from "./Link";

export function ModuleCard({ module }: { module: PlatformModule }) {
  return (
    <article className="card module-card" aria-labelledby={`module-${module.id}`}>
      <header className="card-header">
        <h3 id={`module-${module.id}`}>
          <Link to={module.path}>{module.title}</Link>
        </h3>
        <span className={`badge badge-${module.status}`}>{module.status === "planned" ? "Planned" : "Available"}</span>
      </header>
      <p>{module.summary}</p>
    </article>
  );
}
