import { useCallback, useEffect, useState } from "react";
import { defaultFetcher, type Fetcher } from "./lib/api";
import { findModule, modules, type PlatformModule } from "./lib/modules";
import { usePathname } from "./lib/router";
import { loadStatus, type StatusSnapshot } from "./lib/status";
import { BrandMark } from "./components/BrandMark";
import { Link } from "./components/Link";
import { ModuleCard } from "./components/ModuleCard";
import { StatusCard } from "./components/StatusCard";

function useServiceStatus(fetcher: Fetcher) {
  const [snapshot, setSnapshot] = useState<StatusSnapshot | null>(null);
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setSnapshot(null);
    void loadStatus(fetcher, controller.signal).then((next) => {
      if (!controller.signal.aborted) setSnapshot(next);
    });
    return () => controller.abort();
  }, [fetcher, generation]);

  const refresh = useCallback(() => setGeneration((g) => g + 1), []);
  return { snapshot, refresh };
}

function Dashboard({ fetcher }: { fetcher: Fetcher }) {
  const { snapshot, refresh } = useServiceStatus(fetcher);
  return (
    <>
      <StatusCard snapshot={snapshot} onRefresh={refresh} />
      <section aria-labelledby="modules-title">
        <h2 id="modules-title" className="section-title">
          Platform modules
        </h2>
        <div className="grid">
          {modules.map((m) => (
            <ModuleCard key={m.id} module={m} />
          ))}
        </div>
      </section>
    </>
  );
}

function ModulePage({ module }: { module: PlatformModule }) {
  return (
    <section className="card" aria-labelledby="module-page-title">
      <header className="card-header">
        <h2 id="module-page-title">{module.title}</h2>
        <span className={`badge badge-${module.status}`}>Planned</span>
      </header>
      <p>{module.summary}</p>
      <p className="muted">This module is not implemented yet. It is part of the AegisFlow roadmap.</p>
      <Link to="/">← Back to dashboard</Link>
    </section>
  );
}

function NotFound({ pathname }: { pathname: string }) {
  return (
    <section className="card" aria-labelledby="not-found-title">
      <h2 id="not-found-title">Page not found</h2>
      <p>
        No page matches <code>{pathname}</code>.
      </p>
      <Link to="/">← Back to dashboard</Link>
    </section>
  );
}

export interface AppProps {
  /** Injected for tests; defaults to the browser's fetch. */
  fetcher?: Fetcher;
  /** Path used when rendering on the server (tests). */
  serverPath?: string;
}

export function App({ fetcher = defaultFetcher, serverPath = "/" }: AppProps) {
  const pathname = usePathname(serverPath);
  const module = findModule(pathname);

  let page;
  if (pathname === "/") page = <Dashboard fetcher={fetcher} />;
  else if (module) page = <ModulePage module={module} />;
  else page = <NotFound pathname={pathname} />;

  return (
    <div className="layout">
      <header className="topbar">
        <Link to="/" className="brand" aria-label="AegisFlow dashboard">
          <BrandMark />
          AegisFlow
        </Link>
        <nav aria-label="Modules">
          <ul className="nav">
            {modules.map((m) => (
              <li key={m.id}>
                <Link to={m.path} aria-current={module?.id === m.id ? "page" : undefined}>
                  {m.title}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
      </header>
      <main className="content">{page}</main>
      <footer className="footer">AegisFlow · DevSecOps &amp; software supply-chain security · Phase 0</footer>
    </div>
  );
}
