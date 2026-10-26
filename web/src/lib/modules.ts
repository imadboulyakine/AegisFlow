// Catalogue of the platform modules shown on the dashboard. All are placeholders in Phase 0.

export type ModuleStatus = "planned" | "available";

export interface PlatformModule {
  id: string;
  path: `/${string}`;
  title: string;
  summary: string;
  status: ModuleStatus;
}

export const modules: readonly PlatformModule[] = [
  {
    id: "supply-chain",
    path: "/supply-chain",
    title: "Supply Chain",
    summary: "SBOMs, signed artifacts and build provenance verification for every release.",
    status: "planned",
  },
  {
    id: "vulnerabilities",
    path: "/vulnerabilities",
    title: "Vulnerabilities",
    summary: "Correlated SAST, SCA and DAST findings with risk-aware prioritisation.",
    status: "planned",
  },
  {
    id: "policies",
    path: "/policies",
    title: "Policies",
    summary: "Deployment gates that enforce signature, provenance and vulnerability policy.",
    status: "planned",
  },
  {
    id: "anomalies",
    path: "/anomalies",
    title: "Anomalies",
    summary: "Explainable anomaly detection over pipeline, supply-chain and runtime signals.",
    status: "planned",
  },
];

/** Returns the module whose path matches `pathname` (ignoring a trailing slash), if any. */
export function findModule(pathname: string): PlatformModule | undefined {
  const normalized = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  return modules.find((m) => m.path === normalized);
}
