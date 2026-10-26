import { describe, expect, test } from "bun:test";
import { renderToString } from "react-dom/server";
import { App } from "./App";
import { StatusCard } from "./components/StatusCard";
import type { Fetcher } from "./lib/api";

// Server-side rendering keeps these tests DOM-free (no happy-dom/jsdom dependency).
const neverCalled: Fetcher = async () => {
  throw new Error("effects must not run during SSR");
};

describe("App", () => {
  test("dashboard renders the header, status card and planned modules", () => {
    const html = renderToString(<App fetcher={neverCalled} serverPath="/" />);
    expect(html).toContain("AegisFlow");
    expect(html).toContain("Service status");
    for (const title of ["Supply Chain", "Vulnerabilities", "Policies", "Anomalies"]) {
      expect(html).toContain(title);
    }
    expect(html.match(/>Planned</g)?.length).toBe(3);
    expect(html.match(/>Available</g)?.length).toBe(1);
    expect(html).toContain("Checking…");
  });

  test("planned module route renders the placeholder page and marks the nav item current", () => {
    const html = renderToString(<App fetcher={neverCalled} serverPath="/policies" />);
    expect(html).toContain('id="module-page-title"');
    expect(html).toContain("not implemented yet");
    expect(html).toMatch(/aria-current="page"[^>]*>Policies</);
  });

  test("vulnerabilities route renders the risk-ranked page in its loading state", () => {
    const html = renderToString(<App fetcher={neverCalled} serverPath="/vulnerabilities" />);
    expect(html).toContain('id="vulns-title"');
    expect(html).toContain("Loading findings…");
    expect(html).toMatch(/aria-current="page"[^>]*>Vulnerabilities</);
    expect(html).not.toContain("style=");
  });

  test("finding detail route keeps the Vulnerabilities nav item current", () => {
    const html = renderToString(<App fetcher={neverCalled} serverPath="/vulnerabilities/42" />);
    expect(html).toContain("Loading finding…");
    expect(html).toMatch(/aria-current="page"[^>]*>Vulnerabilities</);
  });

  test("unknown route renders a client-side not-found page", () => {
    const html = renderToString(<App fetcher={neverCalled} serverPath="/nope" />);
    expect(html).toContain("Page not found");
    expect(html).toContain("<code>/nope</code>");
  });

  test("markup contains no inline styles (strict CSP)", () => {
    const html = renderToString(<App fetcher={neverCalled} serverPath="/" />);
    expect(html).not.toContain("style=");
  });
});

describe("StatusCard", () => {
  test("shows version details when the service is operational", () => {
    const html = renderToString(
      <StatusCard
        onRefresh={() => {}}
        snapshot={{
          readiness: { ok: true, value: { ready: true, status: "ready" } },
          version: {
            ok: true,
            value: {
              version: "v0.1.0",
              commit: "0123456789abcdef0123456789abcdef01234567",
              buildDate: "2026-10-26T12:00:00Z",
              goVersion: "go1.27.3",
            },
          },
        }}
      />,
    );
    expect(html).toContain("Operational");
    expect(html).toContain("v0.1.0");
    expect(html).toContain("0123456789ab");
    expect(html).toContain("2026-10-26 12:00 UTC");
    expect(html).not.toContain('role="alert"');
  });

  test("lists probe errors when unreachable", () => {
    const html = renderToString(
      <StatusCard
        onRefresh={() => {}}
        snapshot={{ readiness: { ok: false, error: "readyz down" }, version: { ok: false, error: "api down" } }}
      />,
    );
    expect(html).toContain("Unreachable");
    expect(html).toContain('role="alert"');
    expect(html).toContain("readyz down");
    expect(html).toContain("api down");
  });
});
