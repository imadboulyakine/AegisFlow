#!/usr/bin/env bun
// Local development server: Bun serves src/index.html with HMR and proxies the Go API.
//
//   terminal 1: make run                  (Go server on :8080)
//   terminal 2: cd web && bun run dev     (http://127.0.0.1:3000)
//
// AEGISFLOW_API_URL overrides the Go server origin (default http://127.0.0.1:8080).
// Development only: HMR injects scripts, so this server does NOT apply the production CSP.
import index from "../src/index.html";

const apiOrigin = new URL(process.env["AEGISFLOW_API_URL"] ?? "http://127.0.0.1:8080");
const port = Number(process.env["PORT"] ?? "3000");

// Hop-by-hop headers must not be forwarded by a proxy (RFC 9110 §7.6.1).
const hopByHop = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host"];

async function proxy(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const target = new URL(url.pathname + url.search, apiOrigin);
  const headers = new Headers(req.headers);
  for (const name of hopByHop) headers.delete(name);
  try {
    const init: RequestInit = { method: req.method, headers, redirect: "manual" };
    if (req.method !== "GET" && req.method !== "HEAD") init.body = req.body;
    return await fetch(target, init);
  } catch {
    return Response.json(
      {
        type: "about:blank",
        title: "Bad Gateway",
        status: 502,
        detail: `Go API not reachable at ${apiOrigin.origin}; start it with "make run".`,
      },
      { status: 502, headers: { "Content-Type": "application/problem+json" } },
    );
  }
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  development: { hmr: true, console: true },
  routes: {
    "/api/*": proxy,
    "/healthz": proxy,
    "/readyz": proxy,
    "/*": index,
  },
});

console.log(`AegisFlow web dev server: ${server.url.href} (API proxied to ${apiOrigin.origin})`);
