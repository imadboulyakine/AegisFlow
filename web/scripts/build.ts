#!/usr/bin/env bun
// Production build for the AegisFlow dashboard using Bun's native bundler (ADR-003: no Vite/webpack).
//
//   bun run build               -> web/dist + copy to internal/webui/dist (embedded by the Go binary)
//   bun run build --sourcemap   -> same, with linked source maps (local debugging only)
//
// The build fails if the emitted HTML contains anything the server's CSP would block
// (inline <script>, inline <style>, style="" or on*="" attributes).
import { cp, mkdir, readdir, rm } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const webRoot = resolve(import.meta.dir, "..");
const outDir = join(webRoot, "dist");
const embedDir = resolve(webRoot, "..", "internal", "webui", "dist");
const keepFile = ".gitkeep";
const withSourcemaps = process.argv.includes("--sourcemap");

/** Returns the CSP violations found in an HTML document (exported for tests). */
export function findCspViolations(html: string): string[] {
  const problems: string[] = [];
  for (const match of html.matchAll(/<script\b([^>]*)>/gi)) {
    if (!/\bsrc\s*=/i.test(match[1] ?? "")) problems.push("inline <script> element");
  }
  if (/<style\b/i.test(html)) problems.push("inline <style> element");
  if (/\sstyle\s*=/i.test(html)) problems.push("style attribute");
  if (/\son[a-z]+\s*=/i.test(html)) problems.push("inline event handler attribute");
  if (/(?:src|href)\s*=\s*["']?\s*javascript:/i.test(html)) problems.push("javascript: URL");
  return problems;
}

/** CSS must not inline images as data: URIs; img-src falls back to 'self' (exported for tests). */
export function findCssViolations(css: string): string[] {
  return /url\(\s*["']?data:/i.test(css) ? ["data: URI in CSS url()"] : [];
}

async function emptyDir(dir: string, keep: string[] = []): Promise<void> {
  await mkdir(dir, { recursive: true });
  for (const entry of await readdir(dir)) {
    if (!keep.includes(entry)) await rm(join(dir, entry), { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  await rm(outDir, { recursive: true, force: true });

  const result = await Bun.build({
    entrypoints: [join(webRoot, "src", "index.html")],
    outdir: outDir,
    target: "browser",
    format: "esm",
    minify: true,
    sourcemap: withSourcemaps ? "linked" : "none",
    // Absolute URLs so deep links such as /vulnerabilities still load /assets/...
    publicPath: "/",
    // Everything under assets/ is content-hashed; the Go server caches it as immutable.
    naming: {
      entry: "[dir]/[name].[ext]",
      chunk: "assets/[name]-[hash].[ext]",
      asset: "assets/[name]-[hash].[ext]",
    },
    define: { "process.env.NODE_ENV": JSON.stringify("production") },
    env: "disable",
    // Fail on non-literal dynamic imports instead of shipping unresolved code paths.
    allowUnresolved: [],
    throw: false,
  });

  if (!result.success) {
    for (const log of result.logs) console.error(log);
    throw new Error("bun build failed");
  }

  const indexFile = Bun.file(join(outDir, "index.html"));
  if (!(await indexFile.exists())) throw new Error("build did not emit index.html");
  const violations = findCspViolations(await indexFile.text());
  if (violations.length > 0) {
    throw new Error(`index.html would violate the Content-Security-Policy: ${violations.join(", ")}`);
  }

  for (const output of result.outputs) {
    if (!output.path.endsWith(".css")) continue;
    const cssViolations = findCssViolations(await Bun.file(output.path).text());
    if (cssViolations.length > 0) {
      throw new Error(`${relative(webRoot, output.path)} would violate the CSP: ${cssViolations.join(", ")}`);
    }
  }

  await emptyDir(embedDir, [keepFile]);
  await cp(outDir, embedDir, { recursive: true });

  for (const output of result.outputs) {
    const size = `${(output.size / 1024).toFixed(1)} KiB`.padStart(10);
    console.log(`${size}  ${relative(webRoot, output.path)}`);
  }
  console.log(`copied ${relative(webRoot, outDir)} -> ${relative(webRoot, embedDir)}`);
}

if (import.meta.main) {
  await main();
}
