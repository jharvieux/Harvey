// Marketing-site smoke check (#1308/#721).
//
//   pnpm exec tsx src/cli/site-smoke.ts                      # https://harvey-qa.com
//   pnpm exec tsx src/cli/site-smoke.ts --base http://localhost:3000
//
// Answers one question about a DEPLOYMENT, not about the repo: can a prospect reach the site and
// hand us a lead right now? On 2026-07-28 the answer had been "no" for six days and nothing said
// so — the live build predated nine of the ten routes site/app/sitemap.ts declares, and /api/scan
// 503'd because its Resend env vars had never been set. Both are silent failures: the site returns
// 200 at "/", the deploy is green, and only a prospect who fills in the form finds out.
//
// NOT part of `pnpm verify` — it needs the network and a live deployment, and verify stays offline
// and deterministic (same posture as osv-staleness). Its arithmetic IS in verify, via
// src/site-smoke.test.ts. Run it on a schedule against production; that is the whole point.
//
// It never submits a real lead: the readiness probe is a GET, and the validation probe is a body
// the handler is required to reject before it sends anything.

import { readFileSync } from "node:fs";
import { evaluateSmoke, smokeFailed, type RouteProbe, type SmokeInput } from "../site-smoke.js";

const DEFAULT_BASE = "https://harvey-qa.com";
const SITEMAP_SOURCE = new URL("../../site/app/sitemap.ts", import.meta.url).pathname;
const NEXT_CONFIG_SOURCE = new URL("../../site/next.config.mjs", import.meta.url).pathname;

function parseBase(argv: string[]): string {
  const i = argv.indexOf("--base");
  const base = i >= 0 ? argv[i + 1] : DEFAULT_BASE;
  if (!base) throw new Error("--base needs a URL");
  return base.replace(/\/+$/, "");
}

/** "https://harvey-qa.com/pricing" and "/pricing" both reduce to "/pricing"; a bare origin to "/". */
function toPath(url: string): string {
  const path = url.replace(/^https?:\/\/[^/]+/, "");
  return path === "" ? "/" : path;
}

async function declaredPaths(): Promise<string[]> {
  // The repo's own sitemap route IS the route contract, so read it rather than restating it here —
  // a second copy would let a new page be added in one place and go unchecked in the other.
  const mod = (await import(SITEMAP_SOURCE)) as { default: () => { url: string }[] };
  return mod.default().map((entry) => toPath(entry.url));
}

/**
 * Redirect sources declared in site/next.config.mjs. Read from the config the same way
 * site/app/site-contract.test.ts reads it, and for the same reason as declaredPaths(): the repo's
 * own declaration IS the contract, so restating the list here would let one be added in one place
 * and go unchecked in the other.
 */
function declaredRedirects(): string[] {
  const config = readFileSync(NEXT_CONFIG_SOURCE, "utf8");
  return [...config.matchAll(/source:\s*"([^"]+)"/g)].map((m) => m[1] ?? "");
}

async function servedPaths(base: string): Promise<string[]> {
  const res = await fetch(`${base}/sitemap.xml`);
  if (!res.ok) throw new Error(`GET ${base}/sitemap.xml → HTTP ${res.status}; cannot compare the deployment against the repo`);
  const xml = await res.text();
  return [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => toPath(m[1] ?? ""));
}

async function probeRoutes(base: string, paths: string[]): Promise<RouteProbe[]> {
  return Promise.all(
    paths.map(async (path) => {
      const res = await fetch(`${base}${path === "/" ? "/" : path}`, { redirect: "manual" });
      return { path, status: res.status };
    }),
  );
}

async function probeReadiness(base: string): Promise<SmokeInput["readiness"]> {
  const res = await fetch(`${base}/api/scan`);
  const body = (await res.json().catch(() => null)) as { configured?: unknown; sandboxSender?: unknown } | null;
  // A deployment without the GET handler answers 405 with no body. That is NOT "not configured" —
  // it is "this build has no answer to give", and reporting the two as one state would be the
  // silent-omission shape (CLAUDE.md's coverage guard) one level down. The same applies to a build
  // predating the sender probe, which is why the two fields are read independently.
  return {
    status: res.status,
    configured: typeof body?.configured === "boolean" ? body.configured : null,
    sandboxSender: typeof body?.sandboxSender === "boolean" ? body.sandboxSender : null,
  };
}

async function probeValidation(base: string): Promise<{ status: number }> {
  const res = await fetch(`${base}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "not-an-email" }),
  });
  return { status: res.status };
}

async function main(): Promise<void> {
  const base = parseBase(process.argv.slice(2));
  console.log(`Smoke-checking ${base}\n`);

  const declared = await declaredPaths();
  const [served, routes, redirects, readiness, validation] = await Promise.all([
    servedPaths(base),
    probeRoutes(base, declared),
    probeRoutes(base, declaredRedirects()),
    probeReadiness(base),
    probeValidation(base),
  ]);

  const checks = evaluateSmoke({ declared, served, routes, redirects, readiness, validation });
  for (const check of checks) {
    console.log(`  ${check.status === "pass" ? "ok  " : "FAIL"}  ${check.name}`);
    console.log(`        ${check.detail}`);
  }

  if (smokeFailed(checks)) {
    console.error(`\n${checks.filter((c) => c.status === "fail").length} of ${checks.length} checks FAILED against ${base}.`);
    console.error("This is the top of the funnel: while a check above is red, prospects are hitting dead ends. See #1308.");
    process.exit(1);
  }
  console.log(`\nAll ${checks.length} checks passed — the site serves what the repo declares and lead capture is live.`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
