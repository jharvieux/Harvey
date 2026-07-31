import { readFileSync, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import sitemap from "./sitemap";

// The offline half of the #1308 guard. src/cli/site-smoke.ts asks whether a DEPLOYMENT still
// serves what the repo declares; this asks whether the repo is self-consistent in the first place,
// and it runs in `pnpm verify` with no network and no build.
//
// It exists because /intake 404ed in production for days with nothing to notice it, and because
// the pages built by #723-#727 could be added, declared and linked in three separate places with
// no check that the three agreed. sitemap.ts is treated as the route contract throughout: it is
// what search engines are handed and what the smoke check compares the deployment against.
//
// No import from `next` anywhere in this file, deliberately — CI installs the repo root's deps but
// never site/node_modules, so a test that needed the Next runtime would be skipped in CI, which is
// the silent-omission shape this whole guard is against.

const APP_DIR = dirname(fileURLToPath(import.meta.url));
const SITE_DIR = join(APP_DIR, "..");

const declared = sitemap().map((entry) => {
  const path = entry.url.replace(/^https?:\/\/[^/]+/, "");
  return path === "" ? "/" : path;
});

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (name === "node_modules" || name === ".next") return [];
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

const appFiles = walk(APP_DIR);
const pageFiles = appFiles.filter((f) => /\/page\.tsx$/.test(f));

/** "app/pricing/page.tsx" -> "/pricing"; "app/page.tsx" -> "/". */
function routeOf(pageFile: string): string {
  const dir = relative(APP_DIR, dirname(pageFile));
  return dir === "" ? "/" : `/${dir}`;
}

// Redirect sources are live paths too — /intake resolves via next.config.mjs, not a page file.
const redirectSources = [...readFileSync(join(SITE_DIR, "next.config.mjs"), "utf8").matchAll(/source:\s*"([^"]+)"/g)].map(
  (m) => m[1],
);

describe("site route contract", () => {
  it("declares every page that exists, and every declared page exists", () => {
    expect(new Set(pageFiles.map(routeOf))).toEqual(new Set(declared));
  });

  it("resolves every internal link to a declared route, a redirect, or an in-page anchor", () => {
    const dead: string[] = [];
    for (const file of appFiles.filter((f) => f.endsWith(".tsx"))) {
      for (const [, href] of readFileSync(file, "utf8").matchAll(/href="([^"]+)"/g)) {
        if (!href.startsWith("/") || href.startsWith("//")) continue;
        const path = href.split("#")[0] || "/";
        if (declared.includes(path) || redirectSources.includes(path)) continue;
        dead.push(`${relative(SITE_DIR, file)} → ${href}`);
      }
    }
    // A dead internal link is what a prospect meets after a page is renamed or a deploy goes out
    // without one, and nothing else in the toolchain looks at hrefs.
    expect(dead).toEqual([]);
  });

  it("reads the result of every Resend send, so no email can fail unobserved", () => {
    // A Resend rejection is an HTTP 4xx, not a thrown error. Both requester confirmations used to
    // sit in a bare `try { await sendEmail(...) } catch`, which cannot see one — so a confirmation
    // bouncing for every single lead (what the resend.dev sandbox sender does for anyone but the
    // account owner) left no trace anywhere. Discarding the response is the whole failure.
    const route = readFileSync(join(APP_DIR, "api/scan/route.ts"), "utf8");
    const discarded = [...route.matchAll(/^[ \t]*await sendEmail\(/gm)].map((m) => m[0].trim());
    expect(discarded).toEqual([]);
  });

  it("documents every environment variable the site reads, so none can go unprovisioned", () => {
    // The whole of #721: /api/scan reads RESEND_API_KEY and SCAN_NOTIFY_TO, they were never set on
    // the Vercel project, and the site shipped anyway. .env.example is the provisioning checklist —
    // a var that never reaches it is a var nobody knows to set.
    const example = readFileSync(join(SITE_DIR, ".env.example"), "utf8");
    const read = new Set(
      appFiles.flatMap((f) => [...readFileSync(f, "utf8").matchAll(/process\.env\.([A-Z0-9_]+)/g)].map((m) => m[1])),
    );
    expect([...read].filter((name) => !example.includes(name))).toEqual([]);
  });
});

// #1597 — the workspace-conversion hazard, caught in the act. Under the old separate-npm-project
// layout site/node_modules was FLAT, so eslint-config-next's own eslint-plugin-react-hooks@5.2.0
// sat there and was what `next lint` loaded. As a pnpm workspace member site/node_modules holds
// only site's DIRECT deps, so an unlisted one resolves by walking UP to the repo root — where the
// root's own eslint-plugin-react-hooks@7.1.1 lives. MEASURED 2026-07-30: that swap happened, and
// `next build` then failed on a v7-only rule (react-hooks/set-state-in-effect) against app/page.tsx
// code that v5 accepts. It failed loudly here; the same mechanism could just as easily have
// substituted a LOOSER ruleset and gone unnoticed. So: anything eslint-config-next declares that is
// also resolvable from site/ must be at the major it declares, which is only true if site declares
// it itself.
describe("site toolchain isolation under pnpm", () => {
  const configNextDir = dirname(createRequire(join(SITE_DIR, "package.json")).resolve("eslint-config-next/package.json"));
  const declaredDeps: Record<string, string> = JSON.parse(readFileSync(join(configNextDir, "package.json"), "utf8")).dependencies;
  const siteRequire = createRequire(join(SITE_DIR, "package.json"));

  it("never lets a repo-root package shadow a version eslint-config-next pins", () => {
    const shadowed: string[] = [];
    for (const [name, range] of Object.entries(declaredDeps)) {
      let resolved: string;
      try {
        // Not resolvable from site/ is the healthy pnpm case: eslint loads it from
        // eslint-config-next's own tree, at the declared version, and nothing can shadow it.
        resolved = JSON.parse(readFileSync(siteRequire.resolve(`${name}/package.json`), "utf8")).version;
      } catch {
        continue;
      }
      const allowedMajors = range.split("||").map((r) => r.trim().replace(/^[\^~>=<\s]*/, "").split(".")[0]);
      if (!allowedMajors.includes(resolved.split(".")[0])) shadowed.push(`${name}: site resolves ${resolved}, eslint-config-next declares ${range}`);
    }
    expect(shadowed).toEqual([]);
  });
});
