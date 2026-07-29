import { readFileSync, readdirSync, statSync } from "node:fs";
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
