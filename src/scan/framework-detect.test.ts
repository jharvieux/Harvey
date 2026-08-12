import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildDegradedKnipConfig, buildInferredKnipConfig, detectOrm, detectTargetFramework, detectWorkspaceFrameworks, nonNextWorkspaces, rawSqlDriver } from "./framework-detect.js";

// Each case writes a throwaway target tree (the probe is disk-based — it must see vite.config /
// index.html that the in-memory detector source set never carries) and asserts the coarse shape.
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function makeTarget(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-fw-"));
  dirs.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, text);
  }
  return dir;
}

describe("detectTargetFramework (#573)", () => {
  it("detects Vite from a vite.config + index.html + import.meta.env SPA export", () => {
    const dir = makeTarget({
      "vite.config.ts": `import { defineConfig } from "vite";\nexport default defineConfig({});\n`,
      "index.html": `<!doctype html><html><body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>`,
      "package.json": JSON.stringify({ name: "spa", devDependencies: { vite: "^5.0.0" } }),
      "src/lib/supabaseClient.ts": `const url = import.meta.env.VITE_SUPABASE_URL;\nexport const x = url;\n`,
    });
    expect(detectTargetFramework(dir)).toBe("vite");
  });

  it("detects Vite from index.html + import.meta.env even with no vite.config or vite dep", () => {
    const dir = makeTarget({
      "index.html": `<!doctype html><div id="root"></div>`,
      "package.json": JSON.stringify({ name: "spa", dependencies: { react: "^18.0.0" } }),
      "src/main.tsx": `const key = import.meta.env.VITE_OPENAI_API_KEY;\nexport default key;\n`,
    });
    expect(detectTargetFramework(dir)).toBe("vite");
  });

  it("detects Next from a `next` dependency in package.json", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app", dependencies: { next: "14.2.0", react: "^18.0.0" } }),
      "app/page.tsx": `export default function Page() {\n  return <div />;\n}\n`,
    });
    expect(detectTargetFramework(dir)).toBe("next");
  });

  it("detects Next from a next.config file with no explicit dep entry", () => {
    const dir = makeTarget({
      "next.config.mjs": `export default {};\n`,
      "package.json": JSON.stringify({ name: "app" }),
      "app/page.tsx": `export default function Page() {\n  return <div />;\n}\n`,
    });
    expect(detectTargetFramework(dir)).toBe("next");
  });

  it("prefers Next when both Next and Vite signals are present (never suppress a real Next app)", () => {
    const dir = makeTarget({
      "next.config.js": `module.exports = {};\n`,
      "vite.config.ts": `export default {};\n`,
      "package.json": JSON.stringify({ name: "hybrid", dependencies: { next: "14.0.0" }, devDependencies: { vite: "^5.0.0" } }),
    });
    expect(detectTargetFramework(dir)).toBe("next");
  });

  it("returns `other` for a plain library with neither framework's shape", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "lib", dependencies: { lodash: "^4.0.0" } }),
      "src/index.ts": `export const add = (a: number, b: number) => a + b;\n`,
    });
    expect(detectTargetFramework(dir)).toBe("other");
  });

  // #872: these all used to land in `other` (or in `vite`, since they build on it) — the bucket
  // with no compensating behaviour, where M9's Next-shaped checks ran and nothing was disclosed.
  it("names each recognised non-Next framework instead of collapsing it into `other`/`vite`", () => {
    const cases: [Record<string, string>, string][] = [
      [{ "@remix-run/react": "^2.0.0" }, "remix"],
      [{ "@react-router/dev": "^7.0.0" }, "react-router"],
      [{ "@tanstack/react-start": "^1.0.0" }, "tanstack-start"],
      [{ astro: "^4.0.0" }, "astro"],
      [{ "@sveltejs/kit": "^2.0.0" }, "sveltekit"],
      [{ nuxt: "^3.0.0" }, "nuxt"],
    ];
    for (const [deps, expected] of cases) {
      // Each of these ships Vite; the framework must win over the bundler it happens to use.
      const dir = makeTarget({ "package.json": JSON.stringify({ name: "app", dependencies: { ...deps, vite: "^5.0.0" } }) });
      expect(detectTargetFramework(dir), expected).toBe(expected);
    }
  });

  it("detects a framework from its config file when the deps live in a parent manifest", () => {
    const dir = makeTarget({ "astro.config.mjs": `export default {};\n`, "package.json": JSON.stringify({ name: "site" }) });
    expect(detectTargetFramework(dir)).toBe("astro");
  });

  it("still prefers Next over a recognised framework's signature (never suppress a real Next app)", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app", dependencies: { next: "14.2.0", astro: "^4.0.0" } }),
    });
    expect(detectTargetFramework(dir)).toBe("next");
  });

  it("treats a malformed package.json as no dependency signal (no crash)", () => {
    const dir = makeTarget({
      "package.json": `{ not valid json`,
      "vite.config.js": `export default {};\n`,
    });
    expect(detectTargetFramework(dir)).toBe("vite");
  });
});

// #757 (part of #756): ORM/architecture detection — decides whether the Supabase-specific RLS
// detectors have a surface to analyze. Supabase must win when both signatures are present so a real
// RLS surface is never suppressed just because Prisma is also a dependency.
describe("detectOrm (#757)", () => {
  it("detects Prisma from a prisma/schema.prisma + @prisma/client dep (Next+Prisma, no Supabase)", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app", dependencies: { next: "14.2.5", "@prisma/client": "^5.18.0" } }),
      "prisma/schema.prisma": `datasource db {\n  provider = "postgresql"\n  url = env("DATABASE_URL")\n}\nmodel Note { id String @id }\n`,
    });
    expect(detectOrm(dir)).toBe("prisma");
  });

  it("detects Prisma from a root schema.prisma with no dep entry", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app" }),
      "schema.prisma": `model User { id String @id }\n`,
    });
    expect(detectOrm(dir)).toBe("prisma");
  });

  it("detects Supabase from a supabase/migrations directory", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app", dependencies: { next: "14.2.5" } }),
      "supabase/migrations/0001_init.sql": `create table public.notes (id uuid primary key);`,
    });
    expect(detectOrm(dir)).toBe("supabase");
  });

  it("prefers Supabase when both signatures appear (never suppress a real RLS surface)", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app", dependencies: { "@supabase/supabase-js": "^2.45.0", "@prisma/client": "^5.18.0" } }),
      "prisma/schema.prisma": `model Note { id String @id }\n`,
      "supabase/migrations/0001_init.sql": `create table public.notes (id uuid primary key);`,
    });
    expect(detectOrm(dir)).toBe("supabase");
  });

  it("returns `unknown` for a target with neither ORM's signature", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "lib", dependencies: { lodash: "^4.0.0" } }),
    });
    expect(detectOrm(dir)).toBe("unknown");
  });

  // #869: everything non-Supabase/non-Prisma used to collapse into `unknown`, which M1 read as
  // "nothing recognised" and reported nothing about. Each recognised layer now names itself so the
  // scan can disclose that its tenant-scope shapes were not assessed.
  it("names each recognised-but-unsupported ORM instead of collapsing it into `unknown`", () => {
    const cases: [string, string][] = [
      ["drizzle-orm", "drizzle"],
      ["kysely", "kysely"],
      ["typeorm", "typeorm"],
      ["sequelize", "sequelize"],
      ["knex", "knex"],
      ["mongoose", "mongoose"],
    ];
    for (const [dep, expected] of cases) {
      const dir = makeTarget({ "package.json": JSON.stringify({ name: "app", dependencies: { [dep]: "^1.0.0" } }) });
      expect(detectOrm(dir), dep).toBe(expected);
    }
  });

  it("names an ORM ahead of the raw driver it sits on (Drizzle over `pg`)", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app", dependencies: { "drizzle-orm": "^0.30.0", pg: "^8.12.0" } }),
    });
    expect(detectOrm(dir)).toBe("drizzle");
  });

  it("resolves a bare Postgres driver to `raw-sql` (#861)", () => {
    const dir = makeTarget({ "package.json": JSON.stringify({ name: "app", dependencies: { pg: "^8.12.0" } }) });
    expect(detectOrm(dir)).toBe("raw-sql");
  });

  it("keeps Supabase winning over a recognised ORM in the same manifest", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app", dependencies: { "@supabase/supabase-js": "^2.45.0", "drizzle-orm": "^0.30.0" } }),
    });
    expect(detectOrm(dir)).toBe("supabase");
  });
});

// #861: the positive raw-SQL signal — a declared driver dependency — that tells a `pg`/postgres.js
// target apart from a genuinely DB-less app, so the M9 data-layer disclosure can name the driver.
describe("rawSqlDriver (#861)", () => {
  it("names the declared driver for each supported raw-SQL client", () => {
    expect(rawSqlDriver(`{"dependencies":{"pg":"^8.12.0"}}`)).toBe("pg");
    expect(rawSqlDriver(`{"dependencies":{"postgres":"^3.4.0"}}`)).toBe("postgres");
    expect(rawSqlDriver(`{"dependencies":{"@neondatabase/serverless":"^0.9.0"}}`)).toBe("@neondatabase/serverless");
  });

  it("returns undefined for an app that declares no database driver", () => {
    expect(rawSqlDriver(`{"dependencies":{"next":"14.2.5","react":"^18.0.0"}}`)).toBeUndefined();
    expect(rawSqlDriver(undefined)).toBeUndefined();
  });
});

// #696: the knip config Harvey generates for a config-less scope. The universal entry set (test
// files above all) is the measured lever; the framework globs add app/route entries per shape.
describe("buildInferredKnipConfig (#696)", () => {
  it("always declares the universal test/script/config entry globs (the dominant lever)", () => {
    for (const fw of ["next", "vite", "other"] as const) {
      const entry = buildInferredKnipConfig(fw).entry as string[];
      expect(entry).toContain("**/*.{test,spec}.{ts,tsx,js,jsx}");
      expect(entry).toContain("load-tests/**/*.{ts,js}");
      expect(entry).toContain("scripts/**/*.{ts,js,mjs}");
    }
  });

  it("adds Next app-router / pages / middleware entries for a Next scope", () => {
    const entry = buildInferredKnipConfig("next").entry as string[];
    expect(entry.some((g) => g.startsWith("app/**/") && g.includes("page"))).toBe(true);
    expect(entry.some((g) => g.startsWith("src/app/**/"))).toBe(true);
    expect(entry).toContain("middleware.{ts,js}");
    expect(entry).toContain("next.config.{js,mjs,cjs,ts}");
  });

  it("adds Vite index.html / main entries for a Vite scope", () => {
    const entry = buildInferredKnipConfig("vite").entry as string[];
    expect(entry).toContain("index.html");
    expect(entry).toContain("src/main.{ts,tsx,js,jsx}");
    expect(entry).toContain("vite.config.{ts,js,mjs,cjs}");
  });

  it("adds no framework globs for an `other` scope (universal set only)", () => {
    const entry = buildInferredKnipConfig("other").entry as string[];
    expect(entry.some((g) => g.includes("app/**") || g.includes("index.html"))).toBe(false);
  });

  it("carries the #695 ignoreExportsUsedInFile default", () => {
    expect(buildInferredKnipConfig("next").ignoreExportsUsedInFile).toEqual({ interface: true, type: true });
  });
});

describe("buildDegradedKnipConfig (#810)", () => {
  it("disables every named plugin so knip loads no target config file, while keeping the inferred entries", () => {
    const config = buildDegradedKnipConfig("vite", ["vite", "vitest", "storybook"]);
    // no plugin's config file is loaded — the whole point, so a missing-node_modules target's
    // vite.config/next.config imports never need to resolve.
    expect(config.vite).toBe(false);
    expect(config.vitest).toBe(false);
    expect(config.storybook).toBe(false);
    // still the inferred entry graph + #695 default, so real entries stand in for what the disabled
    // plugins would have contributed.
    expect((config.entry as string[])).toContain("index.html");
    expect((config.entry as string[])).toContain("**/*.{test,spec}.{ts,tsx,js,jsx}");
    expect(config.ignoreExportsUsedInFile).toEqual({ interface: true, type: true });
  });

  it("is identical to buildInferredKnipConfig when no plugins are named (empty list is a no-op)", () => {
    expect(buildDegradedKnipConfig("next", [])).toEqual(buildInferredKnipConfig("next"));
  });

  it.each(["remix", "react-router"] as const)(
    "preserves %s framework-contract routes when plugins/config cannot load",
    (framework) => {
      const config = buildDegradedKnipConfig(framework, ["remix", "react-router"]);
      expect(config.remix).toBe(false);
      expect(config["react-router"]).toBe(false);
      expect(config.entry).toEqual(expect.arrayContaining([
        "app/root.{ts,tsx,js,jsx}",
        "app/routes.{ts,tsx,js,jsx}",
        "app/routes/**/*.{ts,tsx,js,jsx}",
      ]));
    },
  );
});

// #597: a monorepo ROOT has no vite.config/next.config of its own — they live in the workspace app
// dirs — so `detectTargetFramework(root)` returns `other`. The per-workspace resolution walks the
// workspace globs (via discoverTargets) and detects a framework for each app, so the M9 gate can
// suppress the SSR family per Vite app instead of false-firing across the whole tree.
describe("monorepo-aware framework resolution (#597)", () => {
  function monorepo(): string {
    return makeTarget({
      "package.json": JSON.stringify({ name: "root", private: true }),
      "pnpm-workspace.yaml": `packages:\n  - "apps/*"\n`,
      "apps/web/package.json": JSON.stringify({ name: "web", devDependencies: { vite: "^5.0.0" } }),
      "apps/web/vite.config.ts": `import { defineConfig } from "vite";\nexport default defineConfig({});\n`,
      "apps/web/src/App.tsx": `export default function App() {\n  return <div>{window.innerWidth}</div>;\n}\n`,
      "apps/api/package.json": JSON.stringify({ name: "api", dependencies: { next: "14.2.0" } }),
      "apps/api/app/page.tsx": `export default function Page() {\n  return <div />;\n}\n`,
    });
  }

  it("returns `other` at the root (documents the #575 regression premise)", () => {
    expect(detectTargetFramework(monorepo())).toBe("other");
  });

  it("resolves a framework per workspace", () => {
    const byRel = new Map(detectWorkspaceFrameworks(monorepo()).map((w) => [w.rel, w.framework]));
    expect(byRel.get("apps/web")).toBe("vite");
    expect(byRel.get("apps/api")).toBe("next");
  });

  it("lists only the non-Next workspaces, with their framework (workspace-relative, POSIX-separated)", () => {
    expect(nonNextWorkspaces(monorepo())).toEqual([{ rel: "apps/web", framework: "vite" }]);
  });

  // #872: a SvelteKit/Astro/Nuxt workspace used to resolve as `vite` (they all declare it) and was
  // suppressed on that basis. Now that it has its own value it must STILL be listed here, or M9's
  // Next-shaped pass would start running over it.
  it("lists a recognised non-Next SSR workspace too, not just Vite SPAs", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "root", private: true }),
      "pnpm-workspace.yaml": `packages:\n  - "apps/*"\n`,
      "apps/site/package.json": JSON.stringify({ name: "site", devDependencies: { "@sveltejs/kit": "^2.0.0", vite: "^5.0.0" } }),
      "apps/api/package.json": JSON.stringify({ name: "api", dependencies: { next: "14.2.0" } }),
    });
    expect(nonNextWorkspaces(dir)).toEqual([{ rel: "apps/site", framework: "sveltekit" }]);
  });

  it("returns [] for a single-app repo (root verdict handles it, no workspace prefixes)", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "spa", devDependencies: { vite: "^5.0.0" } }),
      "vite.config.ts": `export default {};\n`,
    });
    expect(nonNextWorkspaces(dir)).toEqual([]);
  });
});
