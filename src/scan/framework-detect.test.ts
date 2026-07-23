import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildDegradedKnipConfig, buildInferredKnipConfig, detectOrm, detectTargetFramework, detectWorkspaceFrameworks, viteWorkspaces } from "./framework-detect.js";

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

  it("lists only the Vite workspaces (workspace-relative, POSIX-separated)", () => {
    expect(viteWorkspaces(monorepo())).toEqual(["apps/web"]);
  });

  it("returns [] for a single-app repo (root verdict handles it, no workspace prefixes)", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "spa", devDependencies: { vite: "^5.0.0" } }),
      "vite.config.ts": `export default {};\n`,
    });
    expect(viteWorkspaces(dir)).toEqual([]);
  });
});
