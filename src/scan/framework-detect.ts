// Target-framework probe (#573). A shared enabler for the modules whose detectors assume a
// Next.js project shape by default (App Router SSR, `"use client"` boundaries, `process.env`
// secrets) and therefore mis-behave on a Vite/no-code SPA export — M9's SSR/App-Router family is
// the first consumer (#575). Returns the coarse shape only; individual detectors decide what to do
// with it (suppress, switch to an all-client tier, widen a secret rule, …).
//
// Detection is disk-based so it can see the files the in-memory detector source set does NOT carry
// (vite.config, index.html). Next wins over Vite when both signals appear — never wrongly suppress
// a real Next app's SSR checks.

import { existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { loadSources } from "../detectors/load-sources.js";
import { discoverTargets } from "../pentest/targets.js";

export type TargetFramework = "next" | "vite" | "other";

// #757 (part of #756): the target's DB/ORM architecture, orthogonal to the JS framework — an app
// can be Next+Prisma with no Supabase. Its consumer is the M1 mechanical tier (src/scan/
// mechanical.ts): the Supabase-specific migration/RLS/PostgREST/edge-config detectors have NO
// surface to analyze on a Prisma/Postgres app (all tenant isolation is app-layer, where the
// ORM-agnostic pg-idor/bola-owner/etc. detectors already run), so it records that tier N/A by
// architecture instead of letting the absence of RLS pass as an implicit gap.
type TargetOrm = "prisma" | "supabase" | "unknown";

const NEXT_CONFIGS = ["next.config.js", "next.config.mjs", "next.config.cjs", "next.config.ts"];
const VITE_CONFIGS = ["vite.config.ts", "vite.config.js", "vite.config.mjs", "vite.config.cjs"];

// A dependency named `name` in package.json's dependencies/devDependencies/peerDependencies. A
// malformed package.json can't assert a dependency either way, so treat it as absent.
function hasDep(pkgText: string | undefined, name: string): boolean {
  if (!pkgText) return false;
  let pkg: unknown;
  try {
    pkg = JSON.parse(pkgText);
  } catch {
    return false;
  }
  if (typeof pkg !== "object" || pkg === null) return false;
  const p = pkg as Record<string, Record<string, unknown> | undefined>;
  return !!(p.dependencies?.[name] ?? p.devDependencies?.[name] ?? p.peerDependencies?.[name]);
}

export function detectTargetFramework(dir: string): TargetFramework {
  const sources = loadSources(dir);
  const pkgText = sources.find((s) => s.path === "package.json")?.text;

  const isNext = hasDep(pkgText, "next") || NEXT_CONFIGS.some((f) => existsSync(join(dir, f)));
  if (isNext) return "next";

  const hasViteConfig = VITE_CONFIGS.some((f) => existsSync(join(dir, f)));
  const usesImportMetaEnv = sources.some((s) => s.text.includes("import.meta.env"));
  const hasIndexHtml = existsSync(join(dir, "index.html"));
  if (hasViteConfig || hasDep(pkgText, "vite") || (hasIndexHtml && usesImportMetaEnv)) return "vite";

  return "other";
}

const PRISMA_SCHEMA_PATHS = ["schema.prisma", join("prisma", "schema.prisma")];

// #757: which DB/ORM architecture the target uses. Supabase WINS when both signatures appear — a
// real Supabase RLS surface must never be suppressed because Prisma is also present as a query
// layer. `unknown` when neither signature is found, so the RLS detectors run unchanged (their own
// no-migrations-found path already yields nothing on a non-Supabase target — the gate is only about
// making that N/A explicit for a recognized Prisma architecture, never widening suppression).
export function detectOrm(dir: string): TargetOrm {
  const pkgText = loadSources(dir).find((s) => s.path === "package.json")?.text;

  const isSupabase =
    hasDep(pkgText, "@supabase/supabase-js") ||
    existsSync(join(dir, "supabase", "config.toml")) ||
    existsSync(join(dir, "supabase", "migrations"));
  if (isSupabase) return "supabase";

  const isPrisma =
    hasDep(pkgText, "@prisma/client") ||
    hasDep(pkgText, "prisma") ||
    PRISMA_SCHEMA_PATHS.some((p) => existsSync(join(dir, p)));
  if (isPrisma) return "prisma";

  return "unknown";
}

// #696: a third-party scan target usually ships NO knip config, so knip can't infer non-app entry
// points and over-reports them — and everything they reach — as unused files. The dominant cause is
// NOT app-router pages (knip's Next plugin already resolves those): it's TEST files (knip recognizes
// no vitest/jest config), plus load-tests and scripts. MEASURED on ATC apps/main (config-less Next
// app, deps installed): baseline 581 unused files; a generated config declaring test globs +
// load-tests + scripts + framework entries collapsed it to 6, a plausible reviewable residual.
// App-router globs alone only moved 581→579 — the test/script globs are the lever. We generate this
// config ONLY for a scope with no config of its own (src/cli/quality-scan.ts); a target that ships
// its own knip config knows its app and its entries are never overridden.
const NEXT_APP_ROUTE_FILES =
  "{page,layout,template,default,route,loading,error,not-found,global-error,sitemap,robots,manifest,opengraph-image,twitter-image,icon,apple-icon}";

function frameworkEntryGlobs(framework: TargetFramework): string[] {
  if (framework === "next") {
    return [
      `src/app/**/${NEXT_APP_ROUTE_FILES}.{ts,tsx,js,jsx}`,
      `app/**/${NEXT_APP_ROUTE_FILES}.{ts,tsx,js,jsx}`,
      "src/pages/**/*",
      "pages/**/*",
      "src/middleware.{ts,js}",
      "middleware.{ts,js}",
      "src/instrumentation.{ts,js}",
      "instrumentation.{ts,js}",
      "next.config.{js,mjs,cjs,ts}",
    ];
  }
  if (framework === "vite") {
    return ["index.html", "vite.config.{ts,js,mjs,cjs}", "src/main.{ts,tsx,js,jsx}"];
  }
  return [];
}

// knip's OWN default entry patterns (verified in node_modules/knip ConfigurationChief.js,
// `{index,cli,main}` × DEFAULT_EXTENSIONS at root and under src/). A config `entry` REPLACES these
// defaults rather than extending them, so we must re-declare them or a plain lib/app whose entry is
// src/index.ts would suddenly read as an unused file (measured: it broke the #693 fixture).
const KNIP_DEFAULT_ENTRY_GLOBS = [
  "{index,cli,main}.{js,mjs,cjs,jsx,ts,tsx,mts,cts}",
  "src/{index,cli,main}.{js,mjs,cjs,jsx,ts,tsx,mts,cts}",
];

// Entries every framework shares — the big lever (test files above all). Independent of framework
// detection so an `other` (no recognized framework) target still gets its tests/scripts declared.
const UNIVERSAL_ENTRY_GLOBS = [
  "**/*.{test,spec}.{ts,tsx,js,jsx}",
  "test/**/*.{ts,tsx}",
  "tests/**/*.{ts,tsx}",
  "src/test/**/*.{ts,tsx}",
  "load-tests/**/*.{ts,js}",
  "scripts/**/*.{ts,js,mjs}",
  "*.config.{js,mjs,cjs,ts}",
  "**/*.d.ts",
];

// The knip config Harvey generates for a config-less scope: framework-derived entries + the
// universal set, plus the same ignoreExportsUsedInFile default the merge path uses (#695). Pure so
// it's unit-testable directly. Because these entries are INFERRED (not the target's own), the CLI
// marks the resulting unused-FILE findings as review-tier rather than confirmed dead code.
export function buildInferredKnipConfig(framework: TargetFramework): Record<string, unknown> {
  return {
    entry: [...KNIP_DEFAULT_ENTRY_GLOBS, ...frameworkEntryGlobs(framework), ...UNIVERSAL_ENTRY_GLOBS],
    ignoreExportsUsedInFile: { interface: true, type: true },
  };
}

// #810: the "NEEDS target npm install" prereq — knip aborts when it tries to LOAD the target's own
// knip config OR any framework plugin config (vite.config.ts, next.config.ts, ...) whose imports
// don't resolve, which is exactly what a not-yet-installed target's node_modules causes. Every knip
// plugin is what reads those config files; setting each to `false` stops knip loading ANY of them
// (MEASURED 2026-07-23: a vite.config importing an uninstalled plugin aborts the whole run even with
// an explicit `-c` override, but disabling the plugins makes knip skip the config file and report
// dead code from source alone). Built on top of buildInferredKnipConfig so the inferred entry globs
// stand in for the entry points those plugins would otherwise have contributed. `pluginNames` is the
// caller-supplied list of knip's own installed plugin ids (knip validates config keys strictly, so
// it must be knip's real plugin set, not a guess) — see quality-scan.ts's knipPluginNames.
export function buildDegradedKnipConfig(framework: TargetFramework, pluginNames: string[]): Record<string, unknown> {
  const config = buildInferredKnipConfig(framework);
  for (const name of pluginNames) config[name] = false;
  return config;
}

// Monorepo-aware resolution (#597). `detectTargetFramework` inspects a SINGLE dir's own
// manifest/config, so at a monorepo ROOT — where vite.config/next.config live in `apps/*`, not the
// root — it returns `other`, and the M9 SSR gate (which only suppresses on `vite`) runs the SSR
// family over the whole tree and false-fires on the Vite app's files. That is the #575 regression:
// the single-app Vite fix silently returns for anyone who scans the repo root (the default
// engagement entry point). This resolves a framework PER workspace so the M9 gate can suppress the
// SSR/App-Router family per-app. Workspace enumeration reuses `discoverTargets` (pentest/targets):
// the same pnpm-workspace.yaml / package.json `workspaces` / glob expansion the M2/M4/M5 passes use.
interface WorkspaceFramework {
  /** Workspace directory relative to `root`, POSIX-separated ("" for the root itself). */
  rel: string;
  framework: TargetFramework;
}

export function detectWorkspaceFrameworks(root: string): WorkspaceFramework[] {
  return discoverTargets(root).apps.map((a) => ({
    rel: a.path === root ? "" : relative(root, a.path).split(sep).join("/"),
    framework: detectTargetFramework(a.path),
  }));
}

// Workspace-relative dirs of every non-root Vite workspace under `root`. The M9 gate suppresses the
// SSR/App-Router family for files under any of these prefixes even when the repo root's OWN verdict
// is `next`/`other`. A single-app repo enumerates only the root (rel === "") and returns [] — its
// suppression is the whole-target `detectTargetFramework(root) === "vite"` path, unchanged.
export function viteWorkspaces(root: string): string[] {
  return detectWorkspaceFrameworks(root)
    .filter((w) => w.rel !== "" && w.framework === "vite")
    .map((w) => w.rel);
}
