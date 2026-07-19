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
