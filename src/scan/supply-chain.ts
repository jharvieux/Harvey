// Supply chain: typosquat/slopsquat name check + unpinned-dependency / missing-lockfile checks
// + a live npm-registry existence cross-check (issue #66) for nonexistent/hallucinated deps.
//
// checkSlopsquat is the first live external network call in this repo's scan modules other than
// src/scan/supabase.ts and src/pentest/client.ts — it sends dependency NAMES only (never source)
// to https://registry.npmjs.org, matching the privacy pitch's "no code egress" (a name-only
// registry lookup is a smaller ask than code egress, but still noted as a scope decision).

import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

// High-traffic npm packages a typosquat/slopsquat target would mimic. Not exhaustive.
const POPULAR_PACKAGES = [
  "react", "react-dom", "next", "express", "lodash", "axios", "chalk", "commander",
  "typescript", "eslint", "webpack", "babel", "vite", "vitest", "jest", "postgres",
  "supabase", "@supabase/supabase-js", "zod", "prisma", "stripe", "tailwindcss",
  "dotenv", "uuid", "moment", "dayjs", "request", "async", "underscore", "jquery",
  "socket.io", "mongoose", "sequelize", "graphql", "apollo-server", "passport",
  "bcrypt", "jsonwebtoken", "nodemailer", "multer", "cors", "helmet", "morgan",
];

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i]![0] = i;
  for (let j = 0; j <= b.length; j++) dp[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i]![j] = a[i - 1] === b[j - 1] ? dp[i - 1]![j - 1]! : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
    }
  }
  return dp[a.length]![b.length]!;
}

// Flags a dependency name that's edit-distance 1 from a popular package but not an exact
// match — the classic typosquat/slopsquat shape ("expres", "raect", "zodd"). Offline corpus
// match, not a live-registry lookup → always "review" precision.
export function checkTyposquat(depNames: string[]): Finding[] {
  const findings: Finding[] = [];
  const popularSet = new Set(POPULAR_PACKAGES);
  for (const name of depNames) {
    if (popularSet.has(name)) continue;
    const closest = POPULAR_PACKAGES.find((p) => levenshtein(name, p) === 1);
    if (closest) {
      findings.push(
        mechanicalFinding({
          id: `SUP-TYPO-${name}`,
          title: `Dependency "${name}" is one edit from popular package "${closest}"`,
          severity: "High",
          category: "Supply chain",
          taxonomy: "Possible typosquat/slopsquat",
          location: "package.json",
          evidence: `"${name}" has Levenshtein distance 1 from "${closest}" (offline corpus match, not a live-registry lookup).`,
          impact: "If this is a typosquat, install pulls attacker-controlled code with full build/runtime access.",
          fix: `Confirm "${name}" is the package you intend; if not, replace with "${closest}".`,
          precisionTier: "review",
        }),
      );
    }
  }
  return findings;
}

const NPM_REGISTRY = "https://registry.npmjs.org";

// Live npm-registry existence cross-check (P-SLOPSQUAT): an AI coding assistant can hallucinate
// a plausible-looking package name that was never published. A 404 from the registry is
// deterministic ground truth for "this name doesn't exist" — not a heuristic corpus match — so
// it's "high" precision, unlike the offline edit-distance check above. A network error can't
// distinguish "doesn't exist" from "registry unreachable", so it's left unflagged (indeterminate)
// rather than risk a false positive on a real dependency; typo/edit-distance-to-a-real-package
// detection (the "review" half of P-SLOPSQUAT's tier split) stays in checkTyposquat above, not
// duplicated here.
export async function checkSlopsquat(depNames: string[], fetchImpl: typeof fetch = fetch): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const name of depNames) {
    let res: Response;
    try {
      res = await fetchImpl(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, { method: "HEAD" });
    } catch (err) {
      console.warn(`checkSlopsquat: "${name}" indeterminate — npm registry unreachable (${err instanceof Error ? err.message : String(err)})`);
      continue;
    }
    if (res.status === 404) {
      findings.push(
        mechanicalFinding({
          id: `SUP-SLOPSQUAT-${name}`,
          title: `Dependency "${name}" does not exist on the npm registry`,
          severity: "High",
          category: "Supply chain",
          taxonomy: "Slopsquatted/hallucinated dependency",
          location: `package.json (${name})`,
          evidence: `HEAD ${NPM_REGISTRY}/${name} returned 404 — no package named "${name}" has ever been published.`,
          impact: "A hallucinated dependency name is a hijack-in-waiting: whoever publishes it first captures every future install. This is confirmed nonexistent, not a heuristic guess.",
          fix: `Confirm "${name}" is the package you intend. If it's hallucinated, find the real package or vendor the code directly.`,
          precisionTier: "high",
        }),
      );
      continue;
    }
    if (!res.ok) {
      console.warn(`checkSlopsquat: "${name}" indeterminate — npm registry returned ${res.status}`);
    }
  }
  return findings;
}

export type DependencyMap = Record<string, string>;

// Unpinned = the declared range can resolve to more than one published version. Syntactic
// check on the range string → deterministic, "high" precision (whether an unpinned range is
// *acceptable* is a severity/triage judgment, not this check's confidence).
export function checkUnpinnedDependencies(deps: DependencyMap): Finding[] {
  const unpinned = Object.entries(deps).filter(([, range]) => {
    const r = range.trim();
    return r === "" || /^[\^~*]/.test(r) || /latest$/i.test(r) || /x$/i.test(r);
  });
  if (unpinned.length === 0) return [];
  return [
    mechanicalFinding({
      id: "SUP-UNPINNED",
      title: `${unpinned.length} dependencies declared with an unpinned version range`,
      severity: "Low",
      category: "Supply chain",
      taxonomy: "Unpinned dependency",
      location: "package.json",
      evidence: `Unpinned: ${unpinned.map(([n, r]) => `${n}@${r}`).join(", ")}.`,
      impact: "A compromised upstream publish (or the next semver-compatible release) can land in installs without review, unless a lockfile is committed and enforced in CI.",
      fix: "Pin exact versions, or rely on a committed, CI-enforced lockfile (frozen install) as the actual pin.",
      precisionTier: "high",
    }),
  ];
}

// Install-time lifecycle scripts (preinstall/install/postinstall) run arbitrary code on every
// `npm install`, so a compromised or malicious dependency (or the project itself) uses them as
// the execution foothold — the Shai-Hulud npm worm class. Presence is a deterministic fact but
// not proof of malice (many legit packages build native addons here) → always "review" tier.
const INSTALL_SCRIPT_HOOKS = ["preinstall", "install", "postinstall"];

export function checkInstallScripts(scripts: Record<string, string>): Finding[] {
  const present = INSTALL_SCRIPT_HOOKS.filter((h) => typeof scripts[h] === "string");
  if (present.length === 0) return [];
  return [
    mechanicalFinding({
      id: "SUP-INSTALL-SCRIPT",
      title: `package.json defines install lifecycle script(s): ${present.join(", ")}`,
      severity: "Medium",
      category: "Supply chain",
      taxonomy: "Install lifecycle script",
      location: "package.json (scripts)",
      evidence: present.map((h) => `${h}: ${scripts[h]}`).join("; "),
      impact: "Install-time scripts run on every `npm install` before any code review — the standard execution foothold for supply-chain worms (Shai-Hulud). Confirm each is expected.",
      fix: "Confirm the script is intentional; install with --ignore-scripts in CI where the build doesn't need it.",
      precisionTier: "review",
    }),
  ];
}

export function checkLockfilePresence(projectDir: string): Finding[] {
  const lockfiles = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"];
  const present = lockfiles.some((f) => existsSync(join(projectDir, f)));
  if (present) return [];
  return [
    mechanicalFinding({
      id: "SUP-NO-LOCKFILE",
      title: "No lockfile found",
      severity: "Medium",
      category: "Supply chain",
      taxonomy: "Missing lockfile",
      location: projectDir,
      evidence: `None of ${lockfiles.join(", ")} present.`,
      impact: "Every install can resolve different transitive versions — no reproducible, reviewable dependency tree.",
      fix: "Commit a lockfile and run installs with --frozen-lockfile / npm ci in CI.",
      precisionTier: "high",
    }),
  ];
}
