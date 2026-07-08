// Supply chain: typosquat/slopsquat name check + unpinned-dependency / missing-lockfile checks.
//
// The issue asks for a typosquat check against the *live* npm registry. That needs a network
// call with no existing precedent in this repo (no other scan module makes live external
// requests). Rather than stub the check out, this implements the real detection logic
// (edit-distance against a corpus of popular package names) offline — the corpus and network
// lookup are the only missing piece, not the classification logic. Wiring in a live-registry
// download-count/publish-recency signal is a natural follow-up once network egress from a
// scan run is an approved product decision (privacy pitch is "no code egress" — a name-only
// registry lookup is a smaller ask, but still a scope decision, not this module's to make).

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
