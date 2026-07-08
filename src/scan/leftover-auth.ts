// Leftover-auth greps: stubbed-out or forgotten auth guards left in from development.
// Pure text patterns — no tool binary, no AST — so every hit here is "review" precision:
// a grep can't tell a genuinely bypassed guard from `// TODO: auth` in a comment explaining
// why auth is deliberately deferred, or `isAdmin = true` in a test fixture.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

interface SourceFile {
  path: string; // relative to the scanned project root
  content: string;
}

const GREP_PATTERNS: { id: string; regex: RegExp; title: string }[] = [
  { id: "todo-auth", regex: /\/\/\s*TODO:?\s*auth/i, title: "TODO: auth left in source" },
  { id: "if-true", regex: /if\s*\(\s*true\s*\)/, title: "if (true) — possible stubbed-out or bypassed guard" },
  { id: "is-admin-true", regex: /isAdmin\s*=\s*true\b/, title: "isAdmin hardcoded to true" },
  { id: "bypass-auth", regex: /bypassAuth/i, title: "bypassAuth reference" },
];

const SENSITIVE_ROUTE_SEGMENT = /(^|\/)(debug|seed|admin|api\/dev)(\/|$|\.)/i;
const AUTH_HINT = /(getServerSession|auth\(\)|requireAuth|withAuth|assertAuth|supabase\.auth\.getUser|createServerClient)/;
const ROUTE_FILE = /(^|\/)(route\.(ts|tsx|js)|pages\/api\/.*\.(ts|tsx|js))$/;

function slug(path: string): string {
  return path.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "");
}

export function classifyLeftoverAuth(file: SourceFile): Finding[] {
  const findings: Finding[] = [];
  for (const p of GREP_PATTERNS) {
    if (p.regex.test(file.content)) {
      findings.push(
        mechanicalFinding({
          id: `AUTH-${p.id}-${slug(file.path)}`,
          title: p.title,
          severity: "Medium",
          category: "Leftover auth",
          taxonomy: "Leftover-auth grep",
          location: file.path,
          evidence: `Pattern "${p.id}" matched in ${file.path}.`,
          impact: "May be a development-time auth bypass left in place; confirm it isn't reachable in production.",
          fix: "Remove the stub/bypass, or confirm and document why it's intentional (test fixture, dev-only branch).",
          precisionTier: "review",
        }),
      );
    }
  }
  if (ROUTE_FILE.test(file.path) && SENSITIVE_ROUTE_SEGMENT.test(file.path) && !AUTH_HINT.test(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-sensitive-route-${slug(file.path)}`,
        title: `${file.path} looks like a debug/seed/admin/dev route with no auth-call hint`,
        severity: "High",
        category: "Leftover auth",
        taxonomy: "Unauthenticated debug/admin route",
        location: file.path,
        evidence: `Route path matches /debug|seed|admin|api\\/dev/ and no auth-check call pattern was found in the file.`,
        impact: "If genuinely unauthenticated, this route is reachable by anyone who finds the path.",
        fix: "Add an auth/role check, or remove the route before shipping.",
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

function walk(dir: string, root: string, out: SourceFile[]): void {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walk(full, root, out);
    } else if (SOURCE_EXT.test(entry)) {
      out.push({ path: relative(root, full), content: readFileSync(full, "utf8") });
    }
  }
}

export function scanLeftoverAuth(projectDir: string): Finding[] {
  const files: SourceFile[] = [];
  walk(projectDir, projectDir, files);
  return files.flatMap(classifyLeftoverAuth);
}
