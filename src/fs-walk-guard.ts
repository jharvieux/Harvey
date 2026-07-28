// The gate behind src/fs-walk.ts (#1451). `statSync(p).isDirectory()` follows symlinks and throws
// on one that does not resolve; the class was fixed in mutation-scan (#944, 2026-07-24) and came
// straight back in codebase-size.ts one day later, because nothing stopped the next walker being
// written from scratch. #766 had already extracted the shared walker for the same reason and it
// drifted too. So the difference here is not another helper — it is that the raw primitive is
// banned, over a DISCOVERY-BACKED sweep: a file added next month is in scope the moment it exists,
// with nothing to register and nothing to remember.
//
// Detection is AST-based, not textual: a `statSync` inside a comment or a string is not a call, and
// a gate that conflates the two would train people to reword their comments.
//
// SCOPE, stated rather than implied:
//   - The banned tokens are `statSync` and `readdirSync` (bare or as a property, e.g. `fs.statSync`).
//     `readdirSync` is in the ban because the crash has TWO shapes and only one of them stats: a
//     names-only walk keeps an unresolvable link (it is not a directory), and the readFileSync that
//     follows is what throws. MEASURED 2026-07-28 — six live sites of that shape, none containing a
//     `statSync` at all. `lstatSync` is deliberately NOT banned: it does not follow the link.
//   - `fs.promises.stat` / `await stat()` / `statfsSync` are outside the ban. They are the same
//     hazard in principle; none of them appears in the tree today, so banning them would be a rule
//     with a population of zero (#1345). Add them here the day one lands.
//   - Fixture directories are skipped: they are scan TARGETS, not Harvey code, and planting a
//     defective walker in one is sometimes the point.

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";
import ts from "typescript";

export const GUARD_MODULE = "src/fs-walk.ts";
export const DISCOVERY_ROOTS = ["src", "tools"];
export const BANNED = ["statSync", "readdirSync"] as const;
export const SAFE_API = ["readEntriesSafe", "readNamesSafe", "readRecursiveSafe", "isDirectorySafe", "statSafe"];

const SOURCE_FILE = /\.[cm]?[jt]sx?$/;
const SKIP_DIRS = new Set(["node_modules", ".git", "fixtures", "__fixtures__"]);

interface WalkSite {
  file: string;
  line: number;
  snippet: string;
}

export function discoverSourceFiles(repoRoot: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readEntriesSafe(dir).entries) {
      if (SKIP_DIRS.has(e.name)) continue;
      const full = join(dir, e.name);
      if (e.isDirectory) walk(full);
      else if (SOURCE_FILE.test(e.name)) out.push(relative(repoRoot, full).split(sep).join("/"));
    }
  };
  for (const root of DISCOVERY_ROOTS) walk(join(repoRoot, root));
  return out.sort();
}

function callSites(file: string, text: string, names: readonly string[]): WalkSite[] {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const out: WalkSite[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : undefined;
      if (name !== undefined && names.includes(name)) {
        const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
        out.push({ file, line: line + 1, snippet: text.split("\n")[line]?.trim() ?? "" });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

export function findBannedStatSites(files: { path: string; text: string }[]): WalkSite[] {
  return files.filter((f) => f.path !== GUARD_MODULE).flatMap((f) => callSites(f.path, f.text, BANNED));
}

export function findGuardedSites(files: { path: string; text: string }[]): WalkSite[] {
  return files.filter((f) => f.path !== GUARD_MODULE).flatMap((f) => callSites(f.path, f.text, SAFE_API));
}

export function readSourceFiles(repoRoot: string, paths: string[]): { path: string; text: string }[] {
  return paths.map((p) => ({ path: p, text: readFileSync(join(repoRoot, p), "utf8") }));
}
