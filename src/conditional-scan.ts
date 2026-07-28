// Gate 4b of the #1320 prevention program (#1330): a scan path that omits a check its sibling path
// runs must say so in the deliverable.
//
// Gate 4a (src/disclosure-venue.ts) catches a bound the engineer WROTE DOWN in a comment and never
// carried into the finding. This is the harder half: an omission that carries no bound at all,
// because the branch that skips the check simply does not call it. `scanLocal` in
// src/scan/supabase.ts is the shape — two of the checks `scanHosted` runs read PostgREST's
// db-schema config, which is not in Postgres, so local mode cannot run them. It returned its
// finding list and said nothing, and a locally-scanned client saw the same silence as one whose
// schema exposure was checked and found clean.
//
// What this checks, mechanically, per registered module:
//   1. the set of sibling scan paths in the file matches the registry EXACTLY — a new `scan*`
//      function fails loud rather than joining the file unexamined;
//   2. the omissions computed from the source (a `check*` call some sibling makes and this path
//      does not) match the omissions the registry DECLARES — a newly-omitted check fails;
//   3. every declared omission is disclosed: the omitting path calls the declared emitter, the
//      emitter carries the declared not-assessed row id, and its text names the client-legible
//      class of every check it stands in for.
//
// The registry is DISCOVERY-BACKED, not merely enumerated: discoverConditionalScans walks
// src/scan and src/detectors for any module carrying two or more sibling `scan*` paths, and the CLI
// fails on one CONDITIONAL_SCANS does not list. So a new conditional module cannot join the repo
// unexamined — #1330's first acceptance bullet ("fails loud when a new conditional path appears")
// without the enumerated list going stale the first time someone adds a file.
//
// SCOPE OF THIS GATE, stated so its own silence is not read as coverage: what discovery recognises
// is a SHAPE — two top-level `scan*` functions in one module, compared by the literal `check*(`
// calls in each one's own body. Two things sit outside it. A check reached INDIRECTLY (through a
// helper, a table of callbacks, a call in another module) is not counted on either side; because
// both sides are read the same way, an indirection added to BOTH paths is simply unseen, while one
// added to a single path reads as an omission and fails loud, which is the safe direction. And a
// conditional omission expressed some other way — an `if (opts.x)` block inside ONE function that
// adds checks, a strategy object, a per-target rule list — is not this shape and is not discovered.
//
// REASON: the omission signal is the literal text of a `check*(` call in a scan path's own body, so a check either path reaches through a helper or another module is invisible to the comparison, and a conditional omission not expressed as two sibling top-level `scan*` functions is not discovered at all
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-28 — `src/conditional-scan.test.ts` "reads a check reached through a helper as an omission" holds the behaviour: an indirected check in one path is reported as omitted even though the path does run it, which is the same blindness in its visible direction.
// FALSIFIER: pnpm exec vitest run src/conditional-scan.test.ts -t "reads a check reached through a helper as an omission" > /tmp/harvey-cs.log 2>&1; grep -q "1 passed" /tmp/harvey-cs.log && exit 1 || { grep -q "1 failed" /tmp/harvey-cs.log && exit 0 || exit 127; }
// TOUCHES: src/conditional-scan.ts src/scan
//
// A lower bound on the defect, not a census of it.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";
import { fileURLToPath } from "node:url";

// One omitted check, and the words the disclosure row must use for it. The class name is what the
// CLIENT reads; naming the internal function in the row would disclose nothing to them, so the
// registry carries both and the gate checks the pair.
type OmittedCheck = { readonly fn: string; readonly namedInRow: string };

export type ConditionalScan = {
  readonly file: string;
  // Exhaustive over the module's sibling scan paths. A `scan*` function in the file and not here
  // is a violation, not an addition.
  readonly paths: readonly string[];
  readonly disclosures: readonly {
    readonly path: string;
    readonly rowId: string;
    readonly emitter: string;
    readonly omits: readonly OmittedCheck[];
  }[];
};

export const CONDITIONAL_SCANS: readonly ConditionalScan[] = [
  {
    file: "src/scan/supabase.ts",
    paths: ["scanHosted", "scanLocal"],
    disclosures: [
      {
        path: "scanLocal",
        rowId: "SB-SCOPE-00",
        emitter: "localScopeFinding",
        omits: [
          { fn: "checkExposedSchemas", namedInRow: "PostgREST-exposed schemas" },
          { fn: "checkGraphqlIntrospection", namedInRow: "GraphQL introspection" },
          { fn: "checkAuthConfig", namedInRow: "GoTrue auth configuration" },
        ],
      },
    ],
  },
];

const SCAN_PATH = /^(?:export )?(?:async )?function (scan[A-Z]\w*)\s*\(/;
const CHECK_CALL = /\b(check[A-Z]\w*)\s*\(/g;
// A top-level `}` in column 0 ends a top-level function body in this repo's formatting.
const BODY_END = /^\}/;

type ScanPathBody = { readonly name: string; readonly body: string };

export function parseScanPaths(text: string): ScanPathBody[] {
  const lines = text.split("\n");
  const out: ScanPathBody[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = SCAN_PATH.exec(lines[i] ?? "");
    if (!m?.[1]) continue;
    let j = i + 1;
    while (j < lines.length && !BODY_END.test(lines[j] ?? "")) j++;
    out.push({ name: m[1], body: lines.slice(i, j + 1).join("\n") });
  }
  return out;
}

function checksCalled(body: string): Set<string> {
  return new Set([...body.matchAll(CHECK_CALL)].map((m) => m[1] as string));
}

// The body of a named function, for reading the disclosure row out of its emitter.
function functionBody(text: string, name: string): string | null {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => new RegExp(`^(?:export )?(?:async )?function ${name}\\s*\\(`).test(l));
  if (start === -1) return null;
  let end = start + 1;
  while (end < lines.length && !BODY_END.test(lines[end] ?? "")) end++;
  return lines.slice(start, end + 1).join("\n");
}

type ConditionalScanViolation = {
  readonly file: string;
  readonly detail: string;
};

export function auditConditionalScan(entry: ConditionalScan, text: string): ConditionalScanViolation[] {
  const violations: ConditionalScanViolation[] = [];
  const fail = (detail: string): void => void violations.push({ file: entry.file, detail });

  const parsed = parseScanPaths(text);
  const found = parsed.map((p) => p.name).sort();
  const declared = [...entry.paths].sort();
  if (found.join(",") !== declared.join(",")) {
    fail(
      `sibling scan paths are ${found.length ? found.join(", ") : "(none)"} but CONDITIONAL_SCANS declares ` +
        `${declared.join(", ")}. A new conditional path must be enumerated (and its omissions declared) before it can ship.`,
    );
    return violations;
  }

  const byName = new Map(parsed.map((p) => [p.name, checksCalled(p.body)]));
  const union = new Set([...byName.values()].flatMap((s) => [...s]));

  for (const path of entry.paths) {
    const runs = byName.get(path) as Set<string>;
    const omitted = [...union].filter((c) => !runs.has(c)).sort();
    const disclosure = entry.disclosures.find((d) => d.path === path);
    const declaredOmits = [...(disclosure?.omits ?? [])].map((o) => o.fn).sort();
    if (omitted.join(",") !== declaredOmits.join(",")) {
      fail(
        `${path} omits ${omitted.length ? omitted.join(", ") : "(nothing)"} that a sibling path runs, but the ` +
          `registry declares ${declaredOmits.length ? declaredOmits.join(", ") : "(nothing)"}. An omission that is ` +
          `not declared is not disclosed either — the client sees the same silence as a check that ran and found nothing.`,
      );
      continue;
    }
    if (!disclosure) continue;

    const body = parsed.find((p) => p.name === path)?.body ?? "";
    if (!new RegExp(`\\b${disclosure.emitter}\\s*\\(`).test(body)) {
      fail(`${path} declares omissions but never calls ${disclosure.emitter}(), so no not-assessed row is emitted.`);
      continue;
    }
    const emitterBody = functionBody(text, disclosure.emitter);
    if (emitterBody === null) {
      fail(`${disclosure.emitter} is declared as ${path}'s disclosure emitter but no such function exists in the file.`);
      continue;
    }
    if (!emitterBody.includes(`id: "${disclosure.rowId}"`)) {
      fail(`${disclosure.emitter} does not emit the declared not-assessed row id ${disclosure.rowId}.`);
      continue;
    }
    for (const omit of disclosure.omits) {
      if (!emitterBody.includes(omit.namedInRow)) {
        fail(
          `${disclosure.rowId} does not name the class it stands in for: ${path} omits ${omit.fn} and the row never ` +
            `says "${omit.namedInRow}". A counted row that does not name what went unchecked discloses nothing.`,
        );
      }
    }
  }
  return violations;
}

// Roots walked for the sibling-scan-path shape. An unregistered module here fails the CLI, which is
// what keeps CONDITIONAL_SCANS from going stale the first time someone adds a file.
export const DISCOVERY_ROOTS = ["src/scan", "src/detectors"] as const;

export function discoverConditionalScans(read: (file: string) => string = (f) => readFileSync(repoPath(f), "utf8")): string[] {
  const out: string[] = [];
  for (const root of DISCOVERY_ROOTS) {
    const walk = (dir: string): void => {
      for (const entry of readEntriesSafe(repoPath(dir)).entries) {
        const rel = `${dir}/${entry.name}`;
        if (entry.isDirectory) walk(rel);
        else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") && parseScanPaths(read(rel)).length >= 2) out.push(rel);
      }
    };
    walk(root);
  }
  return out.sort();
}

function repoPath(rel: string): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", rel);
}

export function readConditionalScan(entry: ConditionalScan): string {
  return readFileSync(repoPath(entry.file), "utf8");
}

export function auditConditionalScans(
  entries: readonly ConditionalScan[],
  read: (entry: ConditionalScan) => string = readConditionalScan,
): ConditionalScanViolation[] {
  return entries.flatMap((entry) => auditConditionalScan(entry, read(entry)));
}
