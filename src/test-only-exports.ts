// #1307 — the "shipped but never called" gate, ratchet half.
//
// knip.json lists `src/**/*.test.ts` as an ENTRY point, so an export whose only consumer is its own
// test is "reachable" and `pnpm knip` reports nothing. A test proving a function works is
// ACCOUNTING; a production call site is DELIVERY, and CLAUDE.md's doctrine says those are not the
// same thing — but `pnpm verify` could not tell them apart. knip.production.json re-runs the same
// analysis with tests dropped from `entry` and `project`, and this module turns its report into a
// ratchet.
//
// A ratchet, NOT a delete list (operator ruling 2026-07-27, #1320): the gate reports, it does not
// authorise deletion. Today's backlog is enumerated in a committed baseline; anything NEW fails,
// and a baseline row that has since gained a production caller fails too, so the list can only
// shrink.
//
// WHAT THE RATCHET CANNOT SEE, recorded here rather than in an issue body the reason registry
// cannot reach. `knip.production.json` sets `ignoreExportsUsedInFile: true`, deliberately: without
// it the same run reports 272 rows instead of 26 (MEASURED 2026-07-27 — copy the config, delete the
// key, `node_modules/.bin/knip --config <copy> --no-config-hints --reporter json`; recorded as 264
// the day before, so quote the run, not this line), because every `src/scan/**` detector is exported
// for its own test while being called by a sibling in the same file, and a gate firing on that
// pattern would fire on nearly every new detector. The cost is a real blind spot with two MEASURED
// instances, not a hypothetical one: `src/fix/schedule.ts:114 DEFAULT_CAPS` and
// `src/fix/verify.ts:52 scrubSecrets` are each dead outside tests and invisible to the count of 26,
// because their only in-file consumer is itself on the baseline. #1328 carries the compensating
// check (triage only the rows whose in-file consumer is itself on the baseline) as an acceptance
// bullet.
//
// REASON: a symbol exported AND used inside its own file is invisible to this ratchet even when the in-file use is itself dead, so the row count understates the dead surface — two instances measured (src/fix/schedule.ts DEFAULT_CAPS, src/fix/verify.ts scrubSecrets)
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-27 — `pnpm test-only-exports --list` reports 26 rows with the flag set; the same analysis with `ignoreExportsUsedInFile` deleted reports 272, and both named symbols appear only in the second run.
// FALSIFIER: grep -q '"ignoreExportsUsedInFile": true' knip.production.json && exit 1 || exit 0
// TOUCHES: knip.production.json

import ts from "typescript";
import { parse } from "./detectors/common.js";

export type UnreferencedKind = "file" | "export" | "type";

/** `id` is a path for `file`, `path:name` for `export`/`type`. Never a line number: those churn. */
export interface Unreferenced {
  kind: UnreferencedKind;
  id: string;
}

/** The subset of knip's `--reporter json` shape this gate reads. */
interface KnipReport {
  files?: readonly string[];
  issues?: readonly {
    file: string;
    exports?: readonly { name: string }[];
    types?: readonly { name: string }[];
  }[];
}

export interface Baseline {
  files: string[];
  exports: string[];
  types: string[];
}

export function collect(report: KnipReport): Unreferenced[] {
  const rows: Unreferenced[] = (report.files ?? []).map((id) => ({ kind: "file", id }));
  for (const issue of report.issues ?? []) {
    for (const e of issue.exports ?? []) rows.push({ kind: "export", id: `${issue.file}:${e.name}` });
    for (const t of issue.types ?? []) rows.push({ kind: "type", id: `${issue.file}:${t.name}` });
  }
  return rows;
}

/**
 * Every exported name in a file. knip reports an unreachable FILE instead of its exports, so
 * without this the report names `src/fix/escalation.ts` and hides `runEscalation` inside it — two
 * of the four capabilities #1307 was opened over are in exactly that position.
 */
export function exportedNames(path: string, text: string): string[] {
  const names: string[] = [];
  for (const stmt of parse(path, text).statements) {
    if (!ts.canHaveModifiers(stmt) || !ts.getModifiers(stmt)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) if (ts.isIdentifier(d.name)) names.push(d.name.text);
    } else if (
      (ts.isFunctionDeclaration(stmt) || ts.isClassDeclaration(stmt) || ts.isInterfaceDeclaration(stmt) || ts.isTypeAliasDeclaration(stmt) || ts.isEnumDeclaration(stmt)) &&
      stmt.name
    ) {
      names.push(stmt.name.text);
    }
  }
  return names;
}

export function toBaseline(rows: readonly Unreferenced[]): Baseline {
  const of = (kind: UnreferencedKind): string[] => rows.filter((r) => r.kind === kind).map((r) => r.id).sort();
  return { files: of("file"), exports: of("export"), types: of("type") };
}

function expand(baseline: Baseline): Unreferenced[] {
  return [
    ...baseline.files.map((id): Unreferenced => ({ kind: "file", id })),
    ...baseline.exports.map((id): Unreferenced => ({ kind: "export", id })),
    ...baseline.types.map((id): Unreferenced => ({ kind: "type", id })),
  ];
}

const key = (r: Unreferenced): string => `${r.kind} ${r.id}`;

/**
 * `added` — reachable only from tests and not on the baseline: a capability that shipped without a
 * production caller. `stale` — on the baseline but reachable now: the ratchet's other pawl, so a
 * wired-up capability cannot leave its row behind to absorb the next regression.
 */
export function compare(rows: readonly Unreferenced[], baseline: Baseline): { added: Unreferenced[]; stale: Unreferenced[] } {
  const now = new Set(rows.map(key));
  const known = new Set(expand(baseline).map(key));
  return {
    added: rows.filter((r) => !known.has(key(r))),
    stale: expand(baseline).filter((r) => !now.has(key(r))),
  };
}
