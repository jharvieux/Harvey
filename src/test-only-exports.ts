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
// it the same run reports far more rows, because every `src/scan/**` detector is exported for its
// own test while being called by a sibling in the same file, and a gate firing on that pattern would
// fire on nearly every new detector. The cost is that a symbol exported AND used inside its own file
// is invisible to the gate even when the in-file use is ITSELF dead.
//
// That cost is no longer only prose: `--blind-spot` (#1328) runs the same analysis with the flag
// deleted and triages the difference down to the rows the flag hides whose in-file consumers are
// ALL themselves on the baseline — the mechanical query that found the two instances #1331 reported
// by hand. Both of those have since gained production callers and the query is empty; it stays wired
// so the next one fails loud instead of being found by hand a second time.
//
// Do NOT quote a row count from this comment. `pnpm test-only-exports --list` prints the gated count
// and `--blind-spot` prints both counts and the delta; the numbers move whenever a capability gains
// or loses a caller.
//
// REASON: a symbol exported AND used inside its own file is invisible to this ratchet even when the in-file use is itself dead, so the gated row count understates the dead surface
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-30 — `pnpm test-only-exports --blind-spot` runs knip with and without `ignoreExportsUsedInFile` and prints both totals plus the hidden delta; the two instances recorded by #1331 (src/fix/schedule.ts DEFAULT_CAPS, src/fix/verify.ts scrubSecrets) both have production callers as of this run, so the triaged suspect list is empty.
// FALSIFIER: test -f knip.production.json || exit 127; grep -q '"ignoreExportsUsedInFile": true' knip.production.json && exit 1 || exit 0
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

/**
 * Top-level declarations in `path` whose body references `name`, excluding `name`'s own declaration.
 * The blind spot is a symbol kept alive ONLY by an in-file use, so this names what is keeping it
 * alive — a caller that is itself dead keeps nothing alive.
 */
export function inFileConsumers(path: string, text: string, name: string): string[] {
  const consumers: string[] = [];
  for (const stmt of parse(path, text).statements) {
    const declared = declaredNames(stmt);
    if (declared.includes(name)) continue;
    let refers = false;
    const walk = (node: ts.Node): void => {
      if (refers) return;
      if (ts.isIdentifier(node) && node.text === name) refers = true;
      else ts.forEachChild(node, walk);
    };
    walk(stmt);
    if (refers) consumers.push(...(declared.length > 0 ? declared : ["<module scope>"]));
  }
  return [...new Set(consumers)];
}

function declaredNames(stmt: ts.Statement): string[] {
  if (ts.isVariableStatement(stmt)) {
    return stmt.declarationList.declarations.flatMap((d) => (ts.isIdentifier(d.name) ? [d.name.text] : []));
  }
  const named =
    ts.isFunctionDeclaration(stmt) || ts.isClassDeclaration(stmt) || ts.isInterfaceDeclaration(stmt) || ts.isTypeAliasDeclaration(stmt) || ts.isEnumDeclaration(stmt);
  return named && stmt.name ? [stmt.name.text] : [];
}

interface BlindSpotSuspect {
  id: string;
  consumers: string[];
}

/**
 * The compensating check for `ignoreExportsUsedInFile` (#1328). `hidden` is the set of rows the
 * unflagged run reports and the flagged run does not — i.e. everything kept alive by an in-file use
 * alone. A row is a SUSPECT when every one of those in-file consumers is itself on the baseline:
 * the symbol is dead capability propping up dead capability, which the gate scores as reachable.
 * A row with no in-file consumer at all is not a suspect — that is knip disagreeing with itself,
 * not the blind spot this query is for.
 */
export function blindSpotSuspects(
  hidden: readonly Unreferenced[],
  baseline: Baseline,
  read: (path: string) => string,
): BlindSpotSuspect[] {
  const deadFiles = new Set(baseline.files);
  const deadExports = new Set(baseline.exports);
  const suspects: BlindSpotSuspect[] = [];
  for (const row of hidden) {
    if (row.kind === "file") continue;
    const [path, name] = splitId(row.id);
    if (name === undefined) continue;
    const consumers = inFileConsumers(path, read(path), name);
    if (consumers.length === 0) continue;
    if (consumers.every((c) => deadFiles.has(path) || deadExports.has(`${path}:${c}`))) {
      suspects.push({ id: row.id, consumers });
    }
  }
  return suspects;
}

/** `path:name` — split on the LAST colon, because a Windows-style path can carry one. */
function splitId(id: string): [string, string | undefined] {
  const at = id.lastIndexOf(":");
  return at < 0 ? [id, undefined] : [id.slice(0, at), id.slice(at + 1)];
}

/** Rows present in the unflagged run and absent from the flagged one: what the flag hides. */
export function hiddenByFlag(unflagged: readonly Unreferenced[], flagged: readonly Unreferenced[]): Unreferenced[] {
  const gated = new Set(flagged.map(key));
  return unflagged.filter((r) => !gated.has(key(r)));
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
