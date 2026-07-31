// #1307 — "shipped but never called" gate. Runs knip a SECOND time with tests removed from the
// entry set (knip.production.json) and ratchets the result against a committed baseline.
//
//   pnpm test-only-exports                    # the gate, as `pnpm verify` runs it
//   pnpm test-only-exports --list             # also enumerate the whole known backlog
//   pnpm test-only-exports --update-baseline  # re-record the backlog after wiring something up
//
// Why a second config instead of `knip --production`: MEASURED 2026-07-27, `knip --production
// --debug` still lists `entry:**/*.{bench,test,test-d,spec,spec-d}.?(c|m)[jt]s?(x)
// (vitest.config.ts)` — production mode does not drop the Vitest plugin's test entry glob, so it
// reported nothing for all four functions named in #1307. knip.production.json turns that plugin
// off and negates `src/**/*.test.ts` out of `project`.
//
// Exit 1 on a NEW row or a STALE baseline row. Exit 0 prints the backlog COUNT anyway — an
// unstated limitation reads as a clean bill of health (CLAUDE.md, "fail loud").

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { arg, assertKnownFlags } from "./args.js";
import { blindSpotSuspects, collect, compare, exportedNames, hiddenByFlag, reasonTriaged, toBaseline, type Baseline, type Unreferenced } from "../test-only-exports.js";
import { collectReasons } from "../recorded-reasons.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

assertKnownFlags(["--dir", "--config", "--baseline", "--list", "--update-baseline", "--blind-spot"]);

const dir = resolve(arg("--dir") ?? REPO_ROOT);
const config = arg("--config") ?? "knip.production.json";
const baselinePath = resolve(dir, arg("--baseline") ?? "test-only-exports.baseline.json");
const listAll = process.argv.includes("--list");

// knip exits 1 whenever it found anything, which is the normal case here; only a crash (no JSON on
// stdout) is an error, and it must not be mistaken for "nothing unreferenced".
function runKnip(configPath: string): Unreferenced[] {
  const knip = spawnSync(join(REPO_ROOT, "node_modules", ".bin", "knip"), ["--directory", dir, "--config", configPath, "--no-config-hints", "--reporter", "json"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  try {
    return collect(JSON.parse(knip.stdout ?? ""));
  } catch {
    console.error(`knip did not produce a JSON report (exit ${knip.status}). stderr:\n${knip.stderr ?? knip.error?.message ?? ""}`);
    process.exit(2);
  }
}

const rows = runKnip(config);

if (process.argv.includes("--update-baseline")) {
  writeFileSync(baselinePath, `${JSON.stringify(toBaseline(rows), null, 2)}\n`);
  console.log(`Recorded ${rows.length} unreferenced rows to ${baselinePath}`);
  process.exit(0);
}

const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as Baseline;

// --blind-spot (#1328): the compensating check for `ignoreExportsUsedInFile`. Re-runs the same
// analysis with the key deleted and triages the difference down to rows kept alive ONLY by an
// in-file consumer that is itself on the baseline — dead capability propping up dead capability.
// Reports both totals unconditionally: the delta measures how much surface the gate leaves
// unexamined, and an unstated limitation reads as a clean bill of health.
if (process.argv.includes("--blind-spot")) {
  const source = JSON.parse(readFileSync(resolve(dir, config), "utf8")) as Record<string, unknown>;
  delete source.ignoreExportsUsedInFile;
  const scratch = mkdtempSync(join(tmpdir(), "harvey-blind-spot-"));
  const unflaggedConfig = join(scratch, "knip.blind-spot.json");
  let unflagged: Unreferenced[];
  try {
    writeFileSync(unflaggedConfig, JSON.stringify(source, null, 2));
    unflagged = runKnip(unflaggedConfig);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  const hidden = hiddenByFlag(unflagged, rows);
  const suspects = blindSpotSuspects(hidden, baseline, (p) => readFileSync(resolve(dir, p), "utf8"));

  console.log("test-only-exports blind spot (#1328) — what `ignoreExportsUsedInFile` hides");
  console.log(`  gated run (${config}): ${rows.length} rows`);
  console.log(`  same analysis with ignoreExportsUsedInFile deleted: ${unflagged.length} rows`);
  console.log(`  hidden by the flag: ${hidden.length} rows — invisible to the gate, by design`);
  console.log(`  of those, kept alive only by a consumer that is ITSELF on the baseline: ${suspects.length}`);
  for (const s of suspects) console.log(`    ${s.id} — in-file consumers: ${s.consumers.join(", ")}`);

  if (suspects.length > 0) {
    console.log("\nEach is dead capability the gate scores as reachable. Wire it up, or record a reason per docs/design/recorded-reasons.md.");
    process.exit(1);
  }
  console.log("\nBLIND SPOT CLEAR — every row the flag hides has a live in-file consumer.");
  process.exit(0);
}

const { added, stale } = compare(rows, baseline);
const count = (kind: Unreferenced["kind"]): number => rows.filter((r) => r.kind === kind).length;

// #1547: the ruling is "a caller OR a recorded reason", and until now the gate could only see
// callers — so a row someone had triaged into a REASON: block was indistinguishable from one nobody
// had read, and the backlog number could only shrink by wiring. Both halves are counted now.
const readSource = (path: string): string => readFileSync(resolve(dir, path), "utf8");
const triaged = new Map(reasonTriaged(rows, collectReasons(["src"], dir), readSource).map((t) => [`${t.row.kind} ${t.row.id}`, t]));

// A `file` row means NOTHING in it is reachable, so name what is inside it — otherwise the
// strongest rows in the report are also the least specific.
const line = (r: Unreferenced): string => {
  const t = triaged.get(`${r.kind} ${r.id}`);
  const mark = t ? `  [recorded reason — ${t.file}:${t.line}]` : "";
  if (r.kind !== "file") return `${r.kind.padEnd(6)} ${r.id}${mark}`;
  const names = exportedNames(r.id, readSource(r.id));
  return `file   ${r.id} — every export unreachable: ${names.join(", ")}${mark}`;
};

console.log("test-only-exports gate (#1307) — production reachability, tests are NOT entry points");
console.log(`  analysed ${dir} with ${config}`);
console.log(`  unreferenced outside tests: ${count("file")} files, ${count("export")} exports, ${count("type")} types (${rows.length} total)`);
console.log(`  known backlog recorded in ${baselinePath} — triage tracked in #1547, not authorised for deletion`);
console.log(`  of the ${rows.length}: ${triaged.size} carry a recorded reason, ${rows.length - triaged.size} still await a caller or a reason (#1547)`);
if (listAll) for (const r of rows) console.log(`    ${line(r)}`);

if (added.length > 0) {
  console.log(`\nNEW — shipped with no production caller (${added.length}):`);
  for (const r of added) console.log(`  ${line(r)}`);
  console.log("Wire it up, or record a reason per docs/design/recorded-reasons.md and re-run with --update-baseline.");
}
if (stale.length > 0) {
  console.log(`\nSTALE baseline rows — now reachable from production, so the ratchet must drop them (${stale.length}):`);
  for (const r of stale) console.log(`  ${r.kind.padEnd(6)} ${r.id}`);
  console.log("Re-run with --update-baseline.");
}

if (added.length > 0 || stale.length > 0) {
  console.log(`\nGATE FAIL — ${added.length} new, ${stale.length} stale.`);
  process.exit(1);
}
console.log(`\nGATE PASS — no capability shipped without a production caller since the baseline (${rows.length} still on it, ${rows.length - triaged.size} untriaged).`);
