// Live scoring gate for the corpus's LIVE-tier rows (#1428).
//
// WHY THIS EXISTS. `expectedTier: "connected"` used to mean "scored by nobody". scoreEntry()
// returned `pass: true` unconditionally for it and `grep -rn 'expectedTier === "connected"'` found
// no consumer anywhere that scored such a row against a live run — so an independent verifier gutted
// all three Supabase live detectors (`return []` as the first statement of checkExposedSchemas,
// checkGraphqlIntrospection and checkRealtimeAuthorization) and `validate-calibration` still exited
// 0 with byte-identical output. The rows locked the answer key; nothing locked the detectors.
//
// This is the consumer that did not exist. It scores every live-tier corpus row against a REAL run
// of a REAL stack, and it fails on a miss like any other scored gate.
//
//   pnpm validate:connected                     # local `supabase start` stack on the default ports
//   pnpm validate:connected --db <url> --rest-url <url>
//
// THREE VENUES, because the rows need different surfaces (see LiveTier, calibration/types.ts):
//   local     — a Postgres connection to the stack. runSupabaseScan({ local: true }) IS the product
//               scan path, so what this venue scores is the shipped code, not a re-implementation.
//   connected — PostgREST's schema allow-list, which Postgres does not hold (that is exactly why
//               local mode discloses SB-SCOPE-00, #1330). Read here from the running REST surface:
//               ask for a schema no target defines and PostgREST answers PGRST106 with its whole
//               allow-list in the `hint` ("Only the following schemas are exposed: public,
//               graphql_public, internal_ops"). MEASURED 2026-07-28 against the calibration stack —
//               and it needs NO credential: the same reply comes back with no apikey header and with
//               a bogus one, which is itself worth knowing (#1494, which also wired this same probe
//               into the product's own local-mode scan — probeExposedSchemas now lives in
//               src/scan/supabase.ts and this file imports it rather than keeping a second copy).
//               The two live checks that consume it are then called directly, so gutting either one
//               turns this gate red.
//   hosted    — the Management API's GoTrue auth config. No fixture project exists for it, so its
//               four rows report NOT SCORED here rather than being quietly counted (#1098).
//
// FAIL LOUD, NEVER SILENTLY GREEN, and never permanently red either. A venue this run does not have
// is DISCLOSED and COUNTED — the same contract FALSIFIER-TIER's SKIPPED-LIVE carries (#1072), for the
// same reason: failing on a venue nobody has would make the gate red forever and train readers to
// ignore it. What must never happen is a run that reached NOTHING printing PASS, so scoring zero rows
// is exit 2, UNVERIFIABLE. A PASS line always states how many rows it is over.
//
// PROVEN TO FAIL, 2026-07-28, against the live calibration stack (all three, one at a time,
// `return [];` inserted as the first statement of the named check in src/scan/supabase-config.ts):
//   checkRealtimeAuthorization  -> exit 1, "FAIL P-REALTIME-NO-AUTHZ ... NOT caught by any rule"
//   checkExposedSchemas         -> exit 1, "FAIL P-API-SCHEMA-WIDE"
//   checkGraphqlIntrospection   -> exit 1, "FAIL P-GRAPHQL-INTROSPECTION"
// Clean tree: exit 0, 3/3 scored. A gate nobody has watched fail is indistinguishable from a dead one.

import "./sync-stdio.js";
import { arg, assertKnownFlags } from "./args.js";
import { buildCoverageMatrix, CORPUS, isLiveTier, LIVE_TIERS, type LiveTier, type MatrixRow } from "../scan/calibration.js";
import { hasPgGraphql, LOCAL_REST_URL, probeExposedSchemas, runSupabaseScan } from "../scan/supabase.js";
import { checkExposedSchemas, checkGraphqlIntrospection, type ExtensionInfo } from "../scan/supabase-config.js";
import type { Finding } from "../findings.js";

const FLAGS = ["--db", "--rest-url"] as const;
assertKnownFlags(FLAGS);

const DEFAULT_DB = "postgresql://postgres:postgres@127.0.0.1:54322/postgres";
const dbUrl = arg("--db") ?? DEFAULT_DB;
const restUrl = (arg("--rest-url") ?? LOCAL_REST_URL).replace(/\/$/, "");

const EXTENSIONS_SQL = `select extname as name, extnamespace::regnamespace::text as schema, extversion as installed_version from pg_extension;`;

async function readExtensions(): Promise<ExtensionInfo[]> {
  const { default: postgres } = await import("postgres");
  const sql = postgres(dbUrl, { max: 1, idle_timeout: 5 });
  try {
    return (await sql.unsafe(EXTENSIONS_SQL)) as unknown as ExtensionInfo[];
  } finally {
    await sql.end();
  }
}

const findings: Finding[] = [];
const venues = new Set<LiveTier>();
const unavailable: { venue: LiveTier; why: string }[] = [];

console.log(`Live corpus gate (#1428) — db ${dbUrl}, rest ${restUrl}\n`);

let extensions: ExtensionInfo[] = [];
try {
  extensions = await readExtensions();
  findings.push(...(await runSupabaseScan({ local: true })));
  venues.add("local");
  console.log(`VENUE local      — connected; the product's own scanLocal produced ${findings.length} finding(s)`);
} catch (e) {
  unavailable.push({ venue: "local", why: `${dbUrl} unreachable — ${e instanceof Error ? e.message : String(e)}. Bring the stack up: \`cd targets/calibration && supabase start\`` });
}

const probe = await probeExposedSchemas(restUrl);
if ("schemas" in probe) {
  const pgGraphql = hasPgGraphql(extensions);
  findings.push(...checkExposedSchemas(probe.schemas), ...checkGraphqlIntrospection(pgGraphql, probe.schemas));
  venues.add("connected");
  console.log(`VENUE connected  — PostgREST exposes [${probe.schemas.join(", ")}]; pg_graphql installed: ${pgGraphql}`);
} else {
  unavailable.push({ venue: "connected", why: probe.unavailable });
}
for (const u of unavailable) console.log(`VENUE ${u.venue.padEnd(10)} — UNAVAILABLE: ${u.why}`);

const liveCorpus = CORPUS.filter((e) => isLiveTier(e.expectedTier));
const matrix = buildCoverageMatrix(findings, liveCorpus, venues);
const byId = new Map(matrix.rows.map((r) => [r.id, r]));

console.log(`\nLIVE-TIER CORPUS — ${liveCorpus.length} row(s) across ${LIVE_TIERS.length} venue(s):`);
const mark = (r: MatrixRow): string => (r.notScored ? "SKIP" : r.pass ? "PASS" : "FAIL");
for (const e of liveCorpus) {
  const r = byId.get(e.id) as MatrixRow;
  console.log(`  ${mark(r)}  ${e.id.padEnd(24)} ${String(e.expectedTier).padEnd(10)} ${e.module ?? "M1"}  ${r.detail}`);
}

const scored = matrix.rows.filter((r) => !r.notScored);
const failures = scored.filter((r) => !r.pass);
const notScored = matrix.rows.filter((r) => r.notScored);
console.log(`\nScored ${scored.length}/${liveCorpus.length}; ${failures.length} failing; ${notScored.length} not scored.`);

// Contract, borrowed from FALSIFIER-TIER's SKIPPED-LIVE (#1072) because the situation is identical:
// a venue this run genuinely does not have is DISCLOSED and COUNTED, not failed — failing it would
// make the gate permanently red and train everyone to ignore it. What must never happen is a run
// that reached NOTHING printing PASS, so scoring zero rows is exit 2, UNVERIFIABLE.
if (scored.length === 0) {
  console.log(
    `\nUNVERIFIABLE (exit 2) — this run scored no live row at all, so it is not a result:` +
      `\n${unavailable.map((u) => `  ${u.venue}: ${u.why}`).join("\n")}` +
      `\nA gate that cannot reach its subject must not print PASS; that is the state #1428 exists to end.`,
  );
  process.exit(2);
}
if (failures.length > 0) {
  console.log(`\nGATE FAIL — live-tier corpus miss: ${failures.map((r) => `${r.id} (${r.detail})`).join("; ")}`);
  process.exit(1);
}
console.log(
  `\nGATE PASS — ${scored.length} live-tier corpus row(s) scored against a real run, all held.` +
    (notScored.length > 0
      ? ` ${notScored.length} row(s) NOT SCORED and listed above: ${notScored.map((r) => r.id).join(", ")}. That is a stated limit of THIS run, not a result — a pass rate here is over the ${scored.length} rows, never over ${liveCorpus.length}.`
      : ""),
);
