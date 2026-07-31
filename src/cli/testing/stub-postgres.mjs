// A stand-in for the `postgres` driver, so a CLI round-trip test can drive
// src/cli/detect-deeper.ts end to end without a live database (#1407).
//
// The rows are read from HARVEY_STUB_PG_ROWS (a JSON object keyed by the first
// distinctive token of each query detect-deeper issues). Anything unlisted
// answers []. This exists so the test under it exercises the CLI's OWN argv
// parsing and file write — the part #1407 found unguarded — rather than the
// driver, whose behaviour is not what that issue is about.

const fixtures = JSON.parse(process.env.HARVEY_STUB_PG_ROWS ?? "{}");

const rowsFor = (query) => {
  for (const [key, rows] of Object.entries(fixtures)) {
    if (query.includes(key)) return rows;
  }
  return [];
};

export default function postgres() {
  const sql = () => Promise.resolve([]);
  sql.unsafe = (query) => Promise.resolve(rowsFor(query));
  sql.end = () => Promise.resolve();
  return sql;
}
