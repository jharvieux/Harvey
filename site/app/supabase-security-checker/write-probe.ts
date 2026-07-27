// Non-destructive write-attempt probe logic (Harvey #888), split out from page.tsx so it can be
// unit-tested offline against the exact PostgREST response shapes measured on a local stack.
//
// SAFETY — why this never persists a row. The probe sends an INSERT that is GUARANTEED to fail
// validation: it omits every column, so any table with at least one NOT-NULL-without-default column
// (PostgREST lists these in `definitions[table].required`) raises 23502 (not-null violation) and the
// statement aborts — never a 2xx, never a stored row. MEASURED 2026-07-26 against
// postgres:16-alpine + postgrest:v14.12 (docs/design/postgrest-write-eval-order.md): Postgres
// evaluates the GRANT and the RLS `WITH CHECK` policy BEFORE the not-null constraint, so:
//   • permissive policy (WITH CHECK true) + grant  -> 400 / 23502  (the write WOULD have been allowed)
//   • restrictive policy denies the row            -> 401|403 / 42501 ("violates row-level security")
//   • no INSERT grant to the role                  -> 401|403 / 42501 ("permission denied for table")
// That ordering is the whole basis for distinguishing "would-be-permitted" from "denied" without
// ever writing. If the table has NO required column we CANNOT guarantee non-persistence, so the probe
// is skipped for that table (disclosed, never a silent gap) rather than risking a stored row.

export type WriteVerdict =
  | "writable" // RLS/grant let the row through; only the deliberately-omitted column stopped it
  | "denied" // grant or RLS WITH CHECK rejected the row (the good outcome)
  | "persisted" // a 2xx came back — MUST NOT happen with an all-columns-omitted body; a default/trigger backfilled the column
  | "inconclusive"; // any other shape — cannot be read as either safe or unsafe

// A column that PostgREST reports as required (NOT NULL, no default). Omitting it guarantees the
// INSERT fails the not-null constraint. Generated/defaulted/nullable columns are absent from
// `required`, so a table whose `required` is empty has no such guarantee — the caller must skip it.
export function requiredColumns(def: unknown): string[] {
  if (!def || typeof def !== "object") return [];
  const req = (def as { required?: unknown }).required;
  return Array.isArray(req) ? req.filter((c): c is string => typeof c === "string") : [];
}

// Whether a non-destructive INSERT probe can be constructed for this table. Only true when omitting
// all columns is guaranteed to violate a not-null constraint.
export function canProbeWrite(def: unknown): boolean {
  return requiredColumns(def).length > 0;
}

// Classify a write-attempt response. The body is always an all-columns-omitted INSERT, so a 2xx is
// never expected; it is surfaced as `persisted` (a loud edge case), never treated as a pass.
export function classifyWriteResponse(status: number, pgCode: string | null): WriteVerdict {
  if (status >= 200 && status < 300) return "persisted";
  if (status === 400 && pgCode === "23502") return "writable"; // not-null fired => grant+RLS already passed
  if (status === 401 || status === 403) return "denied"; // 42501: grant or RLS WITH CHECK rejected the row
  return "inconclusive";
}

// PostgREST returns its DB error code in the JSON body's `code`. Pull it out defensively.
export function pgCodeOf(body: unknown): string | null {
  if (body && typeof body === "object") {
    const c = (body as { code?: unknown }).code;
    if (typeof c === "string") return c;
  }
  return null;
}
