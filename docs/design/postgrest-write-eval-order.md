# PostgREST write eval-order — empirical basis for the free RLS write-attempt probe (#888)

The free RLS checker (`site/app/supabase-security-checker/page.tsx`) is a **public** tool people
point at their own live Supabase projects. Its write-attempt half (#888, split from #749) was
deferred because it carries **destructive-write risk against strangers' production databases** and
its safety rests on an empirical claim about PostgREST that had never been measured. Operator ruling
2026-07-26: **GO**, including the measurement. This file is that measurement.

## The claim under test

The probe's safety plan (issue #749 Part 1): send an INSERT that omits a required NOT-NULL column, so
the write is rejected by the not-null constraint (400) *without persisting a row*, and read the status
to tell **"would have been permitted"** from **"denied"**. That only works if PostgreSQL evaluates the
GRANT and the RLS `WITH CHECK` policy **before** the not-null constraint. If not, a denied write and a
would-be-permitted write could be indistinguishable, or worse, a row could persist.

## What was measured

MEASURED 2026-07-26 against a local throwaway stack — `postgres:16-alpine` (PostgreSQL 16.14) +
`public.ecr.aws/supabase/postgrest:v14.12`, the same PostgREST image the local Supabase CLI ships —
started via `docker run`, never a remote or client DB. Reproduction scripts: the two `run.sh`/`run2.sh`
harnesses used are ephemeral (scratchpad); the schema and probes are reproduced below.

Three tables, all with a `secret text NOT NULL` column and RLS enabled:

| table          | RLS policy                                | anon grant        |
|----------------|-------------------------------------------|-------------------|
| `open_writable`| `FOR ALL … USING(true) WITH CHECK(true)`  | select/ins/upd/del|
| `scoped`       | INSERT `WITH CHECK (tenant_id = jwt tenant)`; upd/del `USING(false)` | select/ins/upd/del |
| `nogrant`      | permissive, but **no** write grant to anon | select only       |

Each probe was sent **as the anon role**, always **omitting the NOT-NULL `secret` column**:

| probe                                             | HTTP | PostgREST `code` | message |
|---------------------------------------------------|------|------------------|---------|
| INSERT `open_writable` `{"tenant_id":999}`        | **400** | `23502` | null value in column "secret" … violates not-null constraint |
| INSERT `scoped` `{"tenant_id":999}`               | **401** | `42501` | new row violates row-level security policy for table "scoped" |
| INSERT `nogrant` `{"tenant_id":999}`              | **401** | `42501` | permission denied for table nogrant |
| UPDATE `open_writable?id=eq.1` `{"secret":null}`  | **400** | `23502` | (not-null) — and the row's `secret` was `a` before AND after |
| UPDATE `scoped?id=eq.1` `{"secret":null}`         | **200** | —       | `[]` — RLS `USING(false)` filtered the row out; nothing matched |
| DELETE `scoped?id=eq.1`                           | **200** | —       | `[]` — nothing matched, nothing deleted |

**Row counts and max ids after every probe: unchanged** (`open_writable`=2, `scoped`=2, `nogrant`=2,
max id 2 each). No probe persisted anything.

## Findings

1. **RLS `WITH CHECK` and the GRANT are evaluated BEFORE the not-null constraint.** A permissive
   policy that would have accepted the row returns `400 / 23502` (only the omitted column stopped it);
   a policy or grant that rejects the row returns `401|403 / 42501` and never reaches the not-null
   check. The two are cleanly distinguishable. **The claim the deferral demanded is confirmed.**
2. **The all-columns-omitted INSERT never persists** as long as the table has ≥1 NOT-NULL-without-default
   column (PostgREST lists exactly those in `definitions[table].required`). If `required` is empty we
   have **no** such guarantee, so the probe must SKIP that table rather than risk a stored row.
3. **`Prefer: tx=rollback` is NOT a usable safety net.** MEASURED: under default PostgREST config a
   VALID insert sent with `Prefer: tx=rollback` returned `201` and **the row persisted**. It only rolls
   back when the server sets `db-tx-end = commit-allow-override`, which Supabase does **not** enable by
   default. A public tool pointed at strangers' projects therefore cannot rely on it. Safety must come
   from the guaranteed-invalid payload, not from a server-side transaction mode.
4. **DELETE cannot be made non-destructive** and is therefore NOT probed. DELETE has no payload to
   invalidate; a permitted DELETE returns 2xx and removes a row. A denied DELETE returns `200 []`
   (RLS filtered the row out), so status alone cannot even confirm a policy exists. The full M2
   pentest (which stands up a *copy* of the stack) is the right place to test delete authorization.

## The safe mechanism the probe ships with

- **INSERT only**, and only when `definitions[table].required` is non-empty. Body is `{}` (omit all
  columns) → guaranteed `23502` on any table with a NOT-NULL-without-default column → never 2xx →
  never persisted.
- Classification (`site/app/supabase-security-checker/write-probe.ts`): `400/23502` → **writable**
  (a finding); `401|403` → **denied** (good); any `2xx` → **persisted** — impossible with an empty
  body, surfaced loudly as "a row may have been created (a default/trigger backfilled the column)",
  never treated as a pass; anything else → **inconclusive**.
- Tables with no required column are **skipped and disclosed** (a count in the output), never silently
  dropped.
