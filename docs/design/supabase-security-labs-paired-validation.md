# Paired broken/fixed validation — `supabase-security-labs` (#895)

**What this is:** the first external, Supabase-native **paired** ground truth Harvey has ever been
scored against — the same lab shipped in a deliberately-broken state and a fixed state, so a true
positive and its matching false-positive trap sit side by side.

`docs/test-targets.md` recorded *"No DVWA-style intentionally-vulnerable Supabase repo exists
(confirmed)"* on 2026-06-27. That was true when written and false by the time it was read. **A recorded
reason is a claim about the world, and claims decay** — this is that rule firing on the repo's own
documentation.

Everything below was executed on **2026-07-24**. Numbers come from runs, not from the target's README.

- Target: `elamilutinovic-vibePep/supabase-security-labs` @ `c8ac29b9c19c1064212bd296c3712909924f9b22`
- Licence **NONE** → all rights reserved by default. Pinned-clone manifest only: nothing from this repo
  is vendored into `targets/` or distilled into a `*.entries.ts`.
- Toolchain: colima/Docker, Supabase CLI 2.102.0, node v24.15.0.

## Step 1 — verify the labelling before trusting it

The repo is unstarred and single-author, so #895 required the labels be checked, not believed. Diffing
`rls-broken-lab/supabase/migrations/`:

| | `…090100__lab_broken_rls_and_storage.sql` | `…090200__lab_fixes_rls_and_storage.sql` |
|---|---|---|
| `families` SELECT | `using (true)` — every authed user reads every family | `using (owner_user_id = auth.uid())` |
| `family_members` SELECT | `using (true)` | `using (public.user_in_family(family_id))` |
| `posts` SELECT | `using (true)` | `using (public.user_in_family(family_id))` |
| `posts` INSERT | `with check (owner_profile_id = auth.uid())` — compares a **profile** id to a **user** id, so nothing inserts | `with check (user_in_family(family_id) and owner_profile_id = current_profile_id())` |
| storage bucket `family-media` | `public = true` | `public = false` + per-object `metadata->>'user_id'` policies |

**Verdict: the labelling is genuine.** The planted bugs are real, named in the migration's own comments,
and the fix migration really does replace each one.

**But the ground truth is incomplete, and that is a finding about the target.** `public.profiles` is
created in `…090000__lab_schema.sql` and **RLS is never enabled on it in any of the three migrations** —
not in the broken one, not in the "fix". So the fixed variant is still leaking a table to `anon`. The
lab does not label this, and any consumer treating the fixed variant as a clean negative would be wrong.

## Step 2 — reproduce it live, with Harvey's own stand-up

The lab ships `01_seed.sh` / `02_repro_leak.sh` / `03_verify_fix.sh`. Those were **not** executed: a
cloned third-party repo's scripts are data, not something to run. The equivalent reproduction was done
with Harvey's own autonomous M2 tier, which is stronger evidence anyway — it means the result is a
statement about *Harvey's* probe methodology, not about the target's test harness.

Two variants were built from the pinned clone in scratch (never committed):

- `broken/` — `__lab_schema.sql` + `__lab_broken_rls_and_storage.sql`
- `fixed/`  — the same plus `__lab_fixes_rls_and_storage.sql`

```
pnpm dynamic-validate <variant> --execute --out <variant>-report
```

Each run: `supabase start` on an isolated project, replay that variant's migrations, create two auth
users, seed two tenants, run the live PostgREST cross-tenant matrix + the auth-attack and
session-lifecycle probes, write `M2.pass.json`, tear down.

### Result: M2 discriminates the pair correctly

| Finding | broken | fixed |
|---|---|---|
| `families` cross-tenant read — Tenant A | **High** | — |
| `families` cross-tenant read — Tenant B | **High** | — |
| `families` cross-tenant read — Admin | **High** | — |
| `profiles` read — anon (no token) | High | High |
| `profiles` read — Tenant A / B / Admin | High ×3 | High ×3 |
| auth/session Info rows (enumeration, login rate limit, refresh reuse, password-change survival) | 4 | 4 |
| total findings | 13 | 10 |

- **3 true positives that disappear when the fix is applied**, and **zero new findings on the fixed
  variant** — the FP trap is clean.
- The 4 `profiles` findings persist across BOTH variants and are **true positives in both**, because the
  lab's own fix never enables RLS on `profiles` (Step 1). They are not Harvey noise.

### What was NOT probed, and why

- `posts` and `family_members` were **skipped by the seeder** — their generic two-tenant INSERT violates
  `posts_family_id_fkey` / `family_members_family_id_fkey`, and #649's per-table SAVEPOINT recorded the
  skip rather than dropping the tables silently. So the planted `posts_select_leaky` and
  `family_members_select_all` policies were **not** exercised live. Two of the five planted bugs are
  therefore *labelled-and-unverified*, recorded here rather than counted as caught.
- The **storage** bugs (public bucket, missing `storage.objects` policies) were not probed at all —
  Harvey's M2 tier has no storage-object probe.
- Realtime channel authorisation and post-deletion data residue are disclosed as not-probed by the run
  itself.

## Step 3 — what the M1 STATIC tier does with the same pair

`pnpm quick-scan --dir <variant>` on both:

| | broken | fixed |
|---|---|---|
| Grade | **F (42/100)** | **F (42/100)** |
| Counted findings | 2 (1 Critical `profiles` RLS-never-enabled, 1 Medium no-lockfile) | identical |
| Indicators | 3 (tenancy-model assumed; `USING (true)` left unassessed; SECURITY DEFINER caller review) | identical |

**The static mechanical tier cannot tell the broken lab from its fix. The output is byte-identical.**
Two separate causes, both real:

1. **The planted class is disclosed, not detected.** The three `USING (true)` SELECT policies produce
   the Info indicator *"USING (true) policies left unassessed — no recognised tenant key to judge them
   against"* rather than a finding, because `family_id`/`owner_user_id` are not in the recognised
   tenant-key list. This is the fail-loud design working (silence would be worse), but it means the
   headline planted bug is not caught at this tier.
2. **Migrations are read cumulatively with no `drop policy` tracking** (already documented at
   `src/scan/supabase-static.ts:583`). The fixed variant's text still *contains* the broken policies, so
   the static reviewer sees them there too. This is the more dangerous half: had the `USING (true)`
   check been a finding rather than a disclosure, the fixed variant would have been a **false
   positive**, and the paired target would have caught that.

### Consequence for `validate-precision.ts`

#895 proposed feeding the fixed variant in as M1 negatives. **That is not yet possible, for two reasons,
and both are recorded rather than worked around:**

- The licence forbids distilling this source into a `*.entries.ts`, which is the only shape
  `validate-precision`'s corpus takes.
- More fundamentally, the fixed variant is **not currently distinguishable from the broken one at the
  static tier**, so as an M1 negative it would assert nothing. It becomes a usable negative the moment
  `drop policy` tracking lands — and at that point it is exactly the right regression test for it.

## What is now pinned

`supabase-security-labs` is a `CorpusTarget` in `src/scan/external-corpus.ts` with source-tier baselines
measured over the repo root; `pnpm corpus-drift --target supabase-security-labs --install` scores
**10/10 green**. Those numbers are near-floor by construction (the repo is prose plus small SQL/Deno
artefacts) — the target earns its place on the paired M1/M2 result above, not on them.
