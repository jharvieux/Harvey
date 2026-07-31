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

   Cause 1 is the durable, still-standing half of the byte-identical result (cause 2 is CLOSED by #937
   below); recorded per #1072 with the live-tier falsifier that would retire it:

   > REASON: at the M1 STATIC (mechanical) tier, quick-scan cannot distinguish the broken supabase-security-labs lab from its fix on the planted RLS class — the USING(true) SELECT bug is disclosed as an Info indicator, not detected as a counted finding, because family_id/owner_user_id are not in the recognised tenant-key list (cause 1); cause 2, cumulative-migration reading, is separately CLOSED by #937 below
   > KIND: empirical
   > PROVENANCE: MEASURED 2026-07-24 (the paired quick-scan in Step 3; TENANT_KEY_CANDIDATES in src/scan/supabase-static.ts re-read 2026-07-26 and still omits family_id/owner_user_id, so cause 1 holds — cause 2 was closed by #937 the same day, so the live divergence question is now purely cause 1)
   > FALSIFIER: pnpm quick-scan --dir <ssl-broken-variant> --findings-out /tmp/ssl-b.json && pnpm quick-scan --dir <ssl-fixed-variant> --findings-out /tmp/ssl-f.json && ! diff -q /tmp/ssl-b.json /tmp/ssl-f.json
   > FALSIFIER-TIER: supabase-labs
   > TOUCHES: src/scan/supabase-static.ts
2. **Migrations are read cumulatively with no `drop policy` tracking** (was documented in the
   `checkMigrationRlsInitplanStatic` header of `src/scan/supabase-static.ts`). The fixed variant's text
   still *contains* the broken policies, so the static reviewer sees them there too. This is the more
   dangerous half: had the `USING (true)` check been a finding rather than a disclosure, the fixed
   variant would have been a **false positive**, and the paired target would have caught that.
   **This cause is now CLOSED by #937 — see "Consequence for the M1 negative corpus" below.**

### Consequence for the M1 negative corpus — RESOLVED by #937/#938 (2026-07-24)

#895 proposed feeding the fixed variant in as an M1 negative. When this doc was first written that was
blocked on two things; both are now resolved, and the resolution is recorded here rather than in the
target's SQL.

**Cause 2 (drop-policy tracking) is closed by #937.** `parseLivePolicies` (`src/migration-sql-parse.ts`)
now reduces the migration set to the policies LIVE at the end of history — a `create policy` defines or
redefines an identity, a `drop policy` removes it, last event wins in file-then-position order — and
both `checkMigrationPolicySemantics` and `checkMigrationRlsInitplanStatic` judge that final state. The
byte-identical broken/fixed result above was **re-measured on 2026-07-24** on an original drop-and-replace
shape: before #937, broken and fixed produced identical semantic-review AND identical initplan output;
after #937 the fixed variant is clean and only the broken one is flagged. So a correctly-fixed client
schema is no longer reported for the bug it already fixed.

**The licence decision (cause 1) stands, and dictates the shape of the negative.** supabase-security-labs
is licence NONE; the corpus invariant in `src/scan/external-corpus.ts` already forbids vendoring it into
`targets/` or distilling it into a `*.entries.ts`. So the M1 negative is **an original re-expression of
the drop-and-replace SHAPE authored from scratch, not a copy** — `public.audit_events` with a
`using (true)` SELECT policy created in `20260724000001_rls_drop_policy_broken.sql` and dropped/replaced
by a tenant-scoped policy in `20260724000002_rls_drop_policy_fixed.sql`. It is wired in as the
`N-RLS-DROP-POLICY-FIXED` negative in `src/scan/calibration/rls-static-semantics.entries.ts`.

**Gate placement — a correction to #895's ask.** #895/#938 named `src/cli/validate-precision.ts`. That
gate's M1 side runs the **Prisma** tenant-scope detector over `src/detectors/__fixtures__/` dirs; a
Supabase-migrations RLS shape is not scored by it at all, so wiring the negative there would be a *false
green* (it would pass by never being looked at). The reviewer this negative actually exercises
(`checkMigrationPolicySemantics` / `checkMigrationRlsInitplanStatic`) runs inside `runMechanicalScan`,
which is scored by **`src/cli/validate-calibration.ts`** — so the negative lives in that M1 mechanical
corpus, where `pnpm exec tsx src/cli/validate-calibration.ts` scores it clean.

**What the corpus negative pins vs. what the unit tests pin.** `validate-calibration` only *fails* a
negative on a FREE-COUNT (high-tier) finding, and the static RLS review is review-tier — so the corpus
entry is the **forward-looking** guard: the day `USING(true)` on a tenant table graduates from a review
disclosure to a high-tier finding (the obvious next detector, and the exact scenario that made cause 2
dangerous), a resurrected dropped policy would fire and fail the gate. The **behavioral** regression —
that the dropped policy is not reported *even at review tier* — is pinned by the `drop/replace lifecycle
(#937)` block in `src/scan/supabase-static.test.ts` and the `parseLivePolicies (#937 …)` block in
`src/migration-sql-parse.test.ts`, both in `pnpm verify`.

**Still not covered (carried forward, not dropped):** the two planted bugs #895 could not seed live
(`posts_select_leaky`, `family_members_select_all` — the generic seeder cannot satisfy
`posts_family_id_fkey` / `family_members_family_id_fkey`) remain unexercised at the M2 tier.
#937/#938 close the M1-static half of the paired target. **The STORAGE half is now closed too — see
below.**

## Step 4 — the storage bugs, probed live on the paired target (#1274, 2026-07-31)

When this doc was written the storage bugs "were not probed at all — Harvey's M2 tier has no
storage-object probe." #956/PR #1004 then built one (`src/pentest/storage-probe.ts`), but its only
evidence was an in-process fixture whose bucket was *named* `family-media` with a hand-supplied
`public: true` — a test asserting a probe fires on a bucket the test itself marked public, which is
the self-confirming shape this repo refuses. #1274 is that gap; this is the live run that closes it.

Both variants rebuilt from the same pinned clone into scratch (never committed — licence NONE), and
run through Harvey's own autonomous stand-up:

```
pnpm dynamic-validate <variant> --execute --out <variant>-report
```

| | broken | fixed |
|---|---|---|
| `M2-STORAGE-PUBLIC-family-media` (Medium) | **fires** | — |
| `M2-STORAGE-SCOPE` verdict for `family-media` | `vulnerable` | `requires-live-run` (bucket empty) |
| total findings | 29 | 19 |

**The probe discriminates the pair.** The finding is derived from a REAL bucket listing — the
service-role oracle enumerating `/storage/v1/bucket` on the running stack — not from a fixture flag,
which is exactly what #1274 asked for. On the fixed variant (`update storage.buckets set public =
false where id = 'family-media'`) the public-bucket finding is absent, so the probe is not simply
always-firing.

Note what the fixed variant does NOT claim: its `M2-STORAGE-SCOPE` row reads `requires-live-run`,
because the oracle listed **0 objects**, which leaves the probe nothing to attempt a cross-tenant or
anon read against. The object-authorization half of the storage class therefore has no verdict on
the fixed variant, and the row says so instead of reporting zero findings. The in-process fixture
supplies its own bucket flag and object count, so it exercises a different branch. The
`storage.objects` per-object `metadata->>'user_id'` policies the fix adds therefore remain
unexercised: seeding real objects into the bucket is the follow-up.

## What is now pinned

`supabase-security-labs` is a `CorpusTarget` in `src/scan/external-corpus.ts` with source-tier baselines
measured over the repo root; `pnpm corpus-drift --target supabase-security-labs --install` scores
**10/10 green**. Those numbers are near-floor by construction (the repo is prose plus small SQL/Deno
artefacts) — the target earns its place on the paired M1/M2 result above, not on them.
