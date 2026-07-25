# Harvey recall measurement — yoanbernabeu/SupatestVibeDemo

**Date:** 2026-07-18
**Target:** `yoanbernabeu/SupatestVibeDemo` ("VulnBlog"), a deliberately-vulnerable
**Supabase-native Vite/React SPA** built as the practice target for the
`supabase-pentest-skills` project. Cloned to `/private/tmp` (ephemeral, deleted after).
**Answer key:** the repo's `README.md` enumerates exactly **9 planted flaws** (three levels),
and the authoritative mechanism-for-mechanism key is
`supabase/migrations/20250201000000_initial_vulnblog.sql` (the RLS/policy/RPC definitions) plus
the four client components. The migration's own header brags the whole point:
*"✅ Linter Supabase = AUCUN WARNING … ❌ Réalité = Failles critiques cachées par des tautologies
logiques"* — i.e. the app is specifically engineered so the **mechanical linter tier sees nothing**;
the flaws are disguised `USING(true)` tautologies and per-user `USING(true)` reads.

This is a MEASUREMENT — every caught / missed below is grounded in an actual Harvey run's output
observed on this date, not recall. No Harvey source was changed. All three tiers were run:
mechanical, semantic (LLM), and dynamic (M2 autonomous stand-up).

## How Harvey was run

- **Mechanical (M1 static + M6/M7/M9 + M10):**
  - `pnpm quick-scan --dir <t> --tenant-mode per-user --findings-out <f>` — 37 raw findings
    (VulnBlog is a **per-user** app, not org-multi-tenant, so `--tenant-mode per-user` is the
    correct model for the static RLS pass).
  - `pnpm detect-static <t>` — Vite-aware; 9 findings across M7/M9 (correctly reports
    "M9 App Router checks N/A — SPA, no SSR").
  - `pnpm pii-classify --schema <t>/supabase/migrations` — M10 data classification.
  - The static RLS/policy pass (the permissive-`USING(true)` review inside quick-scan) reads
    `supabase/migrations/*.sql`. There is **no `supabase/config.toml`** in the repo, so the
    static open-signup / password / realtime config checks (#588 and the connected-tier
    `supabase-config` checks) have nothing to read — recorded as requires-live-run, not a skip.
- **Semantic (LLM):** manual security review of the four components + the migration SQL, guided by
  `briefs/scan-extras.txt`, triaged against `briefs/fp-rules.txt`.
- **Dynamic (M2):** `pnpm dynamic-validate <t> --execute --out <dir>` — the autonomous live
  pipeline (`supabase start` → apply the client migration → seed two auth users → live PostgREST
  cross-principal matrix). Self-isolated per #604 (`project-id harvey-dv-3569abe86e`, DB ports
  57691/57692); teardown scoped to that project only. No foreign Supabase volumes touched.

## The answer key (9 planted flaws)

Reconstructed from `README.md` (§Failles Volontaires) + the migration + component source.
`migration` = `supabase/migrations/20250201000000_initial_vulnblog.sql`.

| # | id | Flaw | Class | Location (file:line) |
|---|----|------|-------|----------------------|
| 1 | F1-ARTICLE-UPDATE | UPDATE articles sans auth | Broken RLS via **tautology** `USING (author_id IS NOT NULL OR author_id IS NULL)` (= always true) → anon/any user rewrites any article (defacement) | `migration:76-78` |
| 2 | F2-ARTICLE-DELETE | DELETE articles sans auth | Same tautology on DELETE → any user destroys any article | `migration:81-83` |
| 3 | F3-ARTICLE-DRAFT-READ | Lecture articles non publiés | `articles` SELECT `USING (true)` → anon reads unpublished drafts (the app gates drafts only client-side with `.eq('published', true)`) | `migration:68-69` |
| 4 | F4-PUBLIC-BUCKET | Bucket avatars public | App uploads to a **public** `avatars` storage bucket and stores `getPublicUrl` → uploaded files world-readable (bucket flag lives in project storage config) | `src/components/Profile.tsx:68-80` |
| 5 | F5-USER-ENUM | Énumération d'utilisateurs | `get_user_by_email(user_email)` **SECURITY DEFINER** RPC returns id/username/email for ANY email with no caller check; reinforced by differential login-vs-signup error messages | `migration:90-101` (+ `src/components/Auth.tsx:58-60`) |
| 6 | F6-REALTIME-UNAUTH | Realtime non authentifié | `ArticleList` subscribes to `postgres_changes` on `articles` with the anon client; because `articles` SELECT is `USING(true)`, Realtime authorization (RLS-backed) lets any anon holding the anon key stream every live change | `src/components/ArticleList.tsx:18-28` (+ migration SELECT `true`) |
| 7 | F7-WEAK-PASSWORD | Mots de passe faibles | Email/password auth with a weak password policy (client `minLength=6`, no complexity; leaked-password/HIBP protection off) — policy lives in project Auth config | `src/components/Auth.tsx:34,127` (+ project Auth config) |
| 8 | F8-OPEN-SIGNUP | Signup ouvert | Open self-service signup with auto-confirm ("Vous pouvez maintenant vous connecter" immediately) → account in ~10s — setting lives in project Auth config | `src/components/Auth.tsx:34-55` (+ project Auth config) |
| 9 | F9-PROFILES-BREACH | Policies profiles permissives | `profiles` SELECT `USING (true)` exposes **every user's email**; plus tautology UPDATE/DELETE lets anyone modify/delete any profile → full data breach | `migration:43-45` (+ `53-55`, `58-60`) |

## Score

**Tally: 9 caught / 9 (100%) — but entirely by the SEMANTIC tier.**

| Tier | Caught (of 9) | Notes |
|------|---------------|-------|
| **Mechanical** (`quick-scan --tenant-mode per-user` + `detect-static` + `pii-classify --schema`) | **0 asserted findings** | Honestly *discloses* F3/F9's `USING(true)` as an unassessed indicator (`SB-RLS-TENANCY-MODEL`), *corroborates* F9's PII sensitivity via M10, and flags an adjacent upload-limit issue near F4. Asserts none of the 9 — the target was engineered to produce exactly this against a linter. |
| **Semantic (LLM)** (manual review of source + migration, triaged vs `fp-rules.txt`) | **9 / 9** | Catches every flaw, incl. the tautology-disguised policies, the SECURITY DEFINER RPC, the public bucket, and the two Auth-config flaws (flagged as config-to-verify). |
| **Dynamic (M2)** (`dynamic-validate --execute`, autonomous stand-up) | **0 proven live** | **Ran** (Supabase started, migration applied, two auth users seeded), **PostgREST-only coverage, 0 findings** — three loud, in-output limitations, no silent skip. Could not prove the bad-RLS flaws because the generic seed found **0 scoped tables** (`articles.author_id` isn't in the recognized owner-column set), so the cross-principal matrix had nothing to leak. `M2.pass.json` written. |
| **Union (caught if any tier caught it)** | **9 / 9** | |

**Dynamic run detail (grounded).** `verdict: GO (full)`; isolated `project-id harvey-dv-3569abe86e`
(DB ports 57691/57692, #604 scoped teardown). The pass artifact records
`"dynamic validation (postgrest-only coverage); 0 finding(s)"` with limitations:
(1) `profiles` links to `auth.users` but was not seeded; (2) **no scoped tables found** — the seed
creates no cross-principal rows, so isolation probes have nothing to leak (the `author_id` gap,
#617); (3) the app failed to become reachable at `127.0.0.1:3000` → degraded to PostgREST-only.
The `:3000` failure was a **foreign** process already holding the port (this Vite SPA has no `start`
script, so the Tier-2 app tier fell back to `npx next start`, which never bound; the health-poll then
hung on the stranger's server — hardening noted on #617). **The intended M2 surface here is Tier-1
(the PostgREST RLS matrix), and it ran** — it simply had nothing seeded to leak. So dynamic is an
**honest partial**: it proved stand-up-ability but not the flaws, and said so loudly.

**Where each tier carried its share.** Dynamic *would* be the natural prover of F1/F2/F3/F9 (bad RLS
is its whole point) but was blocked by the seeding gap (#617); on this engagement the **semantic
tier carries every flaw**, including the config/logic ones (F4 bucket, F5 SECURITY DEFINER, F6
realtime, F7 password, F8 signup) that have no source-tier or no-client-DB mechanical detector.


### Per-flaw results

| # | Mechanical | Semantic (LLM) | Dynamic (M2) | Overall |
|---|-----------|----------------|--------------|---------|
| F1 UPDATE tautology | **miss** — `CLAUSE_TRUE` only matches literal `true`; the `(x IS NOT NULL OR x IS NULL)` tautology is not normalized (gap A) | **CAUGHT** — always-true predicate, no owner check |not proven — 0 scoped rows seeded (#617)| **caught (semantic)** |
| F2 DELETE tautology | **miss** — same as F1 | **CAUGHT** |not proven — 0 scoped rows seeded (#617)| **caught (semantic)** |
| F3 draft read `USING(true)` | **partial** — disclosed as `SB-RLS-TENANCY-MODEL` "USING(true) left unassessed, no tenant key" indicator; spared as a finding by the per-user precision rule (`checkUsingTrueReview` returns null on a table with no recognized scope key) | **CAUGHT** — anon reads `published=false` rows directly |not proven — 0 scoped rows seeded (#617)| **caught (semantic); disclosed (mechanical)** |
| F4 public bucket | **miss** — public-bucket detector (`checkPublicBucketsWithNoPolicies`) is connected/live-storage tier; `from('avatars')`+`getPublicUrl` not modeled statically. Adjacent `AUTH-upload-no-limit` (upload with no size/MIME cap) fired on the same file — different class | **CAUGHT** — public bucket + world-readable object authz |n/a — not a cross-tenant table probe| **caught (semantic)** |
| F5 user enumeration | **miss** — SECURITY DEFINER classifier needs a live DB query (argNames/exposedTo/body); not run without a client DB. Differential auth errors not statically modeled | **CAUGHT** — unrestricted SECURITY DEFINER RPC + oracle |n/a — not a cross-tenant table probe| **caught (semantic)** |
| F6 realtime unauth | **miss** — `checkRealtimeAuthorization` is connected/live tier; no config.toml to read | **CAUGHT** — anon realtime subscription + `USING(true)` SELECT |n/a — not a cross-tenant table probe| **caught (semantic)** |
| F7 weak password | **N/A static** — `password_hibp_enabled` is a live Auth-config check; no config.toml → requires-live-run | **CAUGHT (config-to-verify)** — email/password auth enabled ⇒ rule applies; flag HIBP/min-length for dashboard confirmation |n/a — not a cross-tenant table probe| **caught (semantic)** |
| F8 open signup | **N/A static** — `mailer_autoconfirm` / open-signup is a live Auth-config check (#588 reads config.toml, absent) → requires-live-run | **CAUGHT (config-to-verify)** — self-service signup + auto-confirm |n/a — not a cross-tenant table probe| **caught (semantic)** |
| F9 profiles breach | **partial** — SELECT `USING(true)` disclosed via the same tenancy-model indicator; tautology UPDATE/DELETE missed (gap A). **M10 `pii-classify` corroborates** the sensitivity: `profiles → Medium (1.9): USERNAME_HANDLE, EMAIL, PHOTO` | **CAUGHT** — every email exposed + anyone edits/deletes any profile |not proven — 0 scoped rows seeded (#617)| **caught (semantic); disclosed + M10-corroborated (mechanical)** |

## Why the mechanical tier is nearly blind here — by design, on both sides

VulnBlog is **purpose-built to defeat the linter tier** (its migration header says so). Two of
Harvey's deliberate precision tradeoffs line up exactly with the two evasion techniques:

1. **Tautology `USING(true)` (F1/F2/F9 writes).** The permissive-policy pass normalizes only a
   literal `(true)` clause (`CLAUSE_TRUE = /^\s*\(*\s*true\s*\)*\s*$/i`, `src/rls-policy-review.ts:36`).
   The plant `(author_id IS NOT NULL OR author_id IS NULL)` is logically `true` but textually
   isn't — so it is not flagged. **Mechanizable (gap A).**
2. **Per-user `USING(true)` reads (F3/F9 SELECT).** `checkUsingTrueReview` deliberately **spares**
   `USING(true)` on a table with no recognized tenant/scope key (`src/rls-policy-review.ts:110`) to
   avoid training users to ignore findings on legitimately world-readable catalogs — and instead
   **discloses** the spared policies via the `SB-RLS-TENANCY-MODEL` indicator ("USING(true) left
   unassessed"). That is the correct precision call in the general case, but on a per-user PII table
   like `profiles` the `USING(true)` SELECT is a genuine email breach. The disclosure is honest
   (no silent skip) but it is not an asserted finding.

The remaining flaws (F4 bucket, F5 SECURITY DEFINER, F6 realtime, F7 password, F8 signup) all live
in the **connected/live tier or the project dashboard**, not in source, so no client DB + no
config.toml ⇒ mechanically requires-live-run. The **semantic tier is what carries all of them** on
this engagement.

## Harvey findings NOT in the answer key (mechanical)

All legitimate, just outside the planted-9 set — no false positives against the app's real behavior:
- 24× known-vulnerable dependency (OSV: vite, esbuild, postcss, react-router, ws, minimatch, …) —
  real CVEs, mostly dev-tier.
- 5× GitHub Actions mutable-action-tag (`.github/workflows/deploy.yml`).
- `AUTH-upload-no-limit` — avatar upload with no size/MIME cap (`Profile.tsx`), adjacent to F4.
- 2× `SB-RLS-INITPLAN` (M7 perf) — `auth.*` re-evaluated per row in the two INSERT policies.
- `SUP-UNPINNED` (18 unpinned deps); `SEC-BUNDLE-00` (bundle secret scan not run — no `dist/` at
  scan time, disclosed not skipped).
- `detect-static`: M7 raw `<img>`, missing hook deps, state sprawl, non-code-split route; M9 N/A (SPA).

## Mechanizable gaps → filed as follow-ups

- **jharvieux/Harvey#616** (M1, mechanical) — **gap A: always-true RLS tautologies.** The
  permissive-policy pass (`CLAUSE_TRUE`, `src/rls-policy-review.ts:36`) normalizes only a literal
  `(true)`; the plant `(author_id IS NOT NULL OR author_id IS NULL)` is logically true but textually
  isn't, so F1/F2 and F9's tautology UPDATE/DELETE go unflagged mechanically. Fix: recognize the
  canonical `(col IS NOT NULL OR col IS NULL)` tautology before the existing checks run.
- **jharvieux/Harvey#617** (M2, dynamic) — **gap B: `author_id` not recognized as a per-user scope
  column.** The two-tenant seed (`USER_SCOPE_COL = /^(owner_id|user_id)$/i`,
  `src/pentest/two-tenant-seed.ts:27`) doesn't match `articles.author_id`, so the live matrix seeds
  0 scoped rows and has nothing to leak — the successor to the now-closed #571. Fix: infer per-user
  ownership from a FK to `auth.users`/the principal table, not a fixed name list.

Not separately filed: F4 (public-bucket) and F5 (SECURITY DEFINER) are already known
connected/live-tier-only gaps (they need a client DB; seen on the vandyand/superredhat scores);
F7/F8 (Auth-config) require the project dashboard, which no repo artifact carries.

## Comparison to the other measurements

`vandyand` (org-tenant + Supabase-Auth) scored 6/8 mechanically-strong with dynamic proving 2 live;
`superredhat` (per-user + custom-auth App Router) needed the semantic tier to reach 12/12.
**VulnBlog is the extreme case of the same axis:** a per-user, Supabase-native **Vite SPA** whose
flaws are (a) tautology-disguised RLS, (b) per-user `USING(true)`, and (c) project-dashboard config.
The mechanical tier asserts **0 of 9** as findings (it honestly *discloses* F3/F9's `USING(true)` and
*corroborates* F9 via M10, and flags an adjacent upload-limit issue near F4) — exactly the outcome
the target was engineered to produce against a linter. **The semantic (LLM) tier catches all 9.**
The result is a clean illustration that Harvey's precision-tuned mechanical layer is not a
substitute for the paid semantic review on adversarially-crafted targets — and that two specific,
cheap mechanizations (tautology normalization; `author_id` owner-column recognition) would move
concrete flaws back into the free/dynamic tiers.
