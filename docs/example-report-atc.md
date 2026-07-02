# Codebase Security & Health Audit — {Client} *(worked example: ATC self-audit)*

> **Template + worked example.** This is the report we hand clients, populated with the ATC self-audit so the
> format is concrete. Replace the findings per engagement; keep the structure, the BFTB scoring, and the
> Action Plan. Generated 2026-06-27.

**Engagement:** point-in-time advisory review of the named repository at the reviewed commit. **Not** a guarantee
of completeness; **not** a substitute for a full penetration test. **Liability capped at fees paid.** Dynamic
checks were run only against an authorized local instance.

---

## 1. Executive summary

**Posture: healthy, with no critical exposure.** The headline question for a multi-tenant SaaS — *can one tenant
reach another tenant's data?* — is **No**: tenant isolation holds (two-layer RLS + app filters; no permissive
`USING (true)` / `auth.role()='authenticated'` policies; no service-role key reachable from the client). The
findings are hardening, performance, and test-quality improvements, not active vulnerabilities.

- **Overall codebase health: 6.3 / 10** (vitals; 914 files, 987 commits).
- **Critical security: 0.   High security: 0.**  Medium: 2.  Low/hardening: 4.  Perf: 4.  Test/maintainability: 5.
- Biggest *latent* risk is concentration, not exposure: `app/api/chat/route.ts` is the #1 hotspot (health 2.4,
  41 changes, co-changes with 29 files) — a future-bug magnet worth decomposing.

## 1.5 Bang-for-the-buck (BFTB) scoring

Each finding is scored **1–100** = round( **Value × Ease × Safety ÷ 125 × 100** ), each axis 1–5:
**Value** (5 = prevents breach/loss/outage or big cost) · **Ease** (5 = one-line/one-toggle) · **Safety**
(5 = additive, can't break anything). So (5,5,5)=100; (1,1,1)≈1. Do the high scores first.

## 1.6 Top bang-for-the-buck

| Rank | Finding | V | E | S | **BFTB** | Severity |
|------|---------|:-:|:-:|:-:|:--------:|----------|
| 1 | **Add commission state-machine test** (Stryker survived mutant on money logic) | 4 | 5 | 5 | **80** | Test · Med |
| 1 | ✅ *Covering indexes for 124 unindexed FKs* — **completed this period** | 4 | 5 | 5 | **80** | Perf |
| 3 | ✅ *Wrap `auth.*` in RLS init-plan (50 policies)* — **completed this period** | 4 | 4 | 4 | **51** | Perf |
| 4 | Parallelize 8 fetch waterfalls (`Promise.all`) | 3 | 4 | 4 | **38** | Perf · Low |
| 5 | Add `server-only` to the 4 core secret/service-role clients | 2 | 5 | 4 | **32** | Hardening · Low |

> **Note:** *Enable leaked-password protection* (which a checklist would score BFTB 80) is **excluded — N/A**:
> this app uses federated/OAuth auth exclusively, so there are no managed passwords. See "Checked & ruled out."

## 1.7 Action plan

**BFTB > 75, plus every Critical/High security finding.** → **No critical or high security issues were found**,
so the plan is the one open quick win (the FK-index 80-scorer shipped this period; the would-be leaked-password
80-scorer is N/A — see "Checked & ruled out"):

| Order | Action | Why it's here | BFTB | Effort | Owner |
|-------|--------|---------------|:----:|--------|-------|
| 1 | Add a test asserting `assertValidTransition` **rejects a from-state not in the map** (kills the survived mutant in the commission state machine) | BFTB 80; closes a test gap on **money** logic | 80 | 1 test | Eng |

> Completed during this engagement (pending prod apply): the 124 FK covering indexes and the 50-policy RLS
> init-plan wrap — both BFTB ≥ 51, both already merged.

---

## 2. Scope & methodology
Reviewed: RLS policies, service-role code paths, API routes, auth/permission layer, migrations, Next.js App
Router surface, and the test suite. Tooling: Supabase advisors (security + perf), the D-091 guard suite,
`vitals` (hotspots), `knip` (dead code), `jscpd` (duplication), **Stryker** (mutation testing), and the M9
static detectors (`server-only`, fetch-waterfalls, dynamic-rendering, client-data-leak). Out of scope:
infrastructure, dependencies, social engineering.

## 3. Findings

### Security
- **F-02 — 3 `SECURITY DEFINER` RLS helpers are RPC-callable by `authenticated`.** Sev **Medium** · **BFTB 10**
  (3×2×2). `auth_user_in_tenant`, `tenant_is_active`, `auth_user_can_access_conversation` are directly callable at
  `/rest/v1/rpc/...`. Mostly caller-scoped (low impact); `tenant_is_active` leaks tenant active-status for arbitrary
  IDs. *Fix:* `REVOKE EXECUTE` from `authenticated` — **but test first**: policies call these, so revoking may break
  RLS for signed-in users (this is *why* the BFTB is low — risky + needs careful testing).
- **F-03 — 13 tables RLS-enabled with no policy.** Sev **Info** · **BFTB 16**. Mostly safe-by-design deny-all
  (service-role-only). *Action:* confirm `tier_definitions` / `stripe_price_map` / `pricing_*` are intended to be
  unreadable by `authenticated`.

### Performance
- **F-04 — 124 unindexed foreign keys.** Sev Perf · **BFTB 80** (4×5×5). ✅ **Fixed this period** (additive covering-index migration; pending prod apply).
- **F-05 — 50 RLS policies re-evaluate `auth.*` per row** (`auth_rls_initplan`). Sev Perf · **BFTB 51**. ✅ **Fixed this period** (wrapped in `(select …)`; zero semantic drift verified).
- **F-06 — 8 fetch waterfalls.** Sev Low · **BFTB 38** (3×4×4). Independent sequential `await`s in server
  components → serialized round-trips. *Fix:* `Promise.all` / single query (confirm independence first).
- **F-07 — 86 unused indexes.** Sev Low · **BFTB 10** (2×2×3). Write/storage overhead. *Fix:* `DROP INDEX
  CONCURRENTLY` after per-index review (risk: dropping a rarely-used-but-needed index).
- **F-08 — 27 pages opt into dynamic rendering.** Sev Low · **BFTB 19**. `searchParams`/`headers()`/`cookies()`
  high in the tree → per-request SSR. Mostly intended (authed pages); confirm none are needlessly dynamic.

### Test quality (Stryker)
- **F-09 — Survived mutant in the commission state machine.** Sev Medium · **BFTB 80** (4×5×5). Removing the `?.`
  in `ALLOWED_TRANSITIONS[from]?.has(to)` did **not** fail any test — the suite never asserts the
  invalid-`from`-state path on money-critical logic. *Fix:* one test case. *(Whole-repo Stryker run recommended
  to complete this module — it was sampled here.)*

### Maintainability
- **F-10 — `server-only` poison-pill absent (43 lib modules).** Sev Low/hardening · **BFTB 32** (2×5×4).
  Currently safe (none are client-imported), but no compile-time guard. *Fix:* add `import 'server-only'` to the 4
  core clients (`service-role-client`, `platform-admin-client`, `tenant-client`, `env`) — transitively covers most.
  *(Requires adding the `server-only` dependency.)*
- **F-11 — 62 unused exports + 75 unused exported types** (knip). Sev Low · **BFTB 14**. Dead surface area;
  review (some may be public API / dynamically used) then prune.
- **F-12 — 4.4% duplicated lines / 465 clones** (jscpd). Sev Low · **BFTB 5** (2×1×3). Maintenance tax;
  consolidate opportunistically — full dedup is multi-week (hence the low BFTB).
- **F-13 — `app/api/chat/route.ts` is the #1 hotspot** (health 2.4, 29 co-changes). Sev — · **BFTB 4** (5×1×1).
  **High value, low BFTB**: decomposing a central, highly-coupled file is high-impact but slow and risky. Schedule
  deliberately, not as a quick win.

### Checked & ruled out (applicability gate)
- **F-01 — Leaked-password protection disabled.** **N/A** (confidence: N/A). A checklist/advisor would score this
  BFTB 80 and put it top of the action plan — but the app uses **federated/OAuth auth exclusively**, so there are
  no Supabase-managed passwords and nothing for the feature to protect. Captured at kickoff via the auth
  questionnaire; shown here for transparency, excluded from findings/action-plan. *(This is the "context-blind
  false positive" class the methodology guards against — correct detection, zero relevance.)*

## 4. Remediation plan
Do the **Action Plan (§1.7)** first (the two BFTB-80 quick wins). Then the BFTB 30–55 band (waterfalls,
`server-only`, the completed perf items' prod apply). Treat F-13 (chat-route decomposition) as a planned
refactor, not a quick win. F-02 (SECURITY DEFINER) only with an RLS regression test.

## 5. Retest & ongoing coverage
Free retest of the Action-Plan items within 14 days. Recurring options: per-release re-scan, or continuous
PR-level coverage (the niche bot). Re-running `vitals` next quarter surfaces **trends** (what's degrading) — the
most actionable signal once there's a baseline.
