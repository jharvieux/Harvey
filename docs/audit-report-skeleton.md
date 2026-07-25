# Audit report skeleton (deliverable template)

> The product is the report. Ranked by **blast radius**, not by file. Each finding is reproducible,
> mapped to the D-091 taxonomy, and paired with a concrete fix. Keep the language plain enough for a
> founder to forward to a non-technical buyer's procurement team.

---

## 0. Cover & engagement terms

- Client, scope (repos/branches/commit SHA reviewed), dates, auditor.
- **Liability language (required):** point-in-time advisory; not a guarantee of completeness; not a
  substitute for a full penetration test; liability capped at fees paid. _(LLC + this paragraph = bounded risk.)_

## 1. Executive summary (1 page — the part the buyer reads)

- One-paragraph posture statement in plain English.
- Findings count by severity: **Critical / High / Medium / Low**.
- The single most important sentence: *can one tenant reach another tenant's data, yes/no, and how.*
- Severity table:

  | # | Title | Severity | Blast radius | Status |
  |---|-------|----------|--------------|--------|
  | 1 | Cross-tenant read via permissive RLS | Critical | All tenants' rows | Open |

## 1.5 Bang-for-the-buck (BFTB) scoring

Every finding gets a **BFTB score (1–100)** so the client knows what to do *first*. Three 1–5 axes:

- **Value** — 5 = prevents a breach / data loss / outage or large cost saving; 3 = real improvement to important code; 1 = cosmetic.
- **Ease** — 5 = one-line / one-config / one-toggle; 3 = ~a day; 1 = multi-week.
- **Safety** — 5 = additive, no logic change (can't break anything); 3 = touches shared code; 1 = central refactor, wide blast radius.

> **BFTB = round( Value × Ease × Safety ÷ 125 × 100 )** — so (5,5,5) = **100** (high value, one-line, zero risk) and (1,1,1) ≈ **1** (low value, multi-week, fragile).

## 1.6 Top bang-for-the-buck (do these first)

The highest-scoring findings — quick, safe, high-impact. Ranked table:

| Rank | Finding | Value | Ease | Safety | **BFTB** | Severity |
|------|---------|:----:|:----:|:------:|:--------:|----------|

## 1.7 Action plan

**Everything that is BFTB > 75, PLUS every Critical or High security finding regardless of BFTB** (security gets
fixed even when it's expensive). Ordered: critical/high security first, then by BFTB descending.

| Order | Action | Why it's here | BFTB | Effort | Owner |
|-------|--------|---------------|:----:|--------|-------|

> If there are no Critical/High security findings, **say so explicitly** — "no critical or high security issues
> found" is a headline result the buyer wants to hear, not an empty section.

## 2. Scope & methodology

- What was reviewed (auth flow, RLS policies, service-role code paths, webhooks, API routes, migrations).
- How: manual code review of tenant-isolation logic + the D-091 taxonomy pass + targeted dynamic checks.
- Explicitly state what was **not** in scope (infra, dependencies, social engineering, etc.).

## 3. Findings (ranked by blast radius)

Order strictly by severity. For each finding use this block:

> ### F-01 — {Title}
> - **Severity:** Critical | High | Medium | Low
> - **Confidence:** Confirmed (repro'd) | Likely (needs one check) | Review (heuristic/candidate) | N/A (ruled out by context)
> - **BFTB:** {score}/100  (Value {1-5} × Ease {1-5} × Safety {1-5})
> - **Taxonomy:** {D-091 pattern, e.g. "Two-layer tenant isolation" / "Service-role leakage"}
> - **Location:** `path/to/file.ts:LINE` (+ the policy/route/migration name)
> - **What it is:** plain-English description of the flaw.
> - **Blast radius:** what an attacker reaches (e.g. "every tenant's `bookings` rows with the public anon key").
> - **Evidence / repro:** the minimal query, request, or policy that demonstrates it (sanitized).
> - **Fix:** the concrete change (e.g. add a `tenant_id` predicate; move to `(select auth.uid())`; add a replay guard).
> - **OK when / Not OK when:** *(for any finding that is safe-or-not depending on design)* — be upfront about the
>   uncertainty and give the client the decision criteria, e.g. *"✓ OK when the table is service-role-only (deny-all);
>   ✗ Not OK when a user feature must read it."* Never assert a context-dependent finding; never silently drop it.
> - **References:** OWASP/CWE + any framework doc.

### Severity rubric (map your taxonomy to it)

| Severity | Definition | Your taxonomy examples |
|---|---|---|
| **Critical** | Cross-tenant data exposure or full DB access | Missing/permissive RLS (`auth.role()='authenticated'`), service-role credential leakage, anon key as master key |
| **High** | Auth bypass, privilege escalation, replayable state change | Per-route permission gap, webhook with no replay protection, fail-open enforcement, single-layer tenant isolation |
| **Medium** | Exploitable under conditions / integrity loss | Idempotency-after-dispatch ordering, read-modify-write counter races, CAS without row-count check, SSRF via unvalidated URL field |
| **Low** | Hardening / defense-in-depth | Missing rate-limit store, error-message schema disclosure, missing input bound |

## 3b. Codebase-health findings (the full-audit modules)

The security findings above (M1/M2) are the headline. These modules make it a *full* audit — lead the pitch
with security, but this is what justifies the bigger package. See `briefs/audit-modules.md` for method per module.

### Hotspots (M3)
Files that are **both** high-churn and high-complexity — where bugs and maintenance cost concentrate. Cross-
reference against findings (a hotspot that's also a security finding = top priority).

| File | Churn (commits/Δlines) | Complexity | Overlapping findings | Priority |
|---|---|---|---|---|

### Duplication (M4)
Overall % duplication + the worst clone clusters, each with a consolidation suggestion (fix-once vs. fix-in-N-places risk).

### Slop / dead code (M5)
Grouped delete / inline / simplify list (narrating comments, single-use helpers, dead exports, stub-shaped code,
orphan TODOs) with an estimated net line reduction.

### Simplification / reuse / maintainability (M6)
Each hand-rolled-or-over-abstracted item → the concrete replacement (stdlib/framework primitive, existing dep,
or "collapse to inline") → the maintenance/onboarding cost it removes. The "lower your ongoing support burden" pitch.

### Performance (M7)
Findings by impact: N+1 / unindexed queries (DB advisor), missing/unused indexes, RLS policies re-evaluated per
row (`auth.*` not wrapped), over-fetching / missing pagination, bundle weight, missing caching, Core Web Vitals.

| Finding | Layer (DB/API/render/bundle) | Impact | Fix | Effort |
|---|---|---|---|---|

> Anchor example for the DB layer (from a real engagement): unindexed foreign keys → covering indexes; bare
> `auth.uid()` in RLS → `(select auth.uid())` to hoist to a once-per-query initplan. Both surfaced by the
> Supabase performance advisor and verified against a test DB.

### Test quality & intent (M8)
Mutation testing (StrykerJS) + tests-for-intent review. The headline: *your coverage number is lying to you, here's where.*

- **Mutation score** overall and per module (whole repo). Note the
  gap vs. line coverage (high coverage + low mutation score = false confidence).
- **Tests that can't fail** — the dangerous ones: a test whose covered behavior could break and it would still pass
  (e.g. a tenant-isolation test that passes even with the RLS policy removed). List location + what it fails to assert.
- **Surviving mutants on a hotspot/finding** — cross-reference M1/M3: an untested mutant on a security-critical or
  high-churn path is a top remediation priority.

| Module / file | Line cov | Mutation score | Surviving mutants (critical) | Action |
|---|---|---|---|---|

## 3c. Checked & ruled out (applicability gate)

Items a generic checklist/advisor would flag, **suppressed because they don't apply to this app's auth model or
architecture** (the *applicability* gate, distinct from the *correctness* gate). Listing them is a credibility
signal — it shows what was checked and *why it's not a finding* — and it stops context-blind false positives from
reaching the action plan.

> Example: *Leaked-password protection disabled* — **N/A**: this app uses federated/OAuth auth exclusively, so
> there are no managed passwords to protect. Captured at kickoff via the auth questionnaire.

## 4. Remediation plan

- Prioritized fix order across **all** modules (Critical security → high-impact perf → hotspot overlaps → maintainability), with rough effort per item.
- "Fix these 3 before your next enterprise demo" callout — the action the buyer actually needs.

## 5. Retest & ongoing coverage (the upsell)

- Offer: free/discounted **retest** of Critical/High fixes within N days (closes the loop, builds trust).
- Recurring options: per-release re-audit, or continuous PR-level coverage (the niche bot) — land-and-expand
  into the relationship the one-time audit opens.

## 6. Appendix

- Full file/route/policy inventory reviewed.
- Taxonomy reference (the generalized D-091 catalog) so the client sees the rigor behind the pass.

---

### Notes for running the audit

- Lead every engagement by answering the cross-tenant question first — it's the headline risk and the buyer's
  real fear. Everything else is supporting cast.
- Keep findings reproducible. A finding the client can't reproduce is a finding they won't pay attention to —
  and it's how you'd lose a dispute.
- The harness (D-091 guards + review agents) does the finding; your value is the verification, the ranking, and
  the plain-English translation a founder can act on.
