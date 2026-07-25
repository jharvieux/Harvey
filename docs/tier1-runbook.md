# Tier 1 runbook — delivering a client audit (M1 security)

> The repeatable scan → triage → report flow for a Tier-1 engagement: multi-tenant security (M1),
> powered by the `anthropics/defending-code-reference-harness` skills and the D-091 brief files
> (`briefs/scan-extras.txt`, `briefs/fp-rules.txt`). This is the low-marginal-cost delivery engine — the thing that
> makes the audit service repeatable instead of bespoke every time. Codebase-health modules (M4–M6)
> have their own runbook: `docs/m4-m6-quality.md`.

---

## 0. Before you start

- A **signed engagement** covering authorized-testing scope, data handling, and liability terms —
  no scan work starts without one (see `docs/audit-report-skeleton.md` §0).
- Confirm the D-091 brief files are current: `briefs/scan-extras.txt` (scan), `briefs/fp-rules.txt`
  (triage), `docs/audit-report-skeleton.md` (deliverable shape).

## 1. Runbook steps

1. **Verify the reference-harness skills are available** — `customize`, `vuln-scan`, `triage`,
   `threat-model`, `patch`. **Verified install path (2026-07-09):** in this environment they are
   *not* installed via the Claude Code plugin/marketplace system — they live as personal,
   user-scope skills at `~/.claude/skills/<name>/SKILL.md` (confirmed present: `customize`,
   `patch`, `quickstart`, `threat-model`, `triage`, `vuln-scan`, plus a shared `~/.claude/skills/_lib/`
   helper directory) and are invoked directly, e.g. `/threat-model bootstrap <repo>`. Before
   relying on them, confirm with `ls ~/.claude/skills/` (or the project's own `.claude/skills/`, if
   the operator's setup installs them per-project instead) — do not assume a specific install
   command works until you've checked. **Could not independently confirm** the origin repo name
   `anthropics/defending-code-reference-harness` from anything on disk in this environment (no
   plugin manifest, marketplace record, or in-repo URL references it) — the skill content matches
   that package's documented behavior (canary target, vuln-pipeline references in `quickstart`),
   but if that repo is the real upstream source, the actual install mechanism (clone + copy/symlink
   into `~/.claude/skills/` or a project's `.claude/skills/`) is unverified from this operator's
   seat. Flag this uncertainty to whoever set up the environment rather than asserting a specific
   install command.
   **Known operational gotcha:** the skills' own instructions invoke a checkpoint helper via the
   *relative* path `.claude/skills/_lib/checkpoint.py` (assuming a project-local install). In a
   user-scope install like this one, that path does not resolve from a repo's working directory —
   use the absolute path (`~/.claude/skills/_lib/checkpoint.py`) instead when running any of these
   skills' Bash checkpoint calls.
   Set the model tier for the pass: `export CLAUDE_CODE_SUBAGENT_MODEL=<model-id>` — see §6 for
   scan-vs-triage model choice (this env var's effect was not independently verified either — see
   `docs/runbooks/dry-run-calibration.md` §4).
2. **Obtain the client repo, read-only.** Confirm scope explicitly before touching code: which
   apps/directories are in scope, which branch, and the commit SHA under review — record all three
   in the report's §0 cover section. Read-only access only; never request write access for a static
   pass.
3. **`/threat-model bootstrap <repo>`** → establishes focus areas (tenancy model, auth provider,
   the surfaces that matter for *this* app) before the scan runs blind.
4. **`/vuln-scan <repo's source root> --extra briefs/scan-extras.txt`** → raw findings
   (`VULN-FINDINGS.{md,json}`). This is the high-recall pass — over-flagging here is fine and
   expected; triage is what fixes it. Use the app's actual source root, not literally `src` — plenty
   of real Pages Router apps (and this runbook's own calibration target) have no `src/` directory at
   all. Add `--no-score` on large scans to skip vuln-scan's own per-finding confidence pass if the
   candidate count is high (dozens+) and time-boxed; every finding still reaches `/triage`
   unfiltered either way. **Known blind spot, verified 2026-07-09:** `/vuln-scan`'s built-in review
   brief hardcodes "open redirect" into its own DO-NOT-REPORT list, independent of
   `briefs/scan-extras.txt` — an open-redirect bug will not surface from this stage even if a
   subagent's focus area covers the exact route, unless `briefs/scan-extras.txt` is changed to explicitly
   override that default (it currently does not).
5. **`/triage VULN-FINDINGS.json --fp-rules briefs/fp-rules.txt`** → verified, deduped, re-ranked
   findings. See §4 for the methodology this step runs. **Known blind spot, verified 2026-07-09:**
   `/triage`'s own built-in verifier exclusion list separately (and redundantly) classifies open
   redirect as a "low-impact nuisance" false positive, so even a finding that somehow survived step
   4 would very likely still be dropped here. If open-redirect coverage matters for an engagement,
   don't rely on this pipeline for it as shipped — flag it via the questionnaire (§3) or a manual
   check instead. Race-condition findings (lost-update/TOCTOU classes) are also borderline: the
   triage verifier has a built-in "theoretical-only race" exclusion rule, so a genuine
   concurrent-request bug needs a concrete "two ordinary requests race" story in the finding to
   survive — it did survive in the one live-verified case we have (a counter-increment race), but
   treat it as a class worth a manual second look, not an automatic catch.
6. **Map confirmed findings into `docs/audit-report-skeleton.md`**, ranked by blast radius.
   **Hand-verify every Critical/High before it ships** — the headline cross-tenant question
   ("can one tenant reach another tenant's data — yes/no, and how") must be answered with a repro,
   not an assertion.
7. **Deliver the report + remediation plan**, and offer the retest upsell (skeleton §5): a
   free/discounted retest of Critical/High fixes within N days.

## 2. Data-access methodology — no Supabase lock-in

The Supabase Security/Performance advisors are reproducible without the client's dashboard: they're
backed by **`splinter`** (https://github.com/supabase/splinter), a single open-source `splinter.sql`
file of SQL lint views. We don't need platform access to get advisor-equivalent findings.

**DB advisors** (RLS gaps, missing indexes, `SECURITY DEFINER` exposure, exposed `auth.users`,
multiple-permissive-policies, etc.): run `splinter.sql` + `index_advisor` + our own taxonomy queries
against one of three access tiers, ranked by trust/coverage tradeoff:

| Tier | Access | Trust ask | Coverage | Notes |
|---|---|---|---|---|
| 1 (recommended) | Read-only Postgres role on a non-prod clone / read-replica | Medium | Highest — read RLS policies, grants, definer function bodies directly | Turnkey `CREATE ROLE` SQL we provide; revoked after the engagement. **Same clone serves the M2 pen test** — one access grant covers both. |
| 2 | Client runs the SQL pack themselves, returns output | Lowest — zero credential sharing | Medium — only what the pack captures | Best when the client won't grant any DB access. |
| 3 | Read-only Supabase Management API token + project ref | Highest ask | Broadest — DB *and* config advisors via `get_advisors` | Use when the client is comfortable with platform-level access; covers the auth/platform-config items §3 can't detect from SQL. |

All three are gated by the signed engagement (authorized-testing only): read-only, scoped to a
clone where possible, time-boxed, revoked at engagement close.

## 3. Auth / platform-config questionnaire (upfront, at kickoff)

Some advisors are **Auth/platform config**, not derivable from DB SQL — `splinter` misses them
entirely. Cover these at kickoff with a short questionnaire, before the scan starts:

- Leaked-password protection (HaveIBeenPwned) enabled?
- MFA available and enforced for privileged/admin accounts?
- Minimum password length / strength requirements set?
- Email confirmation required before first access?
- Auth rate-limiting / CAPTCHA on sign-in & sign-up?
- Allowed redirect URLs locked down (no open redirect)?
- Session / JWT expiry sane; refresh-token rotation on?
- Service-role key server-only, rotated, never in the client bundle? (cross-check M9 `server-only`)
- RLS-enabled-by-default discipline on new tables?
- Custom SMTP configured (not the default shared sender)?

**Rule: any item the client hasn't done — or answers "I don't know" to — becomes a finding.**
"Don't know" is itself a finding: unverified security posture. Tag it taxonomy `Config`, severity
per item (see the scan-extras severity rubric).

The questionnaire is **bidirectional**, feeding both directions of the applicability gate (§5):
gaps become findings, and architecture answers (e.g. "OAuth only, no managed passwords") suppress
the checklist items that don't apply.

> **Cross-reference:** issue #31 tracks a fuller, standalone kickoff artifact
> (`docs/templates/auth-questionnaire.md`) covering tenancy model, roles/permissions, data
> sensitivity/compliance context, staging availability for M2, and integration surface — not yet
> written as of this runbook. The list above is the Tier-1-scan-relevant subset (the items that map
> directly to `briefs/scan-extras.txt` preconditions); once #31 lands, treat its questionnaire as the
> canonical kickoff artifact and this section as a pointer into it, not a duplicate to maintain
> separately.

## 4. False-positive control methodology

FP control is a **pipeline property**, not per-scanner perfection. Every finding runs this funnel
before it reaches the report:

1. **Two stages: find (high recall) → triage (high precision).** Never ship raw scanner output.
   The scan brief (`briefs/scan-extras.txt`) may over-flag; triage (`briefs/fp-rules.txt`) kills the noise.
2. **Deterministic suppression — `briefs/fp-rules.txt`.** Codifies known-FP classes (service-role bypass
   by itself, RLS-enabled-no-policy on a service-role-only table, derived-absolute-value updates,
   operator/env config URLs, shared permission gates with matching authority, in-process caches,
   upstream replay protection, test/fixture/seed code) and honors the client's own inline
   allow-comments.
3. **Two gates in triage, not one:**
   - **Correctness** — is it true? Requires a `file:line` + a trigger/repro. No repro → it goes to
     "areas to review" (skeleton §3c-adjacent), not the findings list.
   - **Applicability** — is it *relevant given this app's auth model and exposure*? This is the
     gate that catches the correct-but-irrelevant class (e.g. leaked-password protection flagged
     on an OAuth-only app). Advisor findings get this gate too, not just scanner findings — see §5.
4. **Adversarial verification** — a skeptic pass per finding ("prove it ISN'T real"); multi-vote on
   LLM-generated findings as hallucination control.
5. **Dynamic confirmation (M2)** for high-severity findings — turns "looks exploitable" into a
   proven repro. Un-reproducible high-severity findings get demoted, not shipped as Critical.
6. **Confidence labels** on every finding — `Confirmed` (repro'd) | `Likely` (needs one check) |
   `Review` (heuristic/candidate) | `N/A` (ruled out by applicability). Heuristic detectors are
   labeled as such. `N/A` findings go in the report's "Checked & ruled out" section (skeleton §3c),
   excluded from severity counts and the action plan.
7. **Human sign-off.** The deliverable is the operator's verified report, not raw tool output.

**Tool-specific FP classes to filter, not relay verbatim:**

| Tool | Known FP class |
|---|---|
| knip | public-API / dynamic exports |
| jscpd | intentional clones |
| Stryker | equivalent mutants, static-const survivors |
| Supabase/splinter advisors | safe-by-design RLS-no-policy on service-role-only tables; intentional `SECURITY DEFINER` |
| LLM-generated findings | require cited evidence, not assertion |

**Bias:** in a paid audit, a false positive costs more than a missed Low — it costs trust.
Under-claim: confirmed findings in the report, uncertain ones in "areas to review" at their stated
confidence.

## 5. Applicability framework — detect > ask > infer

Every rule in `briefs/scan-extras.txt` has a **precondition** (its `[when: …]` tag) — a fact about the
app that must hold for the finding to be real. Establish each precondition in this priority order:

1. **Detect** (from code/schema) — preferred: deterministic, no client effort, immune to "I don't
   know." The scan's own results are applicability signals — zero `'use server'` actions means
   Server-Action checks are N/A; zero webhook handlers means webhook-replay is N/A. **PII /
   data-sensitivity is detected, never asked** — matched against standard infoType dictionaries
   (M10, `tools/pii-classify.mjs`), names-only and privacy-safe.
2. **Ask** (the kickoff questionnaire, §3) — only for facts *not* in the repo: platform auth
   config, upstream-enforced controls (IdP/WAF), business intent ("is this table meant to be
   public", "do you want SOC 2"). Bidirectional: answers surface gaps *and* suppress irrelevant
   rules.
3. **Infer** (threat-model + operator judgment) — the residue after detect and ask. Every
   suppression made this way carries a stated, auditable reason in the report.

**Detect deeper before falling back to "confirm intent."** Most "ambiguous" findings resolve to a
verdict if you read the actual artifact instead of stopping at the advisor's summary:
- `SECURITY DEFINER` exposure — read the function body (`pg_get_functiondef`). Uses
  `auth.uid()`/`auth.jwt()` to constrain by the caller → caller-scoped, OK. Filters only by a
  parameter with no caller check → returns arbitrary data, not OK.
- RLS-enabled-no-policy — check the grants (`information_schema.role_table_grants`). No
  anon/authenticated SELECT grant → deny-all by design, OK. Has a client SELECT grant but no
  policy → grant/policy mismatch, needs confirmation.

## 6. Uncertainty handling — OK-when / Not-OK-when

For findings that are safe-or-not depending on design (RLS-enabled-no-policy, `SECURITY DEFINER`
exposure, unused indexes, low-confidence PII names): **state the uncertainty plainly and give the
client decision criteria**, so they can self-resolve. Never assert a context-dependent finding as
fact; never silently drop it either. Every such finding in the report carries an explicit
**OK when / Not OK when** pair (skeleton §3, per-finding block):

- RLS-enabled-no-policy: ✓ OK if the table is service-role-only (deny-all by design); ✗ Not OK if
  a user feature must read it via PostgREST (policy missing → feature silently returns empty).
- `SECURITY DEFINER` RPC-exposed: ✓ OK if caller-scoped (uses `auth.uid()`); ✗ Not OK if it returns
  cross-tenant data or leaks existence/status for arbitrary IDs.

## 7. Cost tracking

Record token/$ cost per stage (threat-model, scan, triage, report-mapping) so engagements can be
priced against a known COGS. Scan and triage are the expensive stages by volume; consider a
lighter model for the high-recall scan pass and a stronger model for triage (precision matters
more once volume is filtered) — pick per engagement based on repo size and budget, and record the
actual choice and cost against the estimate for future pricing calibration.

## 8. Client-data handling

- Read-only access only, scoped to the engagement.
- No proprietary client code pasted into shared/third-party logs — keep scan artifacts
  (`VULN-FINDINGS.*`, intermediate reports) inside the engagement's working directory.
- Delete local copies of client code and scan artifacts after the engagement closes and the report
  is delivered, per the signed engagement's data-retention terms.

---

### Deferred: live dry-run validation

**Update 2026-07-09 (issue #53):** step 1's install-path claim and steps 3-5's LLM pipeline
(`/threat-model bootstrap` → `/vuln-scan --extra` → `/triage --fp-rules`) have now been run for
real against `targets/calibration` and cross-checked against its `GROUND-TRUTH.md` answer key — see
`docs/runbooks/dry-run-calibration.md` §10 for the full results (7 of 8 planted bugs caught,
1 excluded by the pipeline's own built-in rules, not a coverage miss). The install-path correction
and known-blind-spot notes above come directly from that run.

Still deferred: this runbook has **not** been executed fully end-to-end producing a real client-shaped
report from the skeleton (`docs/audit-report-skeleton.md`) against a throwaway Supabase/Next.js repo
outside the calibration fixture, and per-stage token/$ cost (§7) has not yet been recorded from a real
engagement-shaped run. Those remain a manual follow-up.
