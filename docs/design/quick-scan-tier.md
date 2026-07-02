# Free Quick-Scan Tier — Freemium GTM Model

Status: v1 (researched 2026-07-01) · Related: `mechanical-toolchain.md`, `scan-coverage-gaps.md`, quick-scan-tier issue.

Audience: solo devs, small shops, AI-reliant "vibe coders" on Next.js + Supabase.

## ⚠️ Decision needed: what the free tier reveals

The proposed model (as originally framed) was: **free quick scan → tell them how many issues we found → gate the details AND the deep scan behind payment.** The competitive/ethics research pushes back on the "gate the details" half, and this is a genuine business call the operator should make. Both variants are laid out below; the research **recommends Variant B**.

- **Variant A — "count only" (as originally described).** Free scan shows counts by severity; every finding's *location and detail* is paywalled. Simplest, but the research finds this reads to a burned, FUD-wary audience as the **"we found 12 criticals, pay to see them" shakedown / beg-bounty** pattern they've been trained to distrust — and it maps to the FTC "sneaking" dark-pattern category. No credible freemium security tool gates the *existence/detail* of findings this way.
- **Variant B — "free triage, paid remediation" (recommended).** The **mechanical layer is genuinely free and complete** — findings, locations, and the (publicly-googleable) mechanical fixes are all shown. What's gated is the **DEEP scan** (LLM semantic review + dynamic RLS/auth pen test), the fixes/patches for deep findings, and monitoring/re-scan. You charge for *depth and labor a solo dev cannot self-serve*, not for un-redacting a count. This matches how every credible tool (Snyk, Semgrep, Socket, GitGuardian, Pentest-Tools) structures free vs paid, and it still converts because the deep layer is the expensive thing they can't do alone.

The rest of this doc assumes Variant B and notes where A would differ.

## 1. Competitive teaser mechanics

The universal pattern across credible tools: **findings/detection are free; the paywall sits on depth, fixes-at-scale, private-repo/seat limits, and monitoring** — never on hiding what was found.

| Tool | FREE | GATED | Mechanic | Lowest paid |
|---|---|---|---|---|
| Snyk | Full vuln detail + CLI/IDE/SCM; private-repo test quotas | Fix examples, prioritization, dashboards, SSO | monthly test quota | ~$25/dev/mo |
| Semgrep | OSS CLI (2,800+ rules); AppSec free ≤10 devs/≤10 repos | Secrets, SSO, RBAC, API | 10-contributor wall | $30/contributor/mo |
| Socket | Unlimited devs/repos, 1,000 scans/mo, full PR detail | Reachability (FP cut), seats, SSO | "we flag everything, paid cuts noise" | $25/dev/mo |
| GitGuardian | Unlimited secret scanning ≤25 devs + remediation guidance | Custom detectors, severity, history | 25-dev/500-incident wall | quote |
| Aikido | 2 users/10 repos, full suite, 10 AI fixes/mo | PR review, unlimited fixes, compliance | $0→$300 "cliff" (cautionary) | $300/mo flat |
| SonarQube Cloud | Public repos; private ≤50k LOC | AI fixes, quality gates, taint, SCA | LOC wall (punishes AI bloat) | ~$34/mo |
| Pentest-Tools | **Light Scan** (passive, ~10 types, findings shown) | **Deep Scan** (40+ active: SQLi/XSS/SSRF/IDOR/JWT), auth scan, reports | passive→active | subscription |
| HubSpot Website Grader | 0–100 score + tips | full report | **email gate** → CRM | free (lead-gen) |

The two closest analogs to the quick-scan: **Pentest-Tools' Light→Deep split** (passive free / active paid — the cleanest security gate to copy) and **HubSpot Website Grader** (free score, email-gated report, viral low-score-urgency / high-score-shareable loop). Sources: [Snyk](https://snyk.io/plans/), [Semgrep](https://semgrep.dev/pricing/), [Socket](https://socket.dev/pricing), [GitGuardian](https://www.gitguardian.com/pricing), [Aikido](https://www.aikido.dev/pricing), [Pentest-Tools](https://pentest-tools.com/website-vulnerability-scanning/website-scanner), [Website Grader case study](https://outgrow.co/blog/hubspot-website-grader-case-study).

## 2. Free-vs-gated output spec

The free tier must pass three tests: (a) *not useless* (real, located findings), (b) *not a shakedown* (no hidden counts, no fear-without-proof), (c) *not self-defeating* (a savvy dev shouldn't be able to fully remediate the *hard* stuff alone). Resolution: give away the **mechanical layer completely** (cheap, low-FP, googleable anyway — withholding it only signals bad faith); charge for the **DEEP layer** a solo dev cannot self-serve.

### FREE (Quick Scan)

| Element | Show free? | Rationale |
|---|---|---|
| Total counts by severity | ✅ | Expected; fine only when paired with detail below (alone = Variant A shakedown). |
| Categories/types found | ✅ | "3× exposed `service_role` key, 2× RLS-disabled table, 5× dependency CVE." Naming the *type* separates triage from extortion. |
| File + line locations (mechanical) | ✅ | The key anti-shakedown move; mechanical findings are deterministic and public. |
| The actual fix (mechanical) | ✅ | Enable RLS on X; move key to server env; bump `next`. Public knowledge — give freely to earn trust. |
| One fully-revealed DEEP sample finding | ✅ (exactly one) | Best converter — a real end-to-end example (finding → exploit path → fix) from *their* repo, proving the paid depth. |
| Letter grade / score (A–F) | ✅ | Proven hook: urgency when low, shareable when high (viral loop / backlinks). Flavor, not core payload. |
| Benchmark vs peers | ⚠️ later | "Cleaner than 60% of scanned Next.js+Supabase repos" — motivating, but only once a real corpus exists; a fabricated benchmark destroys trust. |

### GATED (paid unlock)

- The **DEEP scan**: LLM semantic review (broken-auth logic, IDOR, tenant-isolation bugs, injection reachability) + **dynamic RLS/auth pen test** (actively probes whether policies are bypassable with the anon key — the single highest-value check for this audience given the 170+ real Lovable/Supabase RLS breaches).
- Fixes/patches for DEEP findings (+ optional one-click patch PR).
- Full detail/locations for DEEP findings beyond the one free sample.
- Re-scan / monitoring / history, PR checks, exportable report (PDF/SARIF).

Under **Variant A**, mechanical locations + fixes move into the gated column and only counts+categories stay free — accept the shakedown-perception risk in exchange for a stronger paywall.

## 3. Trust & ethics framing ("free triage, paid remediation," not ransom)

This audience smells FUD and "beg bounties" (automated scanners that flag trivia then send escalating pay-or-else emails). Guardrails:

1. **Never hide the existence/nature of a finding behind payment.** Issue types + locations + mechanical fixes are always free; you charge for *depth and labor* (dynamic testing, semantic analysis, patches, monitoring). This is the line between shakedown and service.
2. **No fear-language on trivia.** Severity must be earned and contextual — flag exploitability, not theoretical presence.
3. **Frame explicitly as triage → remediation:** *"The free scan is real and complete for mechanical issues — fixes included. Paid gets you the deep semantic + live pen-test that catches the logic and auth bugs a static scan physically can't."*
4. **Cite neutral authorities** (CISA/NIST/OWASP, the real CVE-2025-48757 Lovable-RLS class, Escape.tech findings) instead of dramatized breach stats.
5. **A clean scan says "clean."** Never manufacture findings to justify the upsell — convert clean repos on *monitoring* ("stay clean on every push"), not fear.

## 4. Delivery mechanics

**Primary channel: local `npx` CLI — "no code leaves your machine."** The single biggest trust differentiator for this audience. The mechanical layer needs only the checked-out code on disk, so it shouldn't require any cloud repo grant — and GitHub OAuth apps **cannot scope source access to read-only**, so handing a token to an unknown startup is a real risk a local scanner sidesteps. Lead with "npx, runs 100% locally, zero code upload."

The **DEEP scan requires code egress** (LLM + dynamic testing need the code and a running target) — be explicit and consent-gated: disclosed up front, ephemeral, not retained/trained-on. Honesty here is itself a trust asset.

| Channel | Trust friction | Best for |
|---|---|---|
| `npx` local CLI (primary) | Lowest — no grant, no signup to run | Free quick scan; the privacy pitch |
| Web "paste repo/deploy URL" (secondary) | Low for the deployed-site dynamic check (public surface only) | Vibe coders with a live Vercel URL but shaky git hygiene |
| Scoped read-only GitHub App (opt-in) | Medium (but ≫ OAuth) | Continuous monitoring / PR checks (paid) |

**Funnel:** `npx` local scan (free, no signup) → email for full report / grade badge → paid DEEP unlock → optional GitHub App for continuous monitoring.

## 5. Pricing shape

Segment willingness-to-pay clusters at $9–29/mo (solo), $29–99/mo (small team). Security comparables: Snyk ~$25/dev, Semgrep $30/contributor, Socket $25/dev, Corgea $39/dev — with **Aikido's $0→$300/mo cliff a cautionary tale**. Offer both a one-time and a subscription because the audience splits:

- **Free** — unlimited local quick scans (mechanical, fixes included), grade + one DEEP sample finding.
- **One-time DEEP report: ~$29–$49/repo** — matches "vibe coder who just shipped and wants one audit before launch." Impulse-priced, no subscription dread; likely the **highest-volume converter** for this audience.
- **Solo subscription: ~$19–$29/mo** — unlimited DEEP scans + monitoring + PR checks.
- **Small-shop: ~$49–$99/mo** — a few seats/repos, continuous monitoring.
- Avoid per-LOC (punishes AI bloat — exactly this audience's code) and a steep flat first tier (Aikido's mistake). Ranges, not precision — validate the one-time-vs-subscription split with an early pricing test.

## 6. Conversion funnel & risks

**Funnel:** frictionless local scan (no signup) → grade + itemized triage + 1 DEEP teaser → email gate for shareable report/badge → paid DEEP unlock (impulse one-time or subscription) → GitHub App for monitoring (retention).

Failure modes:
1. **False positives destroy everything.** A single wrong "critical" in the free count nukes credibility and reads as a manufactured shakedown. This is *the* existential risk and the entire reason the free tier is **mechanical-only** — tune mechanical checks for near-zero FP even at the cost of recall, and never surface a probabilistic/semantic finding in the free count (see `mechanical-toolchain.md` §7 trust boundary).
2. **Too noisy → distrust** (over-flagging trivia as high-severity = beg-bounty smell). Contextualize severity by exploitability; default low-confidence to "info."
3. **Too clean → "I don't need you."** Convert clean repos on monitoring + the DEEP-sample teaser, not fear.
4. **Shakedown perception on the gate** — mitigated structurally by Variant B (locations + mechanical fixes free; gate visibly on depth/labor).
5. **Repo-access trust** — mitigated by local-`npx`-first; ask for a scoped GitHub App only after payment + monitoring intent.
6. **DEEP-scan code egress objection** — disclose plainly, ephemeral/no-train, confine free tier to local so trust is earned before any upload.

**Strategic bet:** win trust with a genuinely useful, honest, low-FP, *local* free scan that gives away the cheap fixes — and monetize the expensive thing a solo dev physically can't do themselves (dynamic RLS/auth pen test + semantic review), which is exactly the failure class (missing RLS, leaked `service_role` keys) documented in 170+ real Lovable/Supabase breaches and ~380k exposed apps.

## Sources

[Snyk plans](https://snyk.io/plans/) · [Semgrep pricing](https://semgrep.dev/pricing/) · [Socket pricing](https://socket.dev/pricing) · [GitGuardian pricing](https://www.gitguardian.com/pricing) · [Aikido pricing](https://www.aikido.dev/pricing) · [Pentest-Tools scanner](https://pentest-tools.com/website-vulnerability-scanning/website-scanner) · [HubSpot Website Grader case study](https://outgrow.co/blog/hubspot-website-grader-case-study) · [GitHub Apps vs OAuth scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/differences-between-github-apps-and-oauth-apps) · beg-bounty/shakedown optics: [indiehackers](https://www.indiehackers.com/post/received-cold-email-from-ethical-hacker-with-info-on-a-vuln-on-your-website-asking-for-a-reward-what-to-do-4d423bc388), [Chino.io](https://www.chino.io/post/we-found-a-security-vulnerability-on-your-website-how-should-you-respond) · Supabase RLS breaches: [byteiota](https://byteiota.com/supabase-security-flaw-170-apps-exposed-by-missing-rls/), [Security Boulevard/Escape.tech](https://securityboulevard.com/2025/10/methodology-how-we-discovered-over-2k-high-impact-vulnerabilities-in-apps-built-with-vibe-coding-platforms/)
