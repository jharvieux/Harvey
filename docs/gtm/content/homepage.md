# Homepage copy — harvey-qa.com

Draft copy for the Harvey homepage (`05-website-plan.md`, page 1). Written to the three
pillars (`02-positioning-messaging.md`) and the "worried founder at 11pm" test: within
10 seconds a visitor knows this is for Supabase apps, it's a real audit not another
scanner, and there's a free way in. This is copy for review/approval, not final markup.

---

## Hero

**Eyebrow:** For founders who shipped fast — with AI or without.

**H1:** Is your Supabase app leaking data you can't see?

**Subhead:**
Harvey runs a ten-part audit of your Supabase + Next.js app — security *and* code
health — then hands you a report you can actually act on. We don't guess from the
outside. We read your policies, stand up a copy of your stack, and try to break in.

**Primary CTA:** Run the free scan →
**Secondary CTA:** See a sample report

**Trust line under the buttons:**
No database access, no credentials, no production contact for the free scan. Just point
us at your repo.

---

## Problem section

**H2:** A logged-in user reading another tenant's data is one bad line of code away.

**Body:**
The apps shipping fastest today — built with Cursor, Claude, Lovable, Bolt — share a
quiet problem: the code *looks* right and isn't. A Row-Level-Security policy that lets
any signed-in user read every tenant's rows. An API route that returns more than it
should. A `service_role` key doing work it shouldn't. These don't show up in a linter or
a dependency scanner, because they live in your app's logic, not its syntax.

It's common, and it's not your fault. When researchers scanned public apps built with AI
tools, roughly one in ten was exposing user data — most from a single missing security
setting. One app leaked 18,697 user records. Shipping fast was the right call. Checking
the work before you scale is what comes next.

*(Stat sourcing: `01-market-competitive-analysis.md`, verified claims only. Never the
refuted "70%" figure.)*

---

## Differentiation section — "a scan is not an audit"

**H2:** Scanners check patterns. Harvey checks whether your app actually leaks.

**Body:**
A scanner can tell you a policy *looks* misconfigured. It can't tell you that **tenant A
can read tenant B's data** — because that answer lives in your authorization logic, your
RLS policies, and how your code fits together across files.

So Harvey does what a scanner can't: we read your actual policies, then stand up a live
copy of your stack with two separate tenants and **try to cross the boundary**. We don't
tell you RLS "might be" wrong. We show you the row we shouldn't have been able to read.

**Three-column proof:**
- **We read the logic.** RLS policies, auth guards, Server Actions, App Router
  boundaries — the multi-file, framework-aware review pattern-matchers miss.
- **We attack a live copy.** Two seeded tenants on your own stack, run locally. Real
  cross-tenant probing, auth attacks, service-seam checks. Proof, not warnings.
- **We show our work.** Every audit lists what we checked — and what we didn't, and why.
  No silent gaps. The one report that tells you where it stopped.

---

## Full-suite section — "security is half your problem"

**H2:** Ten parts. Security is only half of it.

**Body:**
The same habits that leak data also pile up: dead code, duplicated logic, tests that
can't actually fail, slow queries, and PII sitting in places you've forgotten. Harvey's
ten modules carry equal weight, because "the true state of your codebase" is the
deliverable — not a vulnerability list.

**The ten-module grid** (two rows of five, each a short line):
1. **Multi-tenant security** — cross-tenant isolation, RLS, auth boundaries
2. **Live pen-test** — a real attack on a live copy of your stack
3. **Hotspot analysis** — where complexity and change collide
4. **Duplication** — copy-pasted logic that drifts out of sync
5. **Dead code** — what's shipped but never runs
6. **Maintainability** — hand-rolled code with a better replacement
7. **Performance** — N+1 queries, missing indexes, Core Web Vitals
8. **Test quality** — which of your tests can't actually catch a bug
9. **App Router boundaries** — server→client leaks, Server Action auth
10. **Data classification** — every piece of PII/PHI/PCI, and where it lives

---

## How it works

**H2:** Free scan first. Buy only if it's worth going deeper.

**Three steps:**
1. **Point us at your repo.** Read-only access (with git history) or a code archive. No
   database, no keys, no production contact. Same-day turnaround.
2. **Get your free report.** Ten modules' worth of source-level findings, in plain
   English, ranked by what matters — yours to keep whether or not you buy.
3. **Go deeper if it's warranted.** If the scan surfaces something worth proving, the
   paid audit confirms it against your live stack and proves what's actually
   exploitable.

---

## Pricing teaser

**H2:** Transparent pricing. No "book a call to hear the price."

**Body:** Free automated scan. A full ten-module audit from $2,000. A connected audit
with the live pen-test from $5,000. See exactly what each tier checks →

*(Anchors per `03-pricing-packaging.md`; treat as launch numbers pending price
discovery. Publishing prices is a deliberate differentiator — competitors hide them.)*

---

## Final CTA

**H2:** Find out what's actually in your codebase.

**Primary CTA:** Run the free scan →
**Reassurance line:** Source-only. No credentials. If it finds nothing worth a deeper
look, don't buy a thing.

---

## Footer essentials

Links: The Audit (methodology) · Pricing · Sample Report · Blog/Research · About ·
Responsible Disclosure · Data Handling. Entity name "Harvey" consistent for AEO.
`llms.txt` linked. Schema.org `Organization` + `Service` in head.

---

## Voice check

Plain English, senior-engineer-to-smart-founder, zero fear-mongering, zero enterprise
jargon. Every claim above is product-true today (ten modules, free source-only tier,
live M2 pen-test, coverage ledger). Do not add a claim the product can't back.
