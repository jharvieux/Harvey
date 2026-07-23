# Service page copy — "Supabase Security Audit"

Draft copy for the #1-priority content/service page (`06-seo-aeo.md`, piece #1). This is
the page that wins the uncontested commercial query "supabase security audit" — where
today only weak results rank (a LinkedIn post, a GitHub markdown file) and no
authoritative service page exists. Written answer-first for AEO. Copy for review.

**Target queries:** supabase security audit · supabase pentest · supabase penetration
testing service price · hire a supabase security expert
**URL:** harvey-qa.com/supabase-security-audit
**Format:** service page + scanner-vs-audit comparison + transparent pricing + FAQ (with
`FAQPage` JSON-LD — the structural edge competitors skip).

---

## H1: Supabase Security Audit

**Answer-first intro (first 50 words — the part AI assistants quote):**
A Supabase security audit is a review of *your* app's authorization logic — RLS
policies, auth guards, and multi-tenant boundaries — to find where users can access data
they shouldn't. Automated scanners can't do this reliably, because the flaws live in
your code's logic, not its syntax. Harvey reads the logic and then proves it against a
live copy of your stack.

---

## H2: The vulnerability almost every Supabase app has at some point

Supabase's Row-Level Security is opt-in, not on by default. The most common flaw isn't a
missing lock — it's a lock that looks fastened and isn't. The canonical example:

```sql
-- Looks correct. Lets ANY logged-in user read EVERY tenant's rows.
CREATE POLICY "users can read" ON documents
  FOR SELECT USING (auth.role() = 'authenticated');
```

That policy passes a glance, passes most automated checks, and quietly exposes every
tenant's data to every logged-in user. Only reading the code — and then testing it —
catches it. The same class includes `service_role` keys on client-reachable paths (which
bypass RLS entirely by design), over-fetching API routes, unauthenticated endpoints, and
IDOR.

---

## H2: Why a scanner isn't enough

| | Automated scanner | Harvey audit |
|---|---|---|
| Finds known-CVE dependency issues | ✅ | ✅ |
| Flags syntax-level patterns | ✅ | ✅ |
| Understands *your* authorization logic | ❌ | ✅ |
| Tests whether tenant A can read tenant B's data | ❌ | ✅ (live) |
| Reviews RLS policy *semantics*, not just presence | ❌ | ✅ |
| Proves a finding is actually exploitable | ❌ | ✅ (live pen-test) |
| Covers code health, not just security | ❌ | ✅ (10 modules) |
| Tells you what it did *not* check | ❌ | ✅ (coverage ledger) |

Scanners are good continuous hygiene — keep yours. An audit answers the question a
scanner structurally can't: *does my app actually leak?*

---

## H2: What Harvey checks

Ten modules, equal weight (security *and* code health). On a Supabase + Next.js app that
means, among much else:

- **Multi-tenant isolation** — every RLS policy reviewed for semantics (not just
  "enabled/disabled"): `USING(true)`, wrong-column predicates, weak `WITH CHECK`,
  user-metadata trust, `SECURITY DEFINER` functions with unguarded writes.
- **`service_role` exposure** — anywhere a service key sits on a client-reachable path.
- **Live cross-tenant pen-test** — we seed two tenants on a local copy of your stack and
  try to read across the boundary. Proof, not a warning.
- **App Router boundaries** — server→client data leaks, Server Action auth/validation.
- **Data classification** — every PII/PHI/PCI column and where it lives.
- Plus performance, duplication, dead code, maintainability, and test quality.

Full methodology → *(link to The Audit page)*

---

## H2: What you get

- A findings report in plain English, ranked by blast radius — written for a founder,
  not a pentester.
- For each finding: what it is, where it is, why it matters, and how to fix it.
- A **coverage ledger**: exactly what we checked and what we didn't, with reasons. No
  silent gaps.
- A re-audit credit: when you ship the fixes, we re-verify the critical findings free.
- Optional **investor-ready summary**: a buyer-facing document for fundraise or
  acquisition diligence — non-technical to read, defensible under technical scrutiny.

---

## H2: Pricing

No "book a call to hear the price." (Sourced from `03-pricing-packaging.md` — launch
anchors, pending price discovery.)

- **Free scan — $0.** Source-only, no credentials, same-day. Ten modules' worth of
  static findings, yours to keep.
- **Connected audit — from $500.** The complete review: all ten modules over your source
  with semantic verdicts (triage + named fixes), plus a read-only pass over your live
  database — live RLS verification, database advisors, drift, and data-classification
  against a read-only copy of your production database.
- **Full audit — from $1,000.** Everything in Connected, plus Harvey stands up your stack
  and runs a live pen-test (and mutation testing) against it. The premium, "everything
  included" tier. (Priced by codebase size; enterprise/regulated = custom.)
- **Investor-ready summary — Full-tier add-on.** The diligence-facing report.

---

## H2: FAQ (answer-first; ships with FAQPage JSON-LD)

**Is the Supabase anon key supposed to be public?**
Yes — the anon key is public by design. Your security comes from Row-Level Security, not
from hiding the key. If RLS is missing or misconfigured, that public key becomes a master
key to your database. That's the single most common failure we find.

**Can't I just run an automated scanner?**
A scanner checks patterns and known CVEs. It can't tell whether *your* users can read
each other's data, because that depends on your authorization logic across multiple
files. That's what an audit is for. Run both — they do different jobs.

**How much does a Supabase security audit cost?**
Harvey's free scan is $0, a connected audit (adds a read-only pass over your live
database) starts at $500, and a full audit — which adds a local-stack pen-test — starts
at $1,000, priced by codebase size. Most boutique "vibe-code" audits run $1,500–$5,000 for
source review only; a traditional web-app pentest runs $4,000–$12,000. Harvey starts well
below both: deeper than a source-only audit, far cheaper than a pentest firm, and it
scales by the size of your codebase.

**Do you need access to my database?**
Not for the free scan or the full audit — those run on source (and a local copy of your
stack). Only the connected tier reads your production database, and only read-only.

**What if my app was built with Lovable / Bolt / Cursor / v0?**
That's exactly who this is for. AI-built Supabase apps are where we most often find
cross-tenant data exposure — and the fix is usually straightforward once you can see it.

**Will you help me fix what you find?**
Every finding comes with a fix. The audit includes a free re-verification of critical
findings after you ship the fixes.

---

## Closing CTA

**Run the free scan on your Supabase app →**
Source-only, no credentials, same-day. If it finds nothing worth going deeper on, don't
buy a thing.
