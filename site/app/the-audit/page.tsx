import type { Metadata } from "next";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

export const metadata: Metadata = {
  title: "The Audit — Harvey's ten-module methodology",
  description:
    "How a Harvey audit works: ten equally-weighted modules across security, tests, performance, data, and maintainability, a coverage ledger that shows what we didn't check, and a live pen-test that proves findings instead of flagging them.",
  alternates: { canonical: "/the-audit" },
  openGraph: {
    title: "The Audit — Harvey's ten-module methodology",
    description:
      "Ten equally-weighted modules, a coverage ledger, and a live pen-test that proves findings instead of flagging them.",
    url: "https://harvey-qa.com/the-audit",
    type: "article",
  },
};

const MODULES: { n: string; h: string; p: string; tier: string }[] = [
  {
    n: "M1",
    h: "Multi-tenant security & access control",
    p: "Who can read and write what. We review auth boundaries, Row-Level Security policy semantics (not just on/off), service-role key exposure, IDOR, over-fetching API routes, and cross-tenant isolation — the class of flaw that lets one user reach another's data.",
    tier: "Free (mechanical) → Connected (live RLS) → Full (semantic review)",
  },
  {
    n: "M2",
    h: "Live pen-test",
    p: "We stand up a copy of your stack locally, seed two tenants and two users, and actually try to cross the boundary — reading tenant B's rows as tenant A, probing auth attacks, endpoints, and service seams. A finding here isn't a warning; it's the row we should never have been able to read.",
    tier: "Full audit only (stands up your stack)",
  },
  {
    n: "M3",
    h: "Hotspot analysis",
    p: "Where complexity and change collide. We rank files by churn × complexity to find the few files that concentrate most of your bug risk — the ones that keep breaking every time you touch them.",
    tier: "Free (source)",
  },
  {
    n: "M4",
    h: "Duplication",
    p: "Copy-pasted logic that drifts out of sync, so a fix in one place silently misses the others. We measure duplicated blocks and near-miss clones that diverged after being copied.",
    tier: "Free (source)",
  },
  {
    n: "M5",
    h: "Dead code / slop",
    p: "What's shipped but never runs — unused exports, unreachable files, dependencies you no longer need. The dead weight an AI assistant tends to leave behind.",
    tier: "Free (source)",
  },
  {
    n: "M6",
    h: "Maintainability / simplification",
    p: "Hand-rolled code that has a safer, standard replacement. We flag reinvented auth, ad-hoc parsers, and fragile custom logic, then — on the paid tiers — name the specific library or pattern to replace it with.",
    tier: "Free (indicators) → Full (named replacement)",
  },
  {
    n: "M7",
    h: "Performance",
    p: "N+1 queries, missing indexes, render-time fetch waterfalls, RLS policies that re-evaluate per row, and Core Web Vitals. What will get slow — and what will fall over — when traffic scales.",
    tier: "Free (code) → Connected (DB advisors) → local Lighthouse",
  },
  {
    n: "M8",
    h: "Test quality",
    p: "Which of your tests can't actually catch a bug. We run mutation testing — deliberately break your code and report which tests still pass anyway. A green suite that can't fail is worse than no suite, because it's trusted.",
    tier: "Free (test-intent) → Full (mutation run)",
  },
  {
    n: "M9",
    h: "App Router boundaries",
    p: "Server→client data leaks, environment variables reachable from the browser, and Server Actions missing auth or input validation — the Next.js-specific ways a boundary quietly becomes public.",
    tier: "Free (source)",
  },
  {
    n: "M10",
    h: "Data classification",
    p: "Every column holding PII, PHI, or PCI data, and whether it's protected. Mapped from your schema for free, and verified against your live database on the connected tier.",
    tier: "Free (schema) → Connected (live)",
  },
];

export default function TheAudit() {
  return (
    <>
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <a href="/">Harvey</a> / The audit
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Methodology
            </span>
            <h1>What a Harvey audit actually does.</h1>
            <p className="lede">
              Ten modules, equal weight — a senior quality leader&apos;s read across your whole codebase, not a
              single-issue scan. Here is exactly what runs, how we prove it, and how we tell you what we didn&apos;t
              check.
            </p>
            <div className="hero-cta">
              <a href="/#scan" className="btn btn-primary">
                Run the free scan →
              </a>
              <a href="/pricing" className="btn btn-ghost">
                See pricing
              </a>
            </div>
          </div>
        </div>

        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">Ten modules · equal weight</span>
            <h2>The ten modules.</h2>
            <p>
              No module is the headline. The deliverable is the true state of your codebase across all ten — one
              readiness verdict. Each module runs at the tier its data allows; nothing runs at a shallower depth than
              your engagement supports.
            </p>
          </div>
          <div className="wrap">
            <div className="prose" style={{ maxWidth: "none" }}>
              {MODULES.map((m) => (
                <div className="method-mod" key={m.n}>
                  <span className="n">{m.n}</span>
                  <h3>{m.h}</h3>
                  <div>
                    <p>{m.p}</p>
                    <span className="tier">Runs at: {m.tier}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">The trust feature</span>
            <h2>The coverage ledger: we show you what we didn&apos;t check.</h2>
            <p>
              An unstated limitation reads as a clean bill of health. Most reports go quiet about what they skipped.
              Every Harvey report carries a coverage ledger instead — each module, its status, and the reason if it
              couldn&apos;t run. A module that couldn&apos;t run is listed as &quot;Not run&quot; with its reason, never
              silently dropped.
            </p>
          </div>
          <div className="wrap narrow">
            <div className="ledger">
              <div className="ledger-row">
                <span className="m">M1 · Access control &amp; data security</span>
                <span className="why">RLS + auth reviewed</span>
                <span className="pill ran">Ran</span>
              </div>
              <div className="ledger-row">
                <span className="m">M8 · Test quality</span>
                <span className="why">mutation run complete</span>
                <span className="pill ran">Ran</span>
              </div>
              <div className="ledger-row">
                <span className="m">M7 · Performance (DB advisors)</span>
                <span className="why">needs a connected database</span>
                <span className="pill part">Not run</span>
              </div>
              <div className="ledger-row">
                <span className="m">M2 · Live pen-test</span>
                <span className="why">Full-audit tier — not in this engagement</span>
                <span className="pill part">Not run</span>
              </div>
            </div>
            <p style={{ color: "var(--faint)", fontSize: "14px", fontFamily: "var(--mono)", marginTop: "16px" }}>
              A real ledger from a real report. The two &quot;Not run&quot; rows tell you precisely what a deeper tier
              would add.
            </p>
          </div>
        </section>

        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">Prove it, don&apos;t flag it</span>
            <h2>The live pen-test, explained.</h2>
          </div>
          <div className="wrap">
            <div className="prose">
              <p>
                Static analysis can tell you a policy <i>looks</i> like it lets the wrong user in. It can&apos;t tell you
                whether it actually does — that depends on how your auth, your policies, and your queries interact at
                runtime. So on the Full audit, Harvey stops guessing and tests it.
              </p>
              <ol>
                <li>
                  <b>We stand up a copy of your stack.</b> Harvey provisions its own local Supabase, applies your
                  migrations, and boots your app — no contact with your production environment.
                </li>
                <li>
                  <b>We seed two tenants and two users.</b> Two separate accounts with separate data, exactly like two
                  real customers.
                </li>
                <li>
                  <b>We try to cross the boundary.</b> Signed in as user A, Harvey runs the cross-tenant matrix against
                  your live PostgREST API and app routes, plus auth-attack and service-seam probes — attempting to read
                  and write data that belongs to user B.
                </li>
                <li>
                  <b>The finding is the evidence.</b> If the boundary holds, we record that it holds. If it doesn&apos;t,
                  the report shows the actual row we retrieved that we never should have been able to see. Proof, not a
                  warning.
                </li>
              </ol>
              <p>
                This is the work that a source-only &quot;vibe-code audit&quot; structurally cannot do, and it&apos;s the
                only tier that carries pen-test language. It&apos;s reserved for the Full audit because standing up and
                attacking a running copy of your stack is the expensive, high-value work.
              </p>
            </div>
          </div>
        </section>

        <section className="final">
          <div className="wrap">
            <span className="eyebrow" style={{ justifyContent: "center" }}>
              Start free
            </span>
            <h2 style={{ marginTop: "16px" }}>See the real state of your codebase.</h2>
            <div className="hero-cta">
              <a href="/#scan" className="btn btn-primary">
                Run the free scan →
              </a>
              <a href="/sample-report" className="btn btn-ghost">
                See a sample report
              </a>
            </div>
            <p className="trust">Source-only, no credentials, yours to keep.</p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
