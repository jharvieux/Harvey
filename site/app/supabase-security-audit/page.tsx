import type { Metadata } from "next";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

export const metadata: Metadata = {
  title: "Supabase Security Audit — a real audit, not a scanner",
  description:
    "A Supabase security audit reviews your app's authorization logic — RLS policies, auth guards, and multi-tenant boundaries — to find where users can reach data they shouldn't, then proves it against a live copy of your stack. Transparent pricing, no book-a-call.",
  alternates: { canonical: "/supabase-security-audit" },
  keywords: [
    "supabase security audit",
    "supabase pentest",
    "supabase penetration testing service",
    "hire a supabase security expert",
    "supabase RLS audit",
  ],
  openGraph: {
    title: "Supabase Security Audit — a real audit, not a scanner",
    description:
      "Reviews your authorization logic and proves cross-tenant flaws live. Transparent pricing, no book-a-call.",
    url: "https://harvey-qa.com/supabase-security-audit",
    type: "article",
  },
};

const faq = [
  {
    q: "Is the Supabase anon key supposed to be public?",
    a: "Yes — the anon key is public by design. Your security comes from Row-Level Security, not from hiding the key. If RLS is missing or misconfigured, that public key becomes a master key to your database. That's the single most common failure we find.",
  },
  {
    q: "Can't I just run an automated scanner?",
    a: "A scanner checks patterns and known CVEs. It can't tell whether your users can read each other's data, because that depends on your authorization logic across multiple files. That's what an audit is for. Run both — they do different jobs.",
  },
  {
    q: "How much does a Supabase security audit cost?",
    a: "Harvey's free scan is $0. Paid tiers are priced by codebase size, measured automatically during the free scan: a Connected audit (adds a read of your live database) starts at $500, and a Full audit (which stands up and attacks a copy of your stack) starts at $1,000. Most boutique vibe-code audits run $1,500–$5,000 for source review only; a traditional pentest runs $4,000–$12,000. Harvey sits between: deeper than a source-only audit, faster and cheaper than a pentest firm.",
  },
  {
    q: "Do you need access to my database?",
    a: "Not for the free scan — it runs on source only, no credentials. Only the Connected and Full tiers read your production database, and only read-only. The Full-tier pen-test runs against a copy Harvey stands up on its own machines, never against your production.",
  },
  {
    q: "What if my app was built with Lovable, Bolt, Cursor, or v0?",
    a: "That's exactly who this is for. AI-built Supabase apps are where we most often find cross-tenant data exposure — and the fix is usually straightforward once you can see it.",
  },
  {
    q: "Will you help me fix what you find?",
    a: "Every finding comes with a fix. The audit includes a free re-verification of the critical findings after you ship the fixes.",
  },
];

const faqJsonLd = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: faq.map((f) => ({
    "@type": "Question",
    name: f.q,
    acceptedAnswer: { "@type": "Answer", text: f.a },
  })),
};

export default function SupabaseSecurityAudit() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(faqJsonLd) }} />
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <a href="/">Harvey</a> / Supabase security audit
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Supabase security
            </span>
            <h1>Supabase security audit — a real audit, not a scanner.</h1>
            <div className="answer-first" style={{ marginTop: "22px" }}>
              A Supabase security audit is a review of <i>your</i> app&apos;s authorization logic — RLS policies, auth
              guards, and multi-tenant boundaries — to find where users can access data they shouldn&apos;t. Automated
              scanners can&apos;t do this reliably, because the flaws live in your code&apos;s logic, not its syntax.
              Harvey reads the logic and then proves it against a live copy of your stack.
            </div>
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
          <div className="wrap">
            <div className="prose">
              <h2>The vulnerability almost every Supabase app has at some point</h2>
              <p>
                Supabase&apos;s Row-Level Security is opt-in, not on by default. The most common flaw isn&apos;t a
                missing lock — it&apos;s a lock that looks fastened and isn&apos;t. The canonical example:
              </p>
              <pre>
                <code>{`-- Looks correct. Lets ANY logged-in user read EVERY tenant's rows.
CREATE POLICY "users can read" ON documents
  FOR SELECT USING (auth.role() = 'authenticated');`}</code>
              </pre>
              <p>
                That policy passes a glance, passes most automated checks, and quietly exposes every tenant&apos;s data
                to every logged-in user. Only reading the code — and then testing it — catches it. The same class
                includes <code>service_role</code> keys on client-reachable paths (which bypass RLS entirely by design),
                over-fetching API routes, unauthenticated endpoints, and IDOR.
              </p>

              <h2>Why a scanner isn&apos;t enough</h2>
            </div>
            <div className="table-scroll" style={{ marginTop: "18px" }}>
              <table className="cmp">
                <thead>
                  <tr>
                    <th>Question about your app</th>
                    <th className="c">Automated scanner</th>
                    <th className="c">Harvey audit</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Finds known-CVE dependency issues</td>
                    <td className="c"><span className="yes">✓</span></td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>Flags syntax-level patterns</td>
                    <td className="c"><span className="yes">✓</span></td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>Understands <i>your</i> authorization logic</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>Tests whether tenant A can read tenant B&apos;s data</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span> live</td>
                  </tr>
                  <tr>
                    <td>Reviews RLS policy <i>semantics</i>, not just presence</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>Proves a finding is actually exploitable</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span> pen-test</td>
                  </tr>
                  <tr>
                    <td>Covers code health, not just security</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span> 10 modules</td>
                  </tr>
                  <tr>
                    <td>Tells you what it did <i>not</i> check</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span> ledger</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="prose" style={{ marginTop: "10px" }}>
              <p>
                Scanners are good continuous hygiene — keep yours. An audit answers the question a scanner structurally
                can&apos;t: <i>does my app actually leak?</i>
              </p>

              <h2>What Harvey checks on a Supabase + Next.js app</h2>
              <p>Ten modules, equal weight (security and code health). Among much else:</p>
              <ul>
                <li>
                  <b>Multi-tenant isolation</b> — every RLS policy reviewed for semantics, not just enabled/disabled:{" "}
                  <code>USING(true)</code>, wrong-column predicates, weak <code>WITH CHECK</code>, user-metadata trust,{" "}
                  <code>SECURITY DEFINER</code> functions with unguarded writes.
                </li>
                <li>
                  <b>service_role exposure</b> — anywhere a service key sits on a client-reachable path.
                </li>
                <li>
                  <b>Live cross-tenant pen-test</b> — we seed two tenants on a local copy of your stack and try to read
                  across the boundary. Proof, not a warning.
                </li>
                <li>
                  <b>App Router boundaries</b> — server→client data leaks, Server Action auth and validation.
                </li>
                <li>
                  <b>Data classification</b> — every PII/PHI/PCI column and where it lives.
                </li>
                <li>Plus performance, duplication, dead code, maintainability, and test quality.</li>
              </ul>
              <p>
                Full methodology → <a href="/the-audit">The Audit</a>.
              </p>

              <h2>What you get</h2>
              <ul>
                <li>A findings report in plain English, ranked by blast radius — written for a founder, not a pentester.</li>
                <li>For each finding: what it is, where it is, why it matters, and how to fix it.</li>
                <li>
                  A <b>coverage ledger</b>: exactly what we checked and what we didn&apos;t, with reasons. No silent
                  gaps.
                </li>
                <li>A re-audit credit: when you ship the fixes, we re-verify the critical findings once at no extra charge — additional re-audits are available as a paid add-on.</li>
                <li>
                  Optional <b>investor-ready summary</b>: a buyer-facing document for fundraise or acquisition diligence.
                </li>
              </ul>

              <h2>Pricing</h2>
              <p>
                No &quot;book a call to hear the price.&quot; Priced by codebase size, measured automatically during the
                free scan:
              </p>
              <ul>
                <li>
                  <b>Free scan — $0.</b> Source-only, no credentials, same-day. Static findings from every module
                  source alone can run, plus the ten-module coverage ledger, yours to keep.
                </li>
                <li>
                  <b>Connected audit — from $500.</b> The full review with real verdicts, plus a read of your live
                  database: live RLS, Supabase advisors, PII in production.
                </li>
                <li>
                  <b>Full audit — from $1,000.</b> Everything in Connected, plus Harvey stands up a copy of your stack
                  and proves findings with a live pen-test, and runs full mutation testing.
                </li>
              </ul>
              <p>
                Full grid and size bands → <a href="/pricing">Pricing</a>.
              </p>
            </div>

            <div className="sec-head" style={{ marginTop: "56px", marginBottom: "0" }}>
              <span className="eyebrow">FAQ</span>
              <h2>Supabase security audit — common questions.</h2>
            </div>
            <div className="faq" style={{ marginTop: "24px" }}>
              {faq.map((f) => (
                <div className="faq-item" key={f.q}>
                  <h3>{f.q}</h3>
                  <p>{f.a}</p>
                </div>
              ))}
            </div>

            <div className="cta-band">
              <div>
                <h3>Run the free scan on your Supabase app.</h3>
                <p>Source-only, no credentials, same-day. If it finds nothing worth going deeper on, don&apos;t buy a thing.</p>
              </div>
              <div className="btns">
                <a href="/#scan" className="btn btn-primary">
                  Run the free scan →
                </a>
                <a href="/supabase-security-checklist" className="btn btn-ghost">
                  Security checklist
                </a>
              </div>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
