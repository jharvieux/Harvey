import type { Metadata } from "next";
import Link from "next/link";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

export const metadata: Metadata = {
  title: "Pricing — Harvey codebase audit",
  description:
    "Transparent, size-banded pricing for a Harvey audit. Free scan $0. Connected audit from $500. Full audit from $1,000. Priced by codebase size, measured automatically during the free scan — no 'book a call to hear the price.'",
  alternates: { canonical: "/pricing" },
  openGraph: {
    title: "Pricing — Harvey codebase audit",
    description:
      "Free scan $0 · Connected from $500 · Full from $1,000. Size-banded, published up front — no 'book a call to hear the price.'",
    url: "https://harvey-qa.com/pricing",
    type: "website",
  },
};

function Check() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

const pricingFaq = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: [
    {
      "@type": "Question",
      name: "How much does a Harvey audit cost?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "The free scan is $0. Paid audits are priced by codebase size, measured automatically during the free scan: a Connected audit starts at $500 and a Full audit starts at $1,000. Medium, large, and enterprise codebases pay more; enterprise and regulated apps are custom-quoted.",
      },
    },
    {
      "@type": "Question",
      name: "Why is pricing based on codebase size?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Lines of app code is the simplest fair proxy for audit effort, and Harvey measures it automatically from your repo during the free scan — so a weekend project and an enterprise monorepo never pay the same. Generated and vendored code is excluded; Harvey's dead-code and duplication modules already detect it.",
      },
    },
    {
      "@type": "Question",
      name: "What is the difference between the Connected and Full tiers?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Connected is the complete review of all ten modules with real verdicts, plus a read of your live database (RLS, Supabase advisors, drift between your deployed schema and your committed migrations, PII in production). Full adds the labor-intensive dynamic work: Harvey stands up a copy of your stack and proves findings live with a pen-test, and runs full mutation testing. Only the Full tier carries pen-test language.",
      },
    },
    {
      "@type": "Question",
      name: "Do I have to book a call to get a price?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "No. The grid is published up front. Most boutique auditors hide pricing behind a mandatory call; Harvey publishes it because transparent, size-based pricing is a friction-remover and on-brand with our coverage-honesty identity. Enterprise and custom bands are the only ones quoted individually.",
      },
    },
  ],
};

export default function Pricing() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(pricingFaq) }} />
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <Link href="/">Harvey</Link> / Pricing
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Transparent pricing
            </span>
            <h1>No &quot;book a call to hear the price.&quot;</h1>
            <p className="lede">
              Publishing prices is deliberate — most boutique auditors hide them behind a call. Pricing scales with your
              codebase size, so a weekend project and an enterprise monorepo never pay the same.
            </p>
          </div>
        </div>

        <section>
          <div className="wrap price-grid">
            <div className="tier">
              <span className="tname">FREE SCAN</span>
              <div className="amt">$0</div>
              <ul>
                <li>
                  <Check />
                  Source-only, no credentials
                </li>
                <li>
                  <Check />
                  Static findings + a ten-module coverage ledger
                </li>
                <li>
                  <Check />
                  Same-day, yours to keep
                </li>
              </ul>
              <Link href="/#scan" className="btn btn-ghost">
                Run the free scan
              </Link>
            </div>
            <div className="tier">
              <span className="tname">CONNECTED AUDIT</span>
              <div className="amt">
                $500<small> / from · by size</small>
              </div>
              <ul>
                <li>
                  <Check />
                  All ten modules, reviewed with real verdicts
                </li>
                <li>
                  <Check />
                  Live database: RLS, Supabase advisors, prod-vs-migration drift
                </li>
                <li>
                  <Check />
                  PII protection verified in production
                </li>
                <li>
                  <Check />
                  Read-only access — nothing stood up
                </li>
              </ul>
              <Link href="/#scan" className="btn btn-ghost">
                Start with a free scan
              </Link>
            </div>
            <div className="tier feature">
              <span className="tname">FULL AUDIT</span>
              <div className="amt">
                $1,000<small> / from · by size</small>
              </div>
              <ul>
                <li>
                  <Check />
                  Everything in the Connected audit
                </li>
                <li>
                  <Check />
                  We stand up your stack and attack it live
                </li>
                <li>
                  <Check />
                  Cross-tenant access &amp; auth flaws proven
                </li>
                <li>
                  <Check />
                  Mutation-tested tests + investor-ready summary
                </li>
              </ul>
              <Link href="/#scan" className="btn btn-primary">
                Start with a free scan
              </Link>
            </div>
          </div>

          <div className="wrap" style={{ marginTop: "26px" }}>
            <div className="table-scroll">
              <table className="cmp">
                <thead>
                  <tr>
                    <th>
                      Codebase size{" "}
                      <span style={{ fontWeight: 400, color: "var(--faint)", textTransform: "none", letterSpacing: 0 }}>
                        · measured automatically
                      </span>
                    </th>
                    <th className="c">Free scan</th>
                    <th className="c">Connected</th>
                    <th className="c">Full audit</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Small · under 10k lines</td>
                    <td className="c">$0</td>
                    <td className="c">$500</td>
                    <td className="c">$1,000</td>
                  </tr>
                  <tr>
                    <td>Medium · 10k–50k lines</td>
                    <td className="c">$0</td>
                    <td className="c">$1,500</td>
                    <td className="c">$3,000</td>
                  </tr>
                  <tr>
                    <td>Large · 50k–150k lines</td>
                    <td className="c">$0</td>
                    <td className="c">$3,500</td>
                    <td className="c">$7,000</td>
                  </tr>
                  <tr>
                    <td>Enterprise · 150k+ / monorepo / regulated</td>
                    <td className="c">$0</td>
                    <td className="c">Custom</td>
                    <td className="c">Custom</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="foot-note" style={{ marginTop: "14px" }}>
              We measure your codebase size during the free scan and quote from it — generated and vendored code
              doesn&apos;t count. Launch pricing; for context, source-only &quot;vibe-code&quot; audits run $1,500–$5,000
              and a traditional pentest $4,000–$12,000 regardless of app size.
            </p>
          </div>

          <div className="wrap">
            <div className="addons">
              <span className="addon-tag">Add-on</span>
              <p>
                <b>Findings to tickets.</b> We file every finding as an issue in your tracker — GitHub, Jira, Linear,
                GitLab, or Azure DevOps — deduped against your last audit, so your team fixes from their own board.
              </p>
            </div>
            <div className="addons" style={{ marginTop: "14px" }}>
              <span className="addon-tag">Add-on</span>
              <p>
                <b>Investor-ready summary.</b> A buyer-facing document for fundraise or acquisition diligence —
                non-technical to read, defensible under technical scrutiny. Available on the Full tier.
              </p>
            </div>
            <div className="addons" style={{ marginTop: "14px" }}>
              <span className="addon-tag">Included</span>
              <p>
                <b>Re-audit credit.</b> When you ship the fixes, we re-verify the critical findings once at no extra
                charge, if requested within 30 days of the original audit. Additional re-audits within that window
                are a paid add-on at 50% of the original audit price. The
                repeat-customer diff automates it, so it&apos;s cheap for us and high-trust for you.
              </p>
            </div>
            <div className="addons" style={{ marginTop: "14px" }}>
              <span className="addon-tag">Included</span>
              <p>
                <b>Machine-readable exports.</b> Ask and your findings also ship as SARIF — the format GitHub code
                scanning and security tooling ingest — plus a CycloneDX software bill of materials of your
                dependencies, the artifact enterprise buyers ask for. The coverage ledger travels inside the SARIF,
                so a module that didn&apos;t run can&apos;t disappear into &quot;no results.&quot;
              </p>
            </div>
          </div>
        </section>

        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">Free indicates · the audit proves</span>
            <h2>What each tier can and can&apos;t tell you.</h2>
            <p>
              The escalation is by access: Free reads your source, Connected adds your live database, Full stands up and
              attacks a running copy. Each rung is a clean superset of the one before.
            </p>
          </div>
          <div className="wrap">
            <div className="matrix-scroll">
              <table className="matrix">
                <thead>
                  <tr>
                    <th>What you actually get</th>
                    <th>
                      Free scan<span className="p">$0</span>
                    </th>
                    <th>
                      Connected<span className="p">from $500</span>
                    </th>
                    <th className="feat">
                      Full audit<span className="p">from $1,000</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="grp">
                    <td colSpan={4}>Reads your source</td>
                  </tr>
                  <tr>
                    <td className="cap">Findings from every module source alone can run</td>
                    <td className="dot"><span className="on">●</span></td>
                    <td className="dot"><span className="on">●</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                  <tr>
                    <td className="cap">Coverage ledger: all ten modules, status and reason</td>
                    <td className="dot"><span className="on">●</span></td>
                    <td className="dot"><span className="on">●</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                  <tr>
                    <td className="cap">False positives triaged out</td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot"><span className="on">●</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                  <tr>
                    <td className="cap">Fixes named, not just flagged</td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot"><span className="on">●</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                  <tr className="grp">
                    <td colSpan={4}>Reads your production database</td>
                  </tr>
                  <tr>
                    <td className="cap">Live database + Supabase advisors + migration drift</td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot"><span className="on">●</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                  <tr>
                    <td className="cap">PII protection verified in production</td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot"><span className="on">●</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                  <tr className="grp">
                    <td colSpan={4}>Stands up &amp; attacks your app</td>
                  </tr>
                  <tr>
                    <td className="cap">Cross-tenant access proven on a live stack</td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                  <tr>
                    <td className="cap">Points out tests that pass even when the code is broken</td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                  <tr>
                    <td className="cap">Auth, endpoint &amp; service-seam attacks</td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot"><span className="off">—</span></td>
                    <td className="dot feat"><span className="on">●</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">Pricing questions</span>
            <h2>Straight answers.</h2>
          </div>
          <div className="wrap">
            <div className="faq">
              <div className="faq-item">
                <h3>How is my codebase size measured?</h3>
                <p>
                  Automatically, during the free scan — lines of application code, with generated and vendored code
                  excluded (our dead-code and duplication modules already detect it). The free scan doubles as an instant,
                  transparent quote for the paid tiers.
                </p>
              </div>
              <div className="faq-item">
                <h3>What if I decline database access on a paid tier?</h3>
                <p>
                  The database-dependent checks record &quot;not run — no access&quot; in the coverage ledger, on-brand,
                  and the rest of the audit still runs. You&apos;re never charged for a check we couldn&apos;t perform.
                </p>
              </div>
              <div className="faq-item">
                <h3>Is the small-tier Full audit a real pentest?</h3>
                <p>
                  It&apos;s a genuine audit of a small app, and the Full tier does run a live pen-test on a copy of your
                  stack. We keep the language honest: a small MVP is scoped-small, so it sits alongside the
                  $1,500–$5,000 source-review audits rather than a formal enterprise pentest — the difference being
                  that those are source-only, and this one actually runs. If you need a compliance letter, we&apos;ll
                  point you to a pentest firm for that specifically.
                </p>
              </div>
              <div className="faq-item">
                <h3>Are these prices final?</h3>
                <p>
                  These are launch anchors. Exact price points are being validated against real engagements; the grid is
                  the honest starting point, not a placeholder for a bigger number revealed on a call.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="final">
          <div className="wrap">
            <span className="eyebrow" style={{ justifyContent: "center" }}>
              Start free
            </span>
            <h2 style={{ marginTop: "16px" }}>The free scan is also your quote.</h2>
            <div className="hero-cta">
              <Link href="/#scan" className="btn btn-primary">
                Run the free scan →
              </Link>
              <a href="/the-audit" className="btn btn-ghost">
                How the audit works
              </a>
            </div>
            <p className="trust">Source-only, no credentials — and it measures your size to quote the paid tiers.</p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
