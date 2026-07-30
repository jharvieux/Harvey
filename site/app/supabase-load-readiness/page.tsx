import type { Metadata } from "next";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

export const metadata: Metadata = {
  title: "Is your Supabase + Next.js app ready for the traffic spike?",
  description:
    "Before you launch, run an ad campaign, or hit a seasonal surge: the N+1 queries, missing indexes, and connection-pool limits that work fine at 20 users and fall over at 2,000 — and how to find them before launch day does.",
  alternates: { canonical: "/supabase-load-readiness" },
  keywords: [
    "supabase load testing",
    "is my app ready for launch traffic",
    "supabase app slow",
    "next.js app slow",
    "scalability audit before launch",
  ],
  openGraph: {
    title: "Is your Supabase + Next.js app ready for the traffic spike?",
    description: "The queries and indexes that work at 20 users and fall over at 2,000 — found before launch day does.",
    url: "https://harvey-qa.com/supabase-load-readiness",
    type: "article",
  },
};

const articleJsonLd = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "Is your Supabase + Next.js app ready for the traffic spike?",
  description:
    "The N+1 queries, missing indexes, and connection-pool limits that work fine at 20 users and fall over at 2,000 — and how to find them before launch day does.",
  author: { "@type": "Organization", name: "Harvey" },
  publisher: { "@type": "Organization", name: "Harvey" },
  mainEntityOfPage: "https://harvey-qa.com/supabase-load-readiness",
};

export default function LoadReadinessPillar() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(articleJsonLd) }} />
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <a href="/">Harvey</a> / Load-readiness check
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Before launch day
            </span>
            <h1>Is your Supabase + Next.js app ready for the traffic spike?</h1>
            <div className="answer-first" style={{ marginTop: "22px" }}>
              Almost always, no — not because the app is broken, but because nothing has ever asked it to do more than
              one developer&apos;s worth of traffic. The queries, indexes, and connection limits that feel instant at 20
              users are frequently the exact things that time out at 2,000. If you have a launch date, an ad spend, or
              a seasonal surge already on the calendar, that is the moment to find out — not the moment you find out.
            </div>
          </div>
        </div>

        <section>
          <div className="wrap">
            <div className="prose">
              <h2>The moment this is for</h2>
              <p>
                You&apos;re about to do something that concentrates traffic into a short window: launch publicly, run a
                paid campaign, post to Product Hunt or Hacker News, or hit a seasonal surge (Black Friday, back-to-school,
                a partner&apos;s newsletter). A date — and often a spend — is already committed. A load-readiness check is
                cheap insurance against that spend buying you a support queue full of timeouts instead of customers.
              </p>

              <h2>Why it works at 20 users and falls over at 2,000</h2>
              <p>
                None of this shows up in normal development, because normal development never has enough rows or enough
                concurrent requests to trigger it:
              </p>
              <h3>1. N+1 queries</h3>
              <p>
                A list page fetches its rows, then issues one more query per row inside the render loop — a related
                record, a lookup, a count. At 20 rows that&apos;s 20 extra queries and nobody notices. At 2,000 rows it&apos;s
                2,000 queries on one page load, and the page times out.
              </p>
              <h3>2. Missing indexes</h3>
              <p>
                Supabase does not index foreign keys automatically. A filter or join on an unindexed column does a full
                table scan — trivial at a few hundred rows, and the first thing to blow your query budget once a table
                has real volume.
              </p>
              <h3>3. Row-Level Security evaluated per row</h3>
              <p>
                An RLS policy that calls <code>auth.uid()</code> directly gets re-evaluated once per row scanned. On a
                100,000-row table that&apos;s 100,000 evaluations for one query — invisible in a demo, expensive under load.
              </p>
              <h3>4. Connection-pool exhaustion</h3>
              <p>
                Serverless functions that open a fresh Postgres connection per request exhaust Supabase&apos;s connection
                limit under concurrency long before CPU or memory become the bottleneck — a spike-traffic failure mode
                that a single-user load test cannot reproduce.
              </p>
              <h3>5. Unbounded selects and overfetching</h3>
              <p>
                A query with no <code>.limit()</code>, or a client component fetching an entire table to filter it in the
                browser, scales the response payload — and the egress bill — linearly with data size instead of with
                what the page actually renders.
              </p>

              <h2>A quick self-audit</h2>
              <ul>
                <li>Does any list page issue a query inside a loop over another query&apos;s results?</li>
                <li>Do your foreign-key and filter columns have indexes — checked, not assumed?</li>
                <li>Do your RLS policies wrap <code>auth.uid()</code> in a subquery, or call it per row?</li>
                <li>Are Postgres connections pooled (PgBouncer / Supabase&apos;s pooler), not opened per request?</li>
                <li>Does every list query have a <code>.limit()</code>, or does it hand the client the whole table?</li>
                <li>Have you tested any of the above at 10× your current data volume, not just today&apos;s?</li>
              </ul>
              <p>
                These are exactly the classes Harvey&apos;s Performance module (M7) flags on your source, cross-referenced
                against the Hotspots module (M3) so the ones sitting in your most complex, most-changed code are ranked
                first — the files most likely to be touched, and to break, right before launch.
              </p>
            </div>

            <div className="cta-band">
              <div>
                <h3>Know what breaks before launch day does.</h3>
                <p>The free scan flags N+1s, missing indexes, and unbounded selects on your source — no database access needed.</p>
              </div>
              <div className="btns">
                <a href="/#scan" className="btn btn-primary">
                  Run the free scan →
                </a>
                <a href="/the-audit" className="btn btn-ghost">
                  How the audit works
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
