import type { Metadata } from "next";
import Link from "next/link";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

export const metadata: Metadata = {
  title: "Data Handling — Harvey",
  description:
    "What Harvey does with your repo and database access: read-only by default, no production contact on the free scan, local-only stand-up for the pen-test, and clear retention and deletion commitments.",
  alternates: { canonical: "/data-handling" },
  openGraph: {
    title: "Data Handling — Harvey",
    description: "Read-only by default. No production contact on the free scan. Clear retention and deletion.",
    url: "https://harvey-qa.com/data-handling",
    type: "article",
  },
};

export default function DataHandling() {
  return (
    <>
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <Link href="/">Harvey</Link> / Data handling
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Trust &amp; ethics
            </span>
            <h1>What Harvey does with your access.</h1>
            <p className="lede">
              An audit means handing an outsider your code, and sometimes a read of your data. That only works on trust,
              and trust needs specifics. Here is exactly what each tier can touch, what we keep, and how to get it
              deleted.
            </p>
            <p className="policy-meta">Last updated: 2026-07-22</p>
          </div>
        </div>

        <section>
          <div className="wrap">
            <div className="answer-first">
              The free scan needs only read access to your source — no database, no credentials, no contact with your
              production environment. Paid tiers add a <b>read-only</b> connection to your database; nothing Harvey does
              writes to, modifies, or takes your production systems offline. The live pen-test runs against a copy Harvey
              stands up on its own machines, never against your production.
            </div>

            <div className="prose" style={{ marginTop: "34px" }}>
              <h2>Access by tier</h2>
              <p>Access rises with the tier, and never beyond what the tier needs:</p>
              <ul>
                <li>
                  <b>Free scan — source only.</b> You give us read access to your repository (or a code archive). No
                  database, no API keys, no production contact. We read the code; that&apos;s all.
                </li>
                <li>
                  <b>Connected audit — adds a read-only database connection.</b> To verify live state (RLS behavior,
                  Supabase advisors, drift between your deployed schema and your committed migrations, PII protection)
                  we connect to your database <b>read-only</b>.
                  We run queries that read; we never write, alter schema, or change data. If you decline this access, the
                  database-dependent checks are recorded as &quot;not run — no access&quot; in your coverage ledger and
                  the rest of the audit still runs.
                </li>
                <li>
                  <b>Full audit — adds a local stand-up.</b> The live pen-test needs a running app to attack, so Harvey
                  provisions <b>its own local copy</b> of your stack from your code and migrations, seeds test data, and
                  attacks that copy. Your production environment is never stood up, never attacked, and never contacted.
                </li>
              </ul>

              <h2>What we collect, and why</h2>
              <ul>
                <li>
                  <b>Your source code</b> — to run the audit. Held only for the duration of the engagement.
                </li>
                <li>
                  <b>Read-only database output</b> (connected tier) — the results of the read-only checks, not a copy of
                  your whole database. We pull what the specific checks need, not a bulk export.
                </li>
                <li>
                  <b>Your contact details and what you told us</b> (email, repo, any context) when you request a scan —
                  to run the scan and get the report back to you.
                </li>
              </ul>
              <p>
                We do not use your code or data to train models, we do not sell it, and we do not share it with any third
                party outside the tightly-scoped service providers below.
              </p>

              <h2>Findings are built to avoid your raw data in the first place</h2>
              <p>
                Two of Harvey&apos;s checks touch the kind of data you&apos;d most want handled carefully, and both are
                built to minimize what they retain:
              </p>
              <ul>
                <li>
                  <b>Data classification (PII/PHI/PCI).</b> By default this check looks at column <i>names, types, and
                  table context</i> — it never reads or stores actual cell values, and the finding it produces records
                  only the column name and inferred category (e.g. &quot;<code>email</code> — PII, high confidence&quot;),
                  never real customer data. A deeper mode that samples real values to classify free-text or generic
                  columns exists as a design only — we have deliberately not built it until there is a clear consent
                  model for sampling your data, so it cannot run against your engagement today.
                </li>
                <li>
                  <b>Credential/secret scanning.</b> When a check finds something that looks like a live credential, the
                  finding stores a redacted excerpt (a short prefix plus a length, e.g.{" "}
                  <code>sk_live_51Q…[redacted, 44 chars]</code>) — enough to confirm and locate the match, never the
                  usable secret itself.
                </li>
              </ul>

              <h2>Where it lives</h2>
              <p>
                Scan requests are delivered to us by email through <b>Resend</b>, our transactional email provider. The
                audit itself runs on controlled machines under our operator&apos;s direct control. The list of
                sub-processors is small and will be published here as it is finalized; today it is the email provider
                (Resend) and the site host (Vercel). We will not add a sub-processor that receives your code or data
                without updating this page.
              </p>

              <h2>Retention and deletion</h2>
              <ul>
                <li>
                  <b>During the engagement</b> we hold your code and any read-only results only as long as needed to
                  produce and deliver the report.
                </li>
                <li>
                  <b>After delivery</b> our default is to delete the working copy of your code and any database output
                  once the report is delivered and the engagement is closed, retaining only the finished report and
                  routine business records.
                </li>
                <li>
                  <b>On request</b> you can ask us to delete everything we hold about your engagement, including the
                  finished report and your intake details, and we will confirm when it is done.
                </li>
              </ul>
              <p>
                The exact default retention period is being finalized alongside our engagement terms; until it is
                published here, treat &quot;deleted on engagement close unless you ask us to keep the report&quot; as the
                operating commitment.
              </p>

              <h2>Read-only, and reversible</h2>
              <p>
                Every database interaction on the paid tiers is read-only by design. Nothing Harvey runs will write to
                your data, change your schema, or take a system offline. You can revoke any access you granted the moment
                the engagement ends — and we recommend you do.
              </p>

              <div className="notice">
                <b>Operator / legal review pending.</b> This page describes how Harvey operates and its intended
                commitments. It is not the binding contract. The formal engagement terms, liability terms, and
                data-processing agreement are being prepared as part of setting up the business entity, and will govern
                where they differ. This page will link to them once they exist.
              </div>
            </div>

            <div className="cta-band">
              <div>
                <h3>Questions before you grant access?</h3>
                <p>Start with the free scan — it needs nothing but read access to your code, so you can see the work before deciding on anything deeper.</p>
              </div>
              <div className="btns">
                <Link href="/#scan" className="btn btn-primary">
                  Run the free scan
                </Link>
                <a href="/responsible-disclosure" className="btn btn-ghost">
                  Responsible disclosure
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
