import type { Metadata } from "next";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";
import { sampleMeta, sampleCounts, sampleFindings, sampleLedger } from "./sample-data";

export const metadata: Metadata = {
  title: "Sample report — what a Harvey audit looks like",
  description:
    "A full sample Harvey audit report: the readiness verdict, findings ranked by blast radius across all ten modules, each with evidence and a named fix, and the coverage ledger showing what ran and what didn't. Synthetic demonstration data.",
  alternates: { canonical: "/sample-report" },
  openGraph: {
    title: "Sample report — what a Harvey audit looks like",
    description: "The readiness verdict, ranked findings with named fixes, and the coverage ledger. Synthetic demo data.",
    url: "https://harvey-qa.com/sample-report",
    type: "article",
  },
};

export default function SampleReport() {
  return (
    <>
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <a href="/">Harvey</a> / Sample report
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              What you get
            </span>
            <h1>A Harvey report, front to back.</h1>
            <p className="lede">
              Every finding in plain English, ranked by blast radius, each with where it is, why it matters, and how to
              fix it — plus the coverage ledger that tells you what we didn&apos;t check. This is the shape of what lands
              in your inbox.
            </p>
            <div style={{ marginTop: "22px" }}>
              <span className="sample-banner">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
                </svg>
                Sample — synthetic data for a fictional app (&quot;Larkspur&quot;). Not a real client&apos;s codebase.
              </span>
            </div>
          </div>
        </div>

        <section>
          <div className="wrap">
            <div className="report-cover">
              <div className="rc-top">
                <div>
                  <div className="lbl">Readiness report</div>
                  <div className="client">{sampleMeta.client}</div>
                  <div className="sub">
                    {sampleMeta.subtitle} · {sampleMeta.tier} · {sampleMeta.size}
                  </div>
                </div>
                <div className="rc-verdict">
                  <div className="lbl">Verdict</div>
                  <div className="grade" style={{ marginTop: "6px" }}>
                    {sampleMeta.verdict}
                  </div>
                </div>
              </div>
              <div className="rc-headline">{sampleMeta.headline}</div>
              <div className="rc-counts">
                {sampleCounts.map((c) => (
                  <div className={`rc-count ${c.cls}`} key={c.label}>
                    <div className="cn">{c.n}</div>
                    <div className="cl">{c.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">Findings · ranked by blast radius</span>
            <h2>Every finding, with the fix.</h2>
            <p>
              Ordered by what matters for this app, not by module. Critical and High first — the things to fix before
              scaling — then the hardening, test-quality, and maintainability wins.
            </p>
          </div>
          <div className="wrap">
            {sampleFindings.map((f) => (
              <article className="finding" key={f.id}>
                <div className="fh">
                  <span className={`sev ${f.severity}`}>{f.severity}</span>
                  <span className="fid">{f.id}</span>
                  <span className="fmod">{f.module}</span>
                </div>
                <h3>{f.title}</h3>
                <p className="loc">{f.location}</p>
                <dl>
                  <div>
                    <dt>Evidence</dt>
                    <dd>{f.evidence}</dd>
                  </div>
                  <div>
                    <dt>Impact</dt>
                    <dd>{f.impact}</dd>
                  </div>
                  <div>
                    <dt>Fix</dt>
                    <dd className="fix">{f.fix}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        </section>

        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">No silent gaps</span>
            <h2>The coverage ledger.</h2>
            <p>
              Ten modules, each with its status and — where it couldn&apos;t fully run — the reason. On this sample, M10
              ran on the schema but the live PII-grant check is still pending the client&apos;s database sign-off, so
              it&apos;s marked partial rather than dropped.
            </p>
          </div>
          <div className="wrap narrow">
            <div className="ledger">
              {sampleLedger.map((l) => (
                <div className="ledger-row" key={l.module}>
                  <span className="m">{l.module}</span>
                  <span className="why">{l.why}</span>
                  <span className={`pill ${l.status === "ran" ? "ran" : "part"}`}>
                    {l.status === "ran" ? "Ran" : "Partial"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="final">
          <div className="wrap">
            <span className="eyebrow" style={{ justifyContent: "center" }}>
              Get yours
            </span>
            <h2 style={{ marginTop: "16px" }}>Want this for your codebase?</h2>
            <p style={{ color: "var(--muted)", fontSize: "17px", maxWidth: "560px", margin: "14px auto 0" }}>
              The free scan returns a real ten-module report on your source — same shape, your findings. Point us at your
              repo and we&apos;ll send it within one business day.
            </p>
            <div className="hero-cta">
              <a href="/#scan" className="btn btn-primary">
                Run the free scan →
              </a>
              <a href="/the-audit" className="btn btn-ghost">
                How the audit works
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
