import type { Metadata } from "next";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

export const metadata: Metadata = {
  title: "Responsible Disclosure — Harvey",
  description:
    "How Harvey handles security findings it discovers in others' code: private-first disclosure, coordinated timelines, aggregate-only research, and never publishing an exploitable detail against an identifiable app.",
  alternates: { canonical: "/responsible-disclosure" },
  openGraph: {
    title: "Responsible Disclosure — Harvey",
    description: "Private-first, coordinated, aggregate-only. How Harvey handles the vulnerabilities it finds.",
    url: "https://harvey-qa.com/responsible-disclosure",
    type: "article",
  },
};

export default function ResponsibleDisclosure() {
  return (
    <>
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <a href="/">Harvey</a> / Responsible disclosure
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Trust &amp; ethics
            </span>
            <h1>Responsible disclosure.</h1>
            <p className="lede">
              Harvey&apos;s job is to find serious flaws in software. Finding them creates a duty to handle them
              carefully — for our clients and for anyone whose data those flaws could expose. This is how we do that.
            </p>
            <p className="policy-meta">Last updated: 2026-07-22</p>
          </div>
        </div>

        <section>
          <div className="wrap">
            <div className="answer-first">
              Harvey discloses vulnerabilities privately first, gives the owner reasonable time to fix, and never
              publishes an exploitable detail against an identifiable app. Any public research reports aggregate,
              anonymized numbers — never a working exploit tied to a named product.
            </div>

            <div className="prose" style={{ marginTop: "34px" }}>
              <h2>Findings in a client&apos;s own code</h2>
              <p>
                When you engage Harvey, everything we find is <b>yours</b>. We deliver findings privately to you and only
                you. We do not publish, sell, share, or disclose them to any third party. What you do with a finding —
                fix it, accept the risk, ignore it — is your decision. Our data-retention and access commitments for
                engagement material are covered on the <a href="/data-handling">Data Handling</a> page.
              </p>

              <h2>Findings in code we were not engaged to audit</h2>
              <p>
                Some of Harvey&apos;s work looks outward — for example, research that scans publicly available
                AI-generated apps to understand how common a class of flaw is. When that work surfaces a real,
                exploitable vulnerability in an app we can identify, we follow coordinated disclosure:
              </p>
              <ol>
                <li>
                  <b>Notify privately first.</b> We contact the owner through a reasonable channel (a published security
                  contact, <code>security.txt</code>, or the most direct contact we can find) before telling anyone
                  else.
                </li>
                <li>
                  <b>Give reasonable time to remediate.</b> Our default window is <b>90 days</b> from first contact
                  before any public mention, shorter only if the flaw is being actively exploited, and extendable by
                  agreement if a fix is genuinely in progress.
                </li>
                <li>
                  <b>Withhold exploit detail.</b> We never publish a working exploit, a proof-of-concept, or reproduction
                  steps tied to an identifiable app — not before a fix, and not after.
                </li>
                <li>
                  <b>Prefer no attribution.</b> Public write-ups describe the class of flaw, not the victim. We do not
                  name an affected app without its owner&apos;s explicit permission.
                </li>
              </ol>

              <h2>Research reports</h2>
              <p>
                When Harvey publishes aggregate research (&quot;we looked at N apps and found X% had a given problem&quot;),
                the report contains <b>only aggregate, anonymized figures</b>. No individual app is named, no dataset of
                vulnerable targets is released, and no finding is described in a way that would let a reader locate or
                exploit a specific app. If a specific app in the sample has a serious live flaw, we follow the private
                disclosure steps above <i>before</i> the research is published — not after.
              </p>

              <h2>What we ask in return</h2>
              <p>
                If you receive a disclosure from Harvey, please acknowledge it and let us know your remediation timeline.
                We are not looking for a bounty and we are not trying to embarrass anyone — we would rather the flaw
                quietly get fixed. If you believe a report is mistaken, tell us; we would rather correct the record than
                be wrong in public.
              </p>

              <h2>Reporting a vulnerability to us</h2>
              <p>
                If you find a security issue in Harvey&apos;s own site or tooling, we want to hear about it. Report it
                privately and give us reasonable time to fix it before disclosing publicly, and we will do the same
                courtesy in reverse. A dedicated security contact address is being finalized; until it is published
                here, use the contact route on the site and mark it &quot;security.&quot;
              </p>
              <p>
                <b>Scope.</b> In scope: the <code>harvey-qa.com</code> marketing/scan-request site and Harvey&apos;s
                publicly available scanning tooling. Out of scope: any client&apos;s codebase, infrastructure, or data
                that Harvey has accessed as part of an engagement — that belongs to the client, and a report about it
                should go to the client directly, not to us. Also out of scope: automated volume scanning that degrades
                the site for other visitors, and any form of social engineering against our operator.
              </p>
              <p>
                <b>Safe harbor.</b> We will not pursue legal action against a good-faith researcher who stays within
                this scope, avoids privacy violations, data destruction, and service disruption, and reports what they
                find privately before any public disclosure. We ask for the same coordinated-disclosure courtesy
                described above in return.
              </p>
              <p>
                <b>Response time.</b> Our target is to acknowledge a report within <b>5 business days</b>. We are a
                small operation, so this is a target, not a guaranteed SLA, and it is one of the items awaiting
                operator confirmation below.
              </p>
              <div className="notice">
                <b>Operator / legal review pending.</b> This policy describes how Harvey intends to operate and reflects
                standard coordinated-disclosure practice. It is not a contract and has not been reviewed by counsel. The
                security contact address, the acknowledgment-time target, and the final disclosure window are subject
                to confirmation before launch.
              </div>
            </div>

            <div className="cta-band">
              <div>
                <h3>Coverage honesty is the brand.</h3>
                <p>The same discipline that makes us careful with disclosures is why every report shows what we didn&apos;t check.</p>
              </div>
              <div className="btns">
                <a href="/data-handling" className="btn btn-ghost">
                  Data handling
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
