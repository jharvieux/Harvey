import type { Metadata } from "next";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

export const metadata: Metadata = {
  title: "Why do you keep fixing the same three files?",
  description:
    "A small number of files hold most of your bug risk, one copy of a fix rarely reaches the other copies, and nothing catches the regression when it returns. Why the same modules keep breaking — and how to find yours before the next release does.",
  alternates: { canonical: "/re-fixing-the-same-files" },
  keywords: [
    "why do i keep fixing the same bug",
    "code hotspots",
    "technical debt hotspots",
    "code churn complexity",
    "same bug keeps coming back",
  ],
  openGraph: {
    title: "Why do you keep fixing the same three files?",
    description: "A small number of files hold most of your bug risk — and one copy of a fix rarely reaches the other copies.",
    url: "https://harvey-qa.com/re-fixing-the-same-files",
    type: "article",
  },
};

const articleJsonLd = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "Why do you keep fixing the same three files?",
  description:
    "A small number of files hold most of your bug risk, one copy of a fix rarely reaches the other copies, and nothing catches the regression when it returns.",
  author: { "@type": "Organization", name: "Harvey" },
  publisher: { "@type": "Organization", name: "Harvey" },
  mainEntityOfPage: "https://harvey-qa.com/re-fixing-the-same-files",
};

export default function ReFixingPillar() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(articleJsonLd) }} />
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <a href="/">Harvey</a> / Re-fixing the same files
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              The re-fixing trap
            </span>
            <h1>Why do you keep fixing the same three files?</h1>
            <div className="answer-first" style={{ marginTop: "22px" }}>
              Because bug risk in most codebases is not spread evenly — a small number of files concentrate most of it,
              a fix applied to one copy of duplicated logic frequently misses the others, hand-rolled code in that area
              keeps inviting new mistakes, and no test catches the regression before it ships again. It is rarely bad
              luck. It is almost always the same handful of files, for reasons you can name.
            </div>
          </div>
        </div>

        <section>
          <div className="wrap">
            <div className="prose">
              <h2>The pain this is for</h2>
              <p>
                &quot;Every change to this part breaks something.&quot; &quot;I fixed this bug last month and it&apos;s
                back.&quot; &quot;One area of the app eats all my time, and I don&apos;t know why.&quot; Nobody searches
                for &quot;churn times complexity&quot; — but almost every founder running a fast-moving codebase has
                felt this exact pattern, usually without being able to point at the specific files causing it.
              </p>

              <h2>Why it&apos;s always the same three files</h2>
              <p>
                Four separate mechanisms compound on each other, and they tend to stack in the same few files rather
                than spreading out:
              </p>
              <h3>1. Hotspots: complexity and change collide</h3>
              <p>
                A file that is both complex (deep nesting, many branches, many responsibilities) and frequently changed
                is a hotspot — every edit has more ways to go wrong, and it gets edited more often than anywhere else.
                Ranking files by churn × complexity finds the small set that concentrates most of a codebase&apos;s bug
                risk, instead of treating every file as an equal suspect.
              </p>
              <h3>2. Duplication: you fixed one copy</h3>
              <p>
                Logic that was copy-pasted instead of shared drifts out of sync. A bug fix lands in the copy someone
                remembered to edit; the other copies keep the old, broken behavior — so the &quot;same&quot; bug
                reappears somewhere that was never actually touched.
              </p>
              <h3>3. Maintainability: fragile hand-rolled code invites the next bug</h3>
              <p>
                Hand-rolled auth, ad-hoc parsing, and other reinvented-wheel code tends to cluster in the same files as
                the hotspots above, and it is disproportionately fragile — a small change nearby has more ways to break
                it than code built on a standard, well-tested pattern.
              </p>
              <h3>4. Test quality: nothing catches it coming back</h3>
              <p>
                A regression returns silently when the tests around that file don&apos;t actually exercise the failure
                path. A green suite that never runs the code that broke — or asserts nothing meaningful when it does —
                is worse than no suite at all, because it&apos;s trusted.
              </p>

              <h2>A quick self-audit</h2>
              <ul>
                <li>Can you name, right now, the one or two files every recent bugfix has touched?</li>
                <li>When you last fixed a bug, did you check whether the same logic was copy-pasted anywhere else?</li>
                <li>Is there a part of the app new contributors are told to &quot;be careful around&quot;?</li>
                <li>Does that area have hand-rolled logic where a standard library or pattern would do?</li>
                <li>If you reintroduced last month&apos;s bug on purpose, would a test actually fail?</li>
                <li>Have you ever ranked files by how often they change AND how complex they are — together?</li>
              </ul>
              <p>
                This is the felt version of the entire code-health half of Harvey&apos;s audit in one pain: Hotspots
                (M3) ranks files by churn × complexity, Duplication (M4) finds the copies a fix missed, Maintainability
                (M6) flags the fragile hand-rolled code sitting in those same files, and Test quality (M8) runs mutation
                testing — deliberately breaking your code — to report which of your tests would actually catch the
                regression coming back.
              </p>
            </div>

            <div className="cta-band">
              <div>
                <h3>Find the files causing most of your bugs.</h3>
                <p>The free scan ranks your codebase by churn × complexity and flags the duplication and fragile code sitting in the same files — no database access needed.</p>
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
