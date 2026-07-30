"use client";

import { useEffect, useState } from "react";
import SiteHeader from "./components/SiteHeader";
import SiteFooter from "./components/SiteFooter";
import { SUPPORT_EMAIL } from "./lib/constants";

type Status = "crit" | "rev" | "pass";

const SCORECARD: { n: string; mod: string; fnd: string; st: Status; label: string }[] = [
  { n: "01", mod: "Access control & data security", fnd: "user can read others' private data", st: "crit", label: "Critical" },
  { n: "02", mod: "Live pen-test", fnd: "boundary crossed, 2 tenants", st: "crit", label: "Critical" },
  { n: "03", mod: "Hotspots", fnd: "3 files hold 60% of churn", st: "rev", label: "Review" },
  { n: "04", mod: "Duplication", fnd: "8% duplicated logic", st: "rev", label: "Review" },
  { n: "05", mod: "Dead code", fnd: "14 unused exports", st: "pass", label: "Clean" },
  { n: "06", mod: "Maintainability", fnd: "hand-rolled auth, use a library", st: "rev", label: "Review" },
  { n: "07", mod: "Performance", fnd: "2 N+1 queries, 1 missing index", st: "crit", label: "Critical" },
  { n: "08", mod: "Test quality", fnd: "41% of tests can't actually fail", st: "rev", label: "Review" },
  { n: "09", mod: "Server→client boundaries", fnd: "server env reachable from client", st: "rev", label: "Review" },
  { n: "10", mod: "Data classification", fnd: "PII in 3 unprotected columns", st: "rev", label: "Review" },
];

const MODULES: { n: string; h: string; p: string }[] = [
  { n: "01", h: "Access control & data security", p: "Who can read and write what — auth boundaries, RLS, and cross-tenant isolation for multi-tenant apps." },
  { n: "02", h: "Live pen-test", p: "A real attack on a live copy of your stack." },
  { n: "03", h: "Hotspot analysis", p: "Where complexity and change collide." },
  { n: "04", h: "Duplication", p: "Copy-pasted logic that drifts out of sync." },
  { n: "05", h: "Dead code", p: "What's shipped but never runs." },
  { n: "06", h: "Maintainability", p: "Hand-rolled code with a better replacement." },
  { n: "07", h: "Performance", p: "N+1 queries, missing indexes, Core Web Vitals." },
  { n: "08", h: "Test quality", p: "Which of your tests can't actually catch a bug." },
  { n: "09", h: "Server→client boundaries", p: "Server→client leaks, server-action auth. Next.js, Remix, React Router 7, TanStack Start." },
  { n: "10", h: "Data classification", p: "Every piece of PII / PHI / PCI, and where it lives." },
];

function Check() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

const capStyle = { color: "var(--faint)", fontSize: "14px", margin: "16px 0 0", fontFamily: "var(--mono)" } as const;

export default function Home() {
  const [mounted, setMounted] = useState(false);

  const [form, setForm] = useState({ email: "", repo: "", context: "" });
  const [status, setStatus] = useState<"idle" | "submitting" | "ok" | "error">("idle");
  const [errMsg, setErrMsg] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus("submitting");
    setErrMsg("");
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (res.ok) {
        setStatus("ok");
      } else {
        const d = (await res.json().catch(() => ({}))) as { error?: string };
        setErrMsg(d.error || `Something went wrong. Please try again or email us at ${SUPPORT_EMAIL}.`);
        setStatus("error");
      }
    } catch {
      setErrMsg(`Network error. Please try again or email us at ${SUPPORT_EMAIL}.`);
      setStatus("error");
    }
  };

  useEffect(() => setMounted(true), []);

  return (
    <>
      <SiteHeader />

      <main>
        {/* HERO */}
        <div className="hero">
          <div className="wrap hero-grid">
            <div>
              <span className="eyebrow">Codebase QA for AI-generated apps</span>
              <h1>
                The QA leader your codebase <em>never had.</em>
              </h1>
              <p className="lede">
                Harvey checks your whole app — security, tests, performance, data, maintainability — and hands you
                one readiness verdict you can act on. It&apos;s the senior quality review you can&apos;t yet justify
                hiring for.
              </p>
              <div className="hero-cta">
                <a href="#scan" className="btn btn-primary">
                  Run the free scan →
                </a>
                <a href="/sample-report" className="btn btn-ghost">
                  See a sample report
                </a>
              </div>
              <p className="trust">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                No database, no credentials, no production contact. Just point us at your repo.
              </p>
            </div>

            {/* the thesis: one readiness verdict across the whole codebase */}
            <figure className="scorecard" style={{ margin: 0 }}>
              <div className="sc-top">
                <div>
                  <div className="lbl">Readiness report</div>
                  <div className="repo">your-saas · main</div>
                </div>
                <div className="sc-verdict">
                  <span className="lbl">Verdict</span>
                  <span className="grade">Not ready to scale</span>
                </div>
              </div>
              <div className="sc-list">
                {SCORECARD.map((r, i) => (
                  <div
                    key={r.n}
                    className={`sc-row${mounted ? " in" : ""}`}
                    style={{ transitionDelay: `${i * 90}ms` }}
                  >
                    <span className="n">{r.n}</span>
                    <span>
                      <span className="mod">{r.mod}</span>
                      <span className="fnd">{r.fnd}</span>
                    </span>
                    <span className={`st ${r.st}`}>{r.label}</span>
                  </div>
                ))}
              </div>
            </figure>
          </div>
        </div>

        {/* PROBLEM */}
        <section>
          <div className="wrap narrow sec-head">
            <span className="eyebrow">Why this matters</span>
            <h2>You shipped fast. Do you actually know what you shipped?</h2>
            <p>
              No QA team, no senior lead reviewing every merge — just you and an AI that says the code it generated is
              fine. The result is a codebase you can&apos;t see the true state of: which tests can&apos;t catch a bug,
              where the data&apos;s exposed, what falls over at scale.
            </p>
          </div>
          <div className="wrap narrow">
            <p style={{ color: "var(--muted)", fontSize: "17px", margin: 0 }}>
              Most founders find out the hard way. To take one example: when researchers reviewed public apps built
              with AI tools, roughly <b style={{ color: "var(--text)" }}>one in ten was exposing user data</b> — a
              blind spot no one on the team could see. Shipping fast was the right call. Harvey shows you the real
              state of what you built — before it costs you.
            </p>
            <p className="cite-note">
              Security researchers who scanned 1,645 AI-built apps found roughly 1 in 10 exposing user data —{" "}
              <a href="https://nvd.nist.gov/vuln/detail/CVE-2025-48757" target="_blank" rel="noopener noreferrer">
                CVE-2025-48757
              </a>
              .
            </p>
          </div>
        </section>

        {/* DIFFERENTIATION */}
        <section id="audit">
          <div className="wrap sec-head">
            <span className="eyebrow">One audit vs. ten tools</span>
            <h2>A scanner gives you noise. Harvey gives you a verdict.</h2>
            <p>
              You could buy a security scanner, a coverage tool, a perf monitor, and a linter — and still not know if
              you&apos;re ready. Harvey is the senior read that runs all of it and tells you what actually matters for{" "}
              <i>your</i> app.
            </p>
          </div>
          <div className="wrap cols">
            <div className="card">
              <h3>
                <span className="ic">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                    <path d="M3 3v18h18M7 14l3-3 3 3 5-6" />
                  </svg>
                </span>
                The whole picture
              </h3>
              <p>
                Ten dimensions in one audit — security, tests, performance, data, maintainability — rolled into a
                single readiness verdict, not ten disconnected dashboards.
              </p>
            </div>
            <div className="card">
              <h3>
                <span className="ic">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                    <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" />
                    <path d="M9 12l2 2 4-4" />
                  </svg>
                </span>
                Judgment, not alerts
              </h3>
              <p>
                Ranked by what matters for your codebase — a senior read, not four thousand linter warnings
                you&apos;ll ignore. Every finding comes with the fix.
              </p>
            </div>
            <div className="card">
              <h3>
                <span className="ic">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                    <path d="M13 2 3 14h7l-1 8 10-12h-7z" />
                  </svg>
                </span>
                We prove it, live
              </h3>
              <p>
                Where it counts, we don&apos;t just flag — we stand up a copy of your stack and prove it. A
                cross-tenant leak isn&apos;t a warning; it&apos;s the row we shouldn&apos;t have been able to read.
              </p>
            </div>
          </div>
        </section>

        {/* COMPARE */}
        <section>
          <div className="wrap narrow sec-head">
            <span className="eyebrow">Tools vs. a leader</span>
            <h2>Everything your tools do — plus what they can&apos;t.</h2>
            <p>
              Most teams already run these. Harvey covers all of it in one audit — then answers the questions none of
              them can.
            </p>
          </div>
          <div className="wrap">
            <div className="table-scroll">
              <table className="cmp">
                <thead>
                  <tr>
                    <th>Your tools</th>
                    <th>What it does</th>
                    <th className="c">Harvey</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Snyk</td>
                    <td>Known-CVE scanning in your dependencies</td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>Dependabot</td>
                    <td>Flags vulnerable dependencies &amp; names the upgrade</td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>ESLint</td>
                    <td>Static analysis of your source for code defects</td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>SonarQube</td>
                    <td>Code smells, duplication &amp; coverage</td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>CodeRabbit</td>
                    <td>AI review of the code your AI wrote</td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p style={capStyle}>That&apos;s the floor — Harvey does all of it. Then it does what none of them can:</p>
            <div className="table-scroll">
              <table className="cmp">
                <thead>
                  <tr>
                    <th>Question about your codebase</th>
                    <th className="c">Tools</th>
                    <th className="c">Harvey</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Which of my tests can&apos;t actually catch a bug?</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>Can one user read another&apos;s private data?</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span> proven live</td>
                  </tr>
                  <tr>
                    <td>What will fall over when traffic scales?</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>Where is unprotected PII sitting?</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                  <tr>
                    <td>One verdict across the whole codebase</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span> 10 modules</td>
                  </tr>
                  <tr>
                    <td>Tells me what it did <i>not</i> check</td>
                    <td className="c"><span className="no">—</span></td>
                    <td className="c hl"><span className="yes">✓</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p style={capStyle}>
              Keep your tools — they&apos;re good continuous hygiene. Harvey answers a different question: is this
              codebase actually ready?
            </p>
          </div>
        </section>

        {/* MODULES */}
        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">Ten modules · equal weight</span>
            <h2>Everything Harvey checks before you scale.</h2>
            <p>
              No module is the headline. The deliverable is the true state of your codebase across all ten — a
              readiness verdict, not a single-issue report.
            </p>
          </div>
          <div className="wrap">
            <div className="mods">
              {MODULES.map((m) => (
                <div className="mod" key={m.n}>
                  <span className="n">{m.n}</span>
                  <div>
                    <h3>{m.h}</h3>
                    <p>{m.p}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* PER-STACK */}
        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">Built for your stack</span>
            <h2>What we check, specific to how you built it.</h2>
            <p>
              The ten modules apply to any codebase. On the stacks AI tools generate most, Harvey goes deeper — a
              sample of the stack-specific checks:
            </p>
          </div>
          <div className="wrap cols-4">
            <div className="card stack">
              <h3>Supabase</h3>
              <ul>
                <li>Row-Level Security policy semantics — not just on/off</li>
                <li>service_role keys on client-reachable paths</li>
                <li>Storage bucket &amp; auth configuration</li>
                <li>Postgres advisors, exposed schemas, function security</li>
              </ul>
            </div>
            <div className="card stack">
              <h3>Next.js</h3>
              <ul>
                <li>App Router server → client data leaks</li>
                <li>Server Action auth &amp; input validation</li>
                <li>Middleware &amp; route-handler authorization</li>
                <li>Env-var leakage, bundle size &amp; Core Web Vitals</li>
              </ul>
            </div>
            <div className="card stack">
              <h3>Vite / SPA</h3>
              <ul>
                <li>Client-exposed env vars (VITE_*)</li>
                <li>Frontend-only auth guards — real authz is server-side</li>
                <li>API access &amp; CORS configuration</li>
                <li>Bundle size &amp; build output</li>
              </ul>
            </div>
            <div className="card stack">
              <h3>Prisma / Drizzle / Postgres</h3>
              <ul>
                <li>Tenant-scope &amp; BOLA detection on Prisma and Drizzle queries</li>
                <li>No RLS safety net — isolation lives entirely in app code</li>
                <li>Live cross-tenant pen-test on a seeded Postgres instance</li>
                <li>PII/PHI/PCI mapped straight from schema.prisma</li>
              </ul>
            </div>
          </div>
          <div className="wrap narrow">
            <p style={{ color: "var(--muted)", fontSize: "17px", margin: "22px 0 0" }}>
              <b style={{ color: "var(--text)" }}>Prisma and Drizzle apps have no RLS to fall back on.</b> There&apos;s
              no database-level tenant enforcement — the boundary between customers is whatever your query code
              enforces, or it isn&apos;t enforced at all. Harvey audits exactly that: static detectors that catch a
              query missing its tenant scope, plus a live pen-test that stands up Postgres, seeds two tenants, and
              tries to cross between them through your app — detection-gated, and proven end-to-end on a real Prisma
              codebase.
            </p>
            <p style={{ color: "var(--muted)", fontSize: "17px", margin: "18px 0 0" }}>
              Harvey also recognises Kysely, TypeORM, Sequelize, Knex, Mongoose and raw SQL drivers, and routes them
              the same way. Where we don&apos;t yet have a dedicated tenant-scope detector for your query layer, the
              report says so by name rather than reporting silence as clean — the same rule that governs everything
              below.
            </p>
          </div>
        </section>

        {/* STEPS */}
        <section id="scan">
          <div className="wrap sec-head">
            <span className="eyebrow">How it works</span>
            <h2>Start free. The full audit goes where a scan can&apos;t.</h2>
          </div>
          <div className="wrap steps">
            <div className="step">
              <h3>Point us at your repo</h3>
              <p>
                Read-only access with git history, or a code archive. No database, no keys, no production contact.
                Same-day turnaround.
              </p>
            </div>
            <div className="step">
              <h3>Get your readiness report</h3>
              <p>
                All ten modules over your source, in plain English, ranked by what matters — a read on what your code
                indicates, yours to keep whether or not you buy.
              </p>
            </div>
            <div className="step">
              <h3>Go deeper</h3>
              <p>
                The paid audit does what source alone can&apos;t: stands up your stack and proves findings live, tests
                whether your tests actually catch bugs, and reviews your live database. Different depth — not more of
                the same.
              </p>
            </div>
          </div>
          <div className="wrap">
            {status === "ok" ? (
              <div className="scan-form form-ok">
                <h3>Request received.</h3>
                <p>
                  We&apos;ll send your ten-module readiness report within one business day. Check your inbox for a
                  confirmation.
                </p>
              </div>
            ) : (
              <form className="scan-form" onSubmit={submit}>
                <h3>Start your free scan</h3>
                <div className="field">
                  <label htmlFor="email">Your email</label>
                  <input
                    id="email"
                    type="email"
                    required
                    autoComplete="email"
                    value={form.email}
                    onChange={(e) => setForm({ ...form, email: e.target.value })}
                    placeholder="you@yourstartup.com"
                  />
                </div>
                <div className="field">
                  <label htmlFor="repo">Repo access</label>
                  <input
                    id="repo"
                    type="text"
                    required
                    value={form.repo}
                    onChange={(e) => setForm({ ...form, repo: e.target.value })}
                    placeholder="GitHub repo URL, or how we can get read-only access"
                  />
                </div>
                <div className="field">
                  <label htmlFor="context">Anything we should know? (optional)</label>
                  <textarea
                    id="context"
                    value={form.context}
                    onChange={(e) => setForm({ ...form, context: e.target.value })}
                    placeholder="Stack, rough size, launch timeline, specific worries…"
                  />
                </div>
                {status === "error" && <p className="form-err">{errMsg}</p>}
                <button type="submit" className="btn btn-primary" disabled={status === "submitting"}>
                  {status === "submitting" ? "Sending…" : "Run the free scan →"}
                </button>
                <p className="form-note">Source-only. No database, no credentials, no production contact.</p>
              </form>
            )}
          </div>
        </section>

        {/* PAID-ONLY */}
        <section>
          <div className="wrap sec-head">
            <span className="eyebrow">Free indicates · the audit proves</span>
            <h2>What the free scan can&apos;t tell you.</h2>
            <p>
              The free scan reads your source and reports what it <i>indicates</i>. A whole class of findings
              doesn&apos;t exist until Harvey runs the deeper tiers — no amount of static analysis can surface them.
            </p>
          </div>
          <div className="wrap">
            <div className="proves" style={{ marginBottom: "22px" }}>
              <div className="prove">
                <div className="ph">
                  <span className="tier-pill full">Full audit</span>
                  <h3>Proven broken access control</h3>
                </div>
                <p className="free">
                  Free scan: flags a policy that <i>looks</i> like it lets users reach data that isn&apos;t theirs.
                </p>
                <p className="paid">
                  Harvey signs in as one user and pulls another&apos;s private records — the actual row they should
                  never have been able to see.
                </p>
              </div>
              <div className="prove">
                <div className="ph">
                  <span className="tier-pill full">Full audit</span>
                  <h3>Tests that can&apos;t catch a bug</h3>
                </div>
                <p className="free">Free scan: notes which tests exist and look thin.</p>
                <p className="paid">
                  Harvey runs mutation testing — breaks your code on purpose and reports which tests still pass anyway.
                </p>
              </div>
            </div>

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
            <p style={capStyle}>
              The free scan is a real ten-module read of your source. Connected adds your live database; Full adds
              standing up and attacking a running copy — the only way to prove a flaw instead of flagging it.
            </p>
          </div>
        </section>

        {/* PRICING */}
        <section id="pricing">
          <div className="wrap sec-head">
            <span className="eyebrow">Transparent pricing</span>
            <h2>No &quot;book a call to hear the price.&quot;</h2>
            <p>
              Publishing prices is deliberate — most boutique auditors hide them behind a call. Pricing scales with
              your codebase size, so a weekend project and an enterprise monorepo never pay the same.
            </p>
          </div>
          <div className="wrap price-grid">
            <div className="tier">
              <span className="tname">FREE SCAN</span>
              <div className="amt">$0</div>
              <ul>
                <li><Check />Source-only, no credentials</li>
                <li><Check />Static findings + a ten-module coverage ledger</li>
                <li><Check />Same-day, yours to keep</li>
              </ul>
              <a href="#scan" className="btn btn-ghost">
                Run the free scan
              </a>
            </div>
            <div className="tier">
              <span className="tname">CONNECTED AUDIT</span>
              <div className="amt">
                $500<small> / from · by size</small>
              </div>
              <ul>
                <li><Check />All ten modules, reviewed with real verdicts</li>
                <li><Check />Live database: RLS, Supabase advisors, prod-vs-migration drift</li>
                <li><Check />PII protection verified in production</li>
                <li><Check />Read-only access — nothing stood up</li>
              </ul>
              <a href="#scan" className="btn btn-ghost">
                Start with a free scan
              </a>
            </div>
            <div className="tier feature">
              <span className="tname">FULL AUDIT</span>
              <div className="amt">
                $1,000<small> / from · by size</small>
              </div>
              <ul>
                <li><Check />Everything in the Connected audit</li>
                <li><Check />We stand up your stack and attack it live</li>
                <li><Check />Cross-tenant access &amp; auth flaws proven</li>
                <li><Check />Mutation-tested tests + investor-ready summary</li>
              </ul>
              <a href="#scan" className="btn btn-primary">
                Start with a free scan
              </a>
            </div>
          </div>
          <div className="wrap">
            <div className="addons">
              <span className="addon-tag">Add-on</span>
              <p>
                <b>Findings to tickets.</b> We file every finding as an issue in your tracker — GitHub, Jira, Linear,
                GitLab, or Azure DevOps — deduped against your last audit, so your team fixes from their own board.
              </p>
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
        </section>

        {/* LEDGER */}
        <section id="ledger">
          <div className="wrap sec-head">
            <span className="eyebrow">How we report</span>
            <h2>
              Harvey tells you what it <i>didn&apos;t</i> check.
            </h2>
            <p>
              An unstated limitation reads as a clean bill of health. So every Harvey report carries a coverage ledger
              — each module, its status, and the reason if it couldn&apos;t run. No silent gaps.
            </p>
          </div>
          <div className="wrap narrow">
            <div className="ledger">
              <div className="ledger-row">
                <span className="m">M8 · Test quality</span>
                <span className="why">mutation run complete</span>
                <span className="pill ran">Ran</span>
              </div>
              <div className="ledger-row">
                <span className="m">M1 · Access control &amp; data security</span>
                <span className="why">RLS + auth reviewed</span>
                <span className="pill ran">Ran</span>
              </div>
              <div className="ledger-row">
                <span className="m">M7 · Performance (DB advisors)</span>
                <span className="why">needs a connected database</span>
                <span className="pill part">Not run</span>
              </div>
              <div className="ledger-row">
                <span className="m">M10 · Data classification (live)</span>
                <span className="why">needs a connected database</span>
                <span className="pill part">Not run</span>
              </div>
            </div>
            <p style={{ color: "var(--muted)", fontSize: "17px", margin: "22px 0 0" }}>
              It goes past modules. If your repo holds infrastructure code, source in a language our rules
              don&apos;t read, or a framework we don&apos;t yet model, the report names it and counts the files
              rather than staying quiet. What we couldn&apos;t assess is stated, not implied.
            </p>
          </div>
        </section>

        {/* FINAL */}
        <section className="final">
          <div className="wrap">
            <span className="eyebrow" style={{ justifyContent: "center" }}>
              Start free
            </span>
            <h2 style={{ marginTop: "16px" }}>Find out what&apos;s actually in your codebase.</h2>
            <div className="hero-cta">
              <a href="#scan" className="btn btn-primary">
                Run the free scan →
              </a>
              <a href="/sample-report" className="btn btn-ghost">
                See a sample report
              </a>
            </div>
            <p className="trust">
              Source-only, no credentials, yours to keep — then see what the full audit can prove that a scan
              can&apos;t.
            </p>
          </div>
        </section>
      </main>

      <SiteFooter />
    </>
  );
}
