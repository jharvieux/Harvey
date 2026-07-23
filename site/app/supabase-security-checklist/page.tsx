"use client";

import { useMemo, useState } from "react";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

type Detect = "scan" | "live";
type Item = { id: string; title: string; desc: React.ReactNode; detect: Detect };
type Group = { name: string; items: Item[] };

const GROUPS: Group[] = [
  {
    name: "Row-Level Security",
    items: [
      {
        id: "rls-enabled",
        title: "RLS is enabled on every table exposed through the API",
        desc: (
          <>
            A table in an API-exposed schema with RLS off is fully readable with the public anon key. Enable RLS on
            every such table — a static check can confirm the toggle, but not that the policy behind it is correct.
          </>
        ),
        detect: "scan",
      },
      {
        id: "rls-scoped",
        title: "Each policy scopes rows to their owner, not just to \"authenticated\"",
        desc: (
          <>
            The most common leak: <code>USING (auth.role() = &apos;authenticated&apos;)</code> lets any logged-in user
            read every row. Policies must compare to <code>auth.uid()</code> or the tenant column. Whether it actually
            isolates tenants can only be confirmed by testing across two real users.
          </>
        ),
        detect: "live",
      },
      {
        id: "rls-write",
        title: "WITH CHECK guards INSERT and UPDATE, not just SELECT",
        desc: (
          <>
            A read policy without a matching <code>WITH CHECK</code> can let a user write rows they can&apos;t read, or
            reassign ownership. Verify both read and write paths.
          </>
        ),
        detect: "live",
      },
      {
        id: "rls-usingtrue",
        title: "No policy uses USING (true) on a private table",
        desc: <>A blanket-true policy disables isolation entirely. Legitimate only on genuinely public tables.</>,
        detect: "scan",
      },
    ],
  },
  {
    name: "Keys & roles",
    items: [
      {
        id: "service-role",
        title: "The service_role key never reaches client-side code",
        desc: (
          <>
            The service_role key bypasses RLS completely. It must live only in server-side code, never in a client
            component, a public env var, or a module a client component imports. A static scan can flag reachable
            imports; confirming it&apos;s never bundled needs a build-graph check.
          </>
        ),
        detect: "scan",
      },
      {
        id: "anon-ok",
        title: "You've confirmed the anon key is meant to be public",
        desc: (
          <>
            The anon key <i>is</i> public by design — that&apos;s expected. Your security comes from RLS behind it, not
            from hiding it. The risk is assuming the key is a secret and skipping RLS.
          </>
        ),
        detect: "scan",
      },
      {
        id: "env-server",
        title: "Server secrets aren't prefixed with NEXT_PUBLIC_ (or VITE_)",
        desc: (
          <>
            Any env var with a client prefix is shipped to the browser. Service keys, webhook secrets, and third-party
            API keys must not carry <code>NEXT_PUBLIC_</code> / <code>VITE_</code>.
          </>
        ),
        detect: "scan",
      },
    ],
  },
  {
    name: "Functions & RPC",
    items: [
      {
        id: "definer",
        title: "SECURITY DEFINER functions check the caller before writing",
        desc: (
          <>
            A <code>SECURITY DEFINER</code> function runs with elevated rights and bypasses RLS. If it&apos;s callable
            over RPC and doesn&apos;t constrain by <code>auth.uid()</code>, any user can invoke it against arbitrary data.
          </>
        ),
        detect: "live",
      },
      {
        id: "rpc-grants",
        title: "Only intended functions are granted EXECUTE to anon/authenticated",
        desc: <>Audit which RPC functions the public roles can call. Revoke EXECUTE from anything not meant to be client-callable.</>,
        detect: "scan",
      },
    ],
  },
  {
    name: "App-layer authorization",
    items: [
      {
        id: "server-action",
        title: "Server Actions and route handlers check ownership, not just login",
        desc: (
          <>
            RLS protects the database, but a Server Action using the service role, or an API route trusting an ID from
            the request, can still leak (IDOR). Every mutation should verify the resource belongs to the caller.
          </>
        ),
        detect: "live",
      },
      {
        id: "over-fetch",
        title: "API routes return only the columns the client needs",
        desc: <>Over-fetching (select *) can return columns — internal flags, other users&apos; PII — the UI never shows but the response exposes.</>,
        detect: "scan",
      },
      {
        id: "cors",
        title: "CORS and public endpoints are intentionally scoped",
        desc: <>Wide-open CORS or an unauthenticated endpoint that returns user data is an exposure regardless of RLS.</>,
        detect: "scan",
      },
    ],
  },
  {
    name: "Data & storage",
    items: [
      {
        id: "storage",
        title: "Storage buckets have access policies (not public by accident)",
        desc: <>A bucket set public exposes every object by URL. Confirm each public bucket is meant to be public and private buckets have policies.</>,
        detect: "scan",
      },
      {
        id: "pii",
        title: "You know which columns hold PII/PHI/PCI and that they're protected",
        desc: <>Map sensitive columns and confirm the policies and grants over them match how sensitive the data is.</>,
        detect: "scan",
      },
    ],
  },
];

const TOTAL = GROUPS.reduce((n, g) => n + g.items.length, 0);

export default function Checklist() {
  const [done, setDone] = useState<Record<string, boolean>>({});
  const count = useMemo(() => Object.values(done).filter(Boolean).length, [done]);
  const pct = Math.round((count / TOTAL) * 100);

  const toggle = (id: string) => setDone((d) => ({ ...d, [id]: !d[id] }));

  return (
    <>
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <a href="/">Harvey</a> / Supabase security checklist
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Interactive checklist
            </span>
            <h1>The Supabase security checklist.</h1>
            <div className="answer-first" style={{ marginTop: "22px" }}>
              Most Supabase data leaks come down to a handful of things: RLS that checks &quot;logged in&quot; instead of
              &quot;is this yours,&quot; a service_role key that reaches the client, or an app-layer route that trusts an
              ID from the request. Work through this list — and note which items a scanner can catch versus which need a
              live test to confirm.
            </div>
          </div>
        </div>

        <section>
          <div className="wrap">
            <div className="check-list">
              <div className="check-progress">
                <span className="num">
                  {count} / {TOTAL}
                </span>
                <div className="bar">
                  <span style={{ width: `${pct}%` }} />
                </div>
                <span className="num">{pct}%</span>
              </div>

              <p style={{ color: "var(--muted)", fontSize: "14.5px", margin: "10px 0 0", fontFamily: "var(--mono)" }}>
                <span className="detect scan" style={{ marginRight: "6px" }}>
                  Scanner
                </span>
                a static check can flag it ·
                <span className="detect live" style={{ margin: "0 6px" }}>
                  Live test
                </span>
                needs a running stack to confirm
              </p>

              {GROUPS.map((g) => (
                <div className="check-grp" key={g.name}>
                  <h3>{g.name}</h3>
                  {g.items.map((it) => (
                    <div className={`check-item${done[it.id] ? " done" : ""}`} key={it.id}>
                      <input
                        type="checkbox"
                        id={it.id}
                        checked={!!done[it.id]}
                        onChange={() => toggle(it.id)}
                      />
                      <label className="ctitle" htmlFor={it.id}>
                        {it.title}
                      </label>
                      <span className={`detect ${it.detect}`}>{it.detect === "scan" ? "Scanner" : "Live test"}</span>
                      <div className="cdesc">{it.desc}</div>
                    </div>
                  ))}
                </div>
              ))}
            </div>

            <div className="cta-band">
              <div>
                <h3>Want the &quot;live test&quot; items actually checked?</h3>
                <p>
                  The items marked &quot;Live test&quot; are exactly what a scanner can&apos;t confirm. Harvey&apos;s
                  free scan covers the static ones on your source; the Full audit proves the live ones on a copy of your
                  stack.
                </p>
              </div>
              <div className="btns">
                <a href="/#scan" className="btn btn-primary">
                  Run the free scan →
                </a>
                <a href="/supabase-security-checker" className="btn btn-ghost">
                  Try the RLS checker
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
