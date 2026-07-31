import type { Metadata } from "next";
import Link from "next/link";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

export const metadata: Metadata = {
  title: "Multi-tenant security in Supabase: how tenant data actually leaks",
  description:
    "The definitive guide to multi-tenant data leaks in Supabase apps: the five ways one tenant ends up reading another's data, why RLS that looks correct often isn't, and how to test that your tenant boundary actually holds.",
  alternates: { canonical: "/multi-tenant-security-supabase" },
  keywords: [
    "multi-tenant security supabase",
    "supabase tenant isolation",
    "supabase RLS multi-tenant",
    "cross-tenant data leak supabase",
  ],
  openGraph: {
    title: "Multi-tenant security in Supabase: how tenant data actually leaks",
    description: "The five ways one tenant ends up reading another's data — and how to test that your boundary holds.",
    url: "https://harvey-qa.com/multi-tenant-security-supabase",
    type: "article",
  },
};

const articleJsonLd = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "Multi-tenant security in Supabase: how tenant data actually leaks",
  description:
    "The five ways one tenant ends up reading another's data in a Supabase app, why RLS that looks correct often isn't, and how to test that your tenant boundary holds.",
  author: { "@type": "Organization", name: "Harvey" },
  publisher: { "@type": "Organization", name: "Harvey" },
  mainEntityOfPage: "https://harvey-qa.com/multi-tenant-security-supabase",
};

export default function MultiTenantPillar() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(articleJsonLd) }} />
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <Link href="/">Harvey</Link> / Multi-tenant security in Supabase
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Pillar guide
            </span>
            <h1>Multi-tenant security in Supabase: how tenant data actually leaks.</h1>
            <div className="answer-first" style={{ marginTop: "22px" }}>
              In a multi-tenant Supabase app, tenant data leaks when a Row-Level Security policy checks that a user is
              logged in but not that the row belongs to them. The public anon key is meant to be public; your isolation
              comes entirely from RLS behind it. When that policy is missing, too broad, or bypassed by a service-role
              key or an app-layer route, any user can read every tenant&apos;s data.
            </div>
          </div>
        </div>

        <section>
          <div className="wrap">
            <div className="prose">
              <h2>What &quot;multi-tenant&quot; means here</h2>
              <p>
                Most SaaS apps are multi-tenant: many customers (tenants) share one database, and each must see only
                their own data. The entire security model rests on one invariant — <b>tenant A can never read or write
                tenant B&apos;s rows</b>. In a Supabase app, that invariant is enforced almost entirely by Row-Level
                Security, because the client talks to the database directly using a public key.
              </p>
              <p>
                That last point is what surprises people: the Supabase <b>anon key is public by design</b>. It ships in
                your frontend. It is not a secret and it is not supposed to be. Everything that stops a stranger — or a
                logged-in customer — from reading the whole table is the RLS policy sitting behind that key. If the
                policy is wrong, the public key becomes a master key.
              </p>

              <h2>The five ways tenant data leaks</h2>

              <h3>1. The &quot;authenticated&quot; trap</h3>
              <p>
                By far the most common. A policy checks that the user is logged in, not that the row is theirs:
              </p>
              <pre>
                <code>{`-- Any logged-in user reads EVERY tenant's rows.
CREATE POLICY "read" ON documents
  FOR SELECT USING (auth.role() = 'authenticated');`}</code>
              </pre>
              <p>
                It looks like security — there&apos;s a policy, it mentions auth — and it passes most automated checks.
                But <code>auth.role() = &apos;authenticated&apos;</code> is true for <i>every</i> signed-in user. The fix
                is to scope by owner:
              </p>
              <pre>
                <code>{`CREATE POLICY "read own" ON documents
  FOR SELECT USING (tenant_id = auth.uid());
-- or: USING (tenant_id = (SELECT tenant_id FROM members WHERE user_id = auth.uid()))`}</code>
              </pre>

              <h3>2. RLS never turned on</h3>
              <p>
                A table in an API-exposed schema with RLS disabled is readable by anyone with the anon key — no login
                required. This happens when a table is added later and the &quot;enable RLS&quot; step is missed. A
                static check catches the toggle being off; it can&apos;t catch a policy that&apos;s <i>on but wrong</i>{" "}
                (that&apos;s #1).
              </p>

              <h3>3. The service_role key on a client path</h3>
              <p>
                The <code>service_role</code> key bypasses RLS entirely — that&apos;s its job, for trusted server code.
                The leak happens when it ends up somewhere the client can reach: a public env var, a client component, or
                a module a client component imports. Now the browser holds a key that ignores every policy you wrote.
              </p>

              <h3>4. SECURITY DEFINER functions with no caller check</h3>
              <p>
                A Postgres function marked <code>SECURITY DEFINER</code> runs with the definer&apos;s privileges and
                bypasses RLS. If it&apos;s callable over RPC and filters only by a parameter the caller supplies — not by{" "}
                <code>auth.uid()</code> — any user can pass any tenant&apos;s ID and act on their data.
              </p>

              <h3>5. App-layer authorization gaps (IDOR)</h3>
              <p>
                Even with perfect RLS, the boundary can leak <i>above</i> the database. A Next.js Server Action or route
                handler that uses the service role, or that trusts a resource ID from the request without checking
                ownership, is an Insecure Direct Object Reference: change the ID in the request, get someone else&apos;s
                data. RLS protects the database; it does not protect a route that has already bypassed it.
              </p>

              <blockquote>
                Four of these five are logic flaws, not syntax flaws. That&apos;s why scanners miss them and why
                &quot;we ran a scan&quot; is not the same as &quot;we know our tenants are isolated.&quot;
              </blockquote>

              <h2>Why AI-generated apps are especially exposed</h2>
              <p>
                Apps built quickly with Cursor, Claude, Lovable, Bolt, or v0 tend to get a working feature first and the
                policy later — and the generated policy is very often the &quot;authenticated&quot; trap from #1, because
                it makes the demo work. The app functions perfectly for its author, who only ever tests as one user. The
                leak is invisible until a second tenant exists — which is to say, until you have customers.
              </p>

              <h2>How to actually test that your boundary holds</h2>
              <p>You cannot confirm isolation by reading one policy. You confirm it by trying to cross the boundary:</p>
              <ol>
                <li>
                  <b>Create two real tenants</b> with separate data — two accounts, exactly like two customers.
                </li>
                <li>
                  <b>Sign in as tenant A</b> and request tenant B&apos;s rows directly — through the REST API, through
                  each route, through every RPC function.
                </li>
                <li>
                  <b>Check writes too</b>, not just reads: can A update, delete, or reassign B&apos;s rows?
                </li>
                <li>
                  <b>The result is the evidence.</b> If a request returns a row it shouldn&apos;t, that returned row is
                  your finding — not a warning that one &quot;might&quot; exist.
                </li>
              </ol>
              <p>
                This cross-tenant test is exactly what Harvey&apos;s live pen-test automates: it stands up a copy of your
                stack, seeds two tenants, and runs the read-and-write matrix across your REST and GraphQL APIs and your
                app routes, then probes the paths a matrix alone misses — anon-callable privileged functions, storage
                objects, invitations and share links, and data left behind after a delete. A source scan flags the
                suspicious policy; the live test proves whether it actually leaks. Whatever the run could not reach is
                listed as unprobed, with the reason.
              </p>

              <h2>A quick self-audit</h2>
              <ul>
                <li>Does every private table have RLS enabled <i>and</i> a policy scoped to the owner?</li>
                <li>Does any policy use <code>auth.role() = &apos;authenticated&apos;</code> or <code>USING (true)</code> on private data?</li>
                <li>Is the <code>service_role</code> key provably absent from anything the browser loads?</li>
                <li>Do your <code>SECURITY DEFINER</code> functions constrain by <code>auth.uid()</code>?</li>
                <li>Does every mutating route/Server Action verify the resource belongs to the caller?</li>
                <li>Have you tested all of the above as a <i>second</i> user, not just as yourself?</li>
              </ul>
              <p>
                Walk the interactive version on the <a href="/supabase-security-checklist">Supabase security checklist</a>,
                or read how the full audit works on <a href="/the-audit">The Audit</a>.
              </p>
            </div>

            <div className="cta-band">
              <div>
                <h3>Find out if your tenants are actually isolated.</h3>
                <p>The free scan flags the risky policies on your source. The Full audit proves — live — whether one tenant can read another.</p>
              </div>
              <div className="btns">
                <Link href="/#scan" className="btn btn-primary">
                  Run the free scan →
                </Link>
                <a href="/supabase-security-audit" className="btn btn-ghost">
                  Supabase security audit
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
