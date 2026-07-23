"use client";

import { useState } from "react";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

type Probe = { table: string; status: "warn" | "ok" | "info"; label: string; detail: string };
type Result = {
  tables: number;
  probes: Probe[];
  crossTenant: { probes: Probe[]; note: string };
  rpc: string[];
  storage: Probe | null;
  note: string;
};

function jwtRole(key: string): string | null {
  try {
    const payload = JSON.parse(atob(key.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return typeof payload.role === "string" ? payload.role : null;
  } catch {
    return null;
  }
}

function normalizeBase(raw: string): string {
  return raw
    .trim()
    .replace(/\/+$/, "")
    .replace(/\/rest\/v1.*$/, "");
}

function rowIds(rows: unknown[]): Set<string> {
  const ids = new Set<string>();
  for (const r of rows) {
    if (r && typeof r === "object") {
      const rec = r as Record<string, unknown>;
      const id = rec.id ?? rec.uuid ?? rec.pk;
      ids.add(id != null ? String(id) : JSON.stringify(rec));
    }
  }
  return ids;
}

async function signIn(base: string, anon: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: anon, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const body = (await res.json().catch(() => ({}))) as { access_token?: string; error_description?: string; msg?: string };
  if (!res.ok || !body.access_token) {
    throw new Error(body.error_description ?? body.msg ?? `sign-in failed for ${email} (HTTP ${res.status})`);
  }
  return body.access_token;
}

async function readIds(base: string, anon: string, token: string, table: string): Promise<Set<string> | null> {
  const res = await fetch(`${base}/rest/v1/${encodeURIComponent(table)}?select=*&limit=50`, {
    headers: { apikey: anon, Authorization: `Bearer ${token}` },
  });
  if (res.status !== 200) return null;
  const rows = (await res.json().catch(() => [])) as unknown[];
  return Array.isArray(rows) ? rowIds(rows) : null;
}

export default function Checker() {
  const [url, setUrl] = useState("");
  const [key, setKey] = useState("");
  const [emailA, setEmailA] = useState("");
  const [passA, setPassA] = useState("");
  const [emailB, setEmailB] = useState("");
  const [passB, setPassB] = useState("");
  const [status, setStatus] = useState<"idle" | "running" | "done" | "error">("idle");
  const [err, setErr] = useState("");
  const [result, setResult] = useState<Result | null>(null);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setResult(null);

    const base = normalizeBase(url);
    if (!/^https:\/\/[^/]+/.test(base)) {
      setErr("Enter your Supabase project URL, e.g. https://abcdefgh.supabase.co");
      setStatus("error");
      return;
    }
    const anon = key.trim();
    if (!anon) {
      setErr("Paste your public anon key (Project Settings → API → Project API keys → anon/public).");
      setStatus("error");
      return;
    }
    if (jwtRole(anon) === "service_role") {
      setErr(
        "That looks like your service_role key — never paste that into any tool, including this one. It bypasses all security. Use the anon (public) key instead.",
      );
      setStatus("error");
      return;
    }

    const wantCross = [emailA, passA, emailB, passB].some((v) => v.trim());
    if (wantCross && !(emailA.trim() && passA.trim() && emailB.trim() && passB.trim())) {
      setErr("For the cross-tenant test, fill in both users (email + password for each) — or leave all four blank to skip it.");
      setStatus("error");
      return;
    }

    setStatus("running");
    const headers = { apikey: anon, Authorization: `Bearer ${anon}` };

    let tableNames: string[] = [];
    let rpcNames: string[] = [];
    try {
      const root = await fetch(`${base}/rest/v1/`, { headers });
      if (!root.ok) {
        setErr(
          `The project responded with ${root.status} at its REST endpoint. Double-check the URL and that this is the anon key.`,
        );
        setStatus("error");
        return;
      }
      const spec = (await root.json()) as { definitions?: Record<string, unknown>; paths?: Record<string, unknown> };
      tableNames = Object.keys(spec.definitions ?? {});
      const paths = spec.paths ? Object.keys(spec.paths) : [];
      if (tableNames.length === 0) {
        tableNames = paths.filter((p) => p.startsWith("/") && p.length > 1 && !p.startsWith("/rpc/")).map((p) => p.slice(1));
      }
      rpcNames = paths.filter((p) => p.startsWith("/rpc/")).map((p) => p.slice(5));
    } catch {
      setErr(
        "Couldn't reach the project from your browser. Check the URL is correct and reachable. (This tool runs entirely in your browser — nothing is sent to Harvey.)",
      );
      setStatus("error");
      return;
    }

    const toProbe = tableNames.slice(0, 12);

    const probes: Probe[] = [];
    for (const t of toProbe) {
      try {
        const res = await fetch(`${base}/rest/v1/${encodeURIComponent(t)}?select=*&limit=1`, { headers });
        if (res.status === 200) {
          const rows = (await res.json()) as unknown[];
          if (Array.isArray(rows) && rows.length > 0) {
            probes.push({
              table: t,
              status: "warn",
              label: "Publicly readable",
              detail: "Your public anon key returned rows from this table. Confirm this table is meant to be public.",
            });
          } else {
            probes.push({
              table: t,
              status: "info",
              label: "Reachable, no rows",
              detail:
                "Reachable with the anon key but returned no rows — RLS may be filtering everything, or the table is empty. Confirm which.",
            });
          }
        } else if (res.status === 401 || res.status === 403) {
          probes.push({
            table: t,
            status: "ok",
            label: "Locked to anon",
            detail: "The anon role is denied — the public key can't read this table.",
          });
        } else {
          probes.push({
            table: t,
            status: "info",
            label: `HTTP ${res.status}`,
            detail: "Unexpected response; inconclusive for this table.",
          });
        }
      } catch {
        probes.push({ table: t, status: "info", label: "Error", detail: "Request failed; inconclusive." });
      }
    }

    // Cross-tenant read test: sign in as two real users and look for tables where both
    // see the SAME rows. Read-only — no writes, nothing persisted to your project.
    const crossTenant: Probe[] = [];
    let crossNote =
      "Not run. Enter two real users from your project (each in a different tenant) to test whether one logged-in user can read another's rows — the leak a source scan can't prove.";
    if (wantCross) {
      try {
        const tokenA = await signIn(base, anon, emailA.trim(), passA.trim());
        const tokenB = await signIn(base, anon, emailB.trim(), passB.trim());
        for (const t of toProbe) {
          const idsA = await readIds(base, anon, tokenA, t);
          const idsB = await readIds(base, anon, tokenB, t);
          if (idsA === null || idsB === null || idsA.size === 0 || idsB.size === 0) continue;
          const shared = [...idsA].filter((id) => idsB.has(id));
          if (shared.length > 0) {
            crossTenant.push({
              table: t,
              status: "warn",
              label: "Cross-tenant read",
              detail: `Both signed-in users returned ${shared.length} of the same row${shared.length === 1 ? "" : "s"} from this table. If these are tenant-owned records (not shared reference data), one tenant is reading another's — an RLS isolation gap.`,
            });
          }
        }
        crossNote =
          crossTenant.length > 0
            ? `${crossTenant.length} table${crossTenant.length === 1 ? "" : "s"} returned overlapping rows to two different users. Review each: if any hold tenant-owned data, that's a cross-tenant leak.`
            : "No table returned the same rows to both users in this check. That's a good sign for tenant isolation on the tables probed — but it isn't proof; a real audit stands up a seeded stack and tests every path.";
      } catch (signInErr) {
        crossNote = `Couldn't run: ${(signInErr as Error).message}. The anon-read, storage, and RPC results below still ran. (Passwords are sent only to your own project's auth endpoint, never to Harvey.)`;
      }
    }

    // Storage: can the public anon key enumerate your storage buckets?
    let storage: Probe | null = null;
    try {
      const res = await fetch(`${base}/storage/v1/bucket`, { headers });
      if (res.status === 200) {
        const buckets = (await res.json().catch(() => [])) as Array<{ name?: string; public?: boolean }>;
        const list = Array.isArray(buckets) ? buckets : [];
        const publicOnes = list.filter((b) => b.public).map((b) => b.name ?? "(unnamed)");
        storage = {
          table: "storage buckets",
          status: "warn",
          label: "Anon can list buckets",
          detail:
            `The public anon key can enumerate your storage buckets (${list.length} found).` +
            (publicOnes.length ? ` Public buckets — readable by anyone: ${publicOnes.join(", ")}.` : "") +
            " Confirm this is intended.",
        };
      } else {
        storage = {
          table: "storage buckets",
          status: "ok",
          label: "Buckets not enumerable",
          detail: "The anon key can't list your storage buckets over the API. (Individual public buckets, if any, are still directly reachable by name.)",
        };
      }
    } catch {
      storage = null;
    }

    const warnCount = probes.filter((p) => p.status === "warn").length;
    setResult({
      tables: tableNames.length,
      probes,
      crossTenant: { probes: crossTenant, note: crossNote },
      rpc: rpcNames.slice(0, 12),
      storage,
      note:
        warnCount > 0
          ? `${warnCount} table${warnCount === 1 ? "" : "s"} returned data to the public anon key. If any of those aren't meant to be public, that's a data-exposure risk worth a closer look.`
          : "No table returned rows to the public anon key in this quick check. That's a good sign — but it's a thin slice, not a full audit (it can't test every route, or writes).",
    });
    setStatus("done");
  }

  return (
    <>
      <SiteHeader />
      <main>
        <div className="hero page-hero">
          <div className="wrap">
            <span className="crumb">
              <a href="/">Harvey</a> / Free RLS checker
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Free tool
            </span>
            <h1>Free Supabase RLS checker.</h1>
            <div className="answer-first" style={{ marginTop: "22px" }}>
              Paste your Supabase project URL and public anon key. This tool asks your project — <b>from your browser</b>
              , using your public key — which tables that key can read. Add two logins and it also tests whether one
              logged-in user can read another&apos;s rows. Everything runs in your browser; nothing is sent to Harvey.
            </div>
          </div>
        </div>

        <section>
          <div className="wrap">
            <form className="tool" onSubmit={run}>
              <div className="field">
                <label htmlFor="url">Supabase project URL</label>
                <input
                  id="url"
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://abcdefgh.supabase.co"
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <div className="field">
                <label htmlFor="key">Public anon key</label>
                <input
                  id="key"
                  type="text"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  placeholder="eyJhbGci… (the anon / public key — NOT service_role)"
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>

              <details className="tool-more">
                <summary>Cross-tenant read test (optional) — two logins</summary>
                <p className="tool-more-hint">
                  Enter two real users from your project, ideally in different tenants/orgs. The tool signs in as each
                  (password sent only to your project&apos;s auth endpoint, never to Harvey) and flags any table where
                  both see the same rows — the tenant-isolation leak a source scan can&apos;t prove. Read-only: it never
                  writes to your project.
                </p>
                <div className="field">
                  <label htmlFor="ea">User A — email</label>
                  <input id="ea" type="text" value={emailA} onChange={(e) => setEmailA(e.target.value)} autoComplete="off" spellCheck={false} />
                </div>
                <div className="field">
                  <label htmlFor="pa">User A — password</label>
                  <input id="pa" type="password" value={passA} onChange={(e) => setPassA(e.target.value)} autoComplete="off" />
                </div>
                <div className="field">
                  <label htmlFor="eb">User B — email</label>
                  <input id="eb" type="text" value={emailB} onChange={(e) => setEmailB(e.target.value)} autoComplete="off" spellCheck={false} />
                </div>
                <div className="field">
                  <label htmlFor="pb">User B — password</label>
                  <input id="pb" type="password" value={passB} onChange={(e) => setPassB(e.target.value)} autoComplete="off" />
                </div>
              </details>

              <p className="privacy">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                Runs entirely in your browser. Your URL, key, and any logins are sent only to your own Supabase project,
                never to Harvey. The anon key is public by design — but never paste your <code>service_role</code> key
                anywhere.
              </p>
              {status === "error" && err && !result && <p className="tool-err">{err}</p>}
              <button type="submit" className="btn btn-primary" disabled={status === "running"}>
                {status === "running" ? "Checking…" : "Check my RLS →"}
              </button>
            </form>

            {result && (
              <div className="tool tool-result" style={{ marginTop: "22px" }}>
                <h3>Anonymous read access</h3>
                <p className="sub">
                  Found {result.tables} table{result.tables === 1 ? "" : "s"} visible to the anon key; probed{" "}
                  {result.probes.length}. {result.note}
                </p>
                {result.probes.map((p) => (
                  <div className="probe" key={p.table}>
                    <span className={`pst ${p.status}`}>{p.label}</span>
                    <div className="pbody">
                      <b>
                        <code>{p.table}</code>
                      </b>
                      <p>{p.detail}</p>
                    </div>
                  </div>
                ))}

                <h3 style={{ marginTop: 26 }}>Cross-tenant read test</h3>
                <p className="sub">{result.crossTenant.note}</p>
                {result.crossTenant.probes.map((p) => (
                  <div className="probe" key={`ct-${p.table}`}>
                    <span className={`pst ${p.status}`}>{p.label}</span>
                    <div className="pbody">
                      <b>
                        <code>{p.table}</code>
                      </b>
                      <p>{p.detail}</p>
                    </div>
                  </div>
                ))}

                <h3 style={{ marginTop: 26 }}>Storage buckets</h3>
                {result.storage ? (
                  <div className="probe">
                    <span className={`pst ${result.storage.status}`}>{result.storage.label}</span>
                    <div className="pbody">
                      <p>{result.storage.detail}</p>
                    </div>
                  </div>
                ) : (
                  <p className="sub">Storage check inconclusive (the endpoint didn&apos;t respond).</p>
                )}

                <h3 style={{ marginTop: 26 }}>RPC functions exposed to the anon key</h3>
                {result.rpc.length > 0 ? (
                  <>
                    <p className="sub">
                      {result.rpc.length} function{result.rpc.length === 1 ? "" : "s"} callable with your public key.
                      Ones marked <code>SECURITY DEFINER</code> run with the owner&apos;s privileges — review that each is
                      safe to expose publicly. (This tool lists them; it never calls them.)
                    </p>
                    <div className="probe">
                      <span className="pst info">RPC</span>
                      <div className="pbody">
                        <p>{result.rpc.map((n) => `${n}()`).join(", ")}</p>
                      </div>
                    </div>
                  </>
                ) : (
                  <p className="sub">No RPC functions are exposed to the anon key.</p>
                )}

                <div className="notice" style={{ marginTop: 22 }}>
                  <b>Still a thin slice, not an audit.</b> Even with the cross-tenant test, this only probes tables the
                  API advertises, using rows that happen to exist. It can&apos;t test writes, every RPC&apos;s internals,
                  whether a <code>service_role</code> key leaks to the client, or whether your app-layer routes check
                  ownership. A real audit stands up a seeded copy of your stack and proves each path.
                </div>
              </div>
            )}

            <div className="cta-band">
              <div>
                <h3>Get the checks this tool can&apos;t do.</h3>
                <p>
                  The free scan reads your source across all ten modules; the Full audit stands up a copy of your stack
                  and proves — live — whether one tenant can read another.
                </p>
              </div>
              <div className="btns">
                <a href="/#scan" className="btn btn-primary">
                  Run the free scan →
                </a>
                <a href="/multi-tenant-security-supabase" className="btn btn-ghost">
                  How tenant data leaks
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
