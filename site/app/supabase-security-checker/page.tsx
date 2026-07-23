"use client";

import { useState } from "react";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";

type Probe = { table: string; status: "warn" | "ok" | "info"; label: string; detail: string };
type Result = { restReachable: boolean; tables: number; probes: Probe[]; note: string };

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

export default function Checker() {
  const [url, setUrl] = useState("");
  const [key, setKey] = useState("");
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

    setStatus("running");
    const headers = { apikey: anon, Authorization: `Bearer ${anon}` };

    let tableNames: string[] = [];
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
      if (tableNames.length === 0 && spec.paths) {
        tableNames = Object.keys(spec.paths)
          .filter((p) => p.startsWith("/") && p.length > 1 && !p.startsWith("/rpc/"))
          .map((p) => p.slice(1));
      }
    } catch {
      setErr(
        "Couldn't reach the project from your browser. Check the URL is correct and reachable. (This tool runs entirely in your browser — nothing is sent to Harvey.)",
      );
      setStatus("error");
      return;
    }

    const probes: Probe[] = [];
    const toProbe = tableNames.slice(0, 12);
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

    const warnCount = probes.filter((p) => p.status === "warn").length;
    setResult({
      restReachable: true,
      tables: tableNames.length,
      probes,
      note:
        warnCount > 0
          ? `${warnCount} table${warnCount === 1 ? "" : "s"} returned data to the public anon key. If any of those aren't meant to be public, that's a data-exposure risk worth a closer look.`
          : "No table returned rows to the public anon key in this quick check. That's a good sign — but it's a thin slice, not a full audit (it can't test logged-in cross-tenant access, writes, RPC functions, or app-layer routes).",
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
              , using your public key — which tables that key can read. Anything it returns is readable by anyone with
              your (public) anon key. It&apos;s a thin slice of a real audit: it checks anonymous read access only.
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
              <p className="privacy">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                Runs entirely in your browser. Your URL and key are sent only to your own Supabase project, never to
                Harvey. The anon key is public by design — but never paste your <code>service_role</code> key anywhere.
              </p>
              {status === "error" && <p className="tool-err">{err}</p>}
              <button type="submit" className="btn btn-primary" disabled={status === "running"}>
                {status === "running" ? "Checking…" : "Check my RLS →"}
              </button>
            </form>

            {status === "done" && result && (
              <div className="tool tool-result" style={{ marginTop: "22px" }}>
                <h3>Result</h3>
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
                <div className="notice" style={{ marginTop: "20px" }}>
                  <b>This is a thin slice, not an audit.</b> It only checks what an anonymous public key can read. It
                  can&apos;t test whether one logged-in tenant can read another&apos;s data, whether writes are guarded,
                  whether a <code>service_role</code> key leaks to the client, or whether your app-layer routes check
                  ownership. Those need a real audit.
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
