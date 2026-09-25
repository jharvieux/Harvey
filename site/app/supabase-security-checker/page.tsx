"use client";

import { useState } from "react";
import Link from "next/link";
import SiteHeader from "../components/SiteHeader";
import SiteFooter from "../components/SiteFooter";
// #1597: imported from the repo's own src/ rather than a copy relocated into site/. site/ is a
// pnpm workspace member and the Vercel deploy now uploads the repo root, so this import crosses
// what used to be a hard boundary. MEASURED 2026-07-30: `next build` needs no
// `experimental.externalDir` for it — the compiled module lands in
// .next/static/chunks/app/supabase-security-checker/page-*.js (grep 23502).
import { canProbeWrite, classifyWriteResponse, pgCodeOf } from "../../../src/supabase-write-probe";
import { SUPPORT_EMAIL } from "../lib/constants";

type Probe = { table: string; status: "warn" | "ok" | "info"; label: string; detail: string };
type Result = {
  tables: number;
  probes: Probe[];
  writes: { probes: Probe[]; note: string };
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

// Coarse, count-only summary for the opt-in lead — never table names, the project URL, or the key.
function coarseSummary(r: Result): string {
  const parts: string[] = [];
  const pub = r.probes.filter((p) => p.status === "warn").length;
  parts.push(`${pub} table${pub === 1 ? "" : "s"} publicly readable of ${r.tables} total`);
  const inconclusive = r.probes.filter((p) => p.status === "info").length;
  if (inconclusive) parts.push(`${inconclusive} read check${inconclusive === 1 ? "" : "s"} inconclusive`);
  const writable = r.writes.probes.filter((p) => p.status === "warn").length;
  if (writable > 0) parts.push(`${writable} anon-writable`);
  const cross = r.crossTenant.probes.filter((p) => p.status === "warn").length;
  if (cross > 0) parts.push(`${cross} cross-tenant finding${cross === 1 ? "" : "s"}`);
  if (r.storage?.status === "warn") parts.push("storage buckets anon-listable");
  if (r.rpc.length) parts.push(`${r.rpc.length} RPC${r.rpc.length === 1 ? "" : "s"} exposed to anon`);
  return parts.join("; ");
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
  const rows: unknown = await res.json().catch(() => null);
  return Array.isArray(rows) ? rowIds(rows) : null;
}

// Non-destructive write-attempt (#888). Sends an INSERT with an EMPTY body: with a table that has
// any required (NOT NULL, no-default) column this is guaranteed to fail the not-null constraint —
// never a 2xx, never a stored row — while still exercising the GRANT + RLS WITH CHECK gate, which
// PostgreSQL evaluates FIRST (see docs/design/postgrest-write-eval-order.md). The status tells us
// whether the write WOULD have been permitted, without ever writing.
async function attemptWrite(base: string, apikey: string, bearer: string, table: string) {
  const res = await fetch(`${base}/rest/v1/${encodeURIComponent(table)}`, {
    method: "POST",
    headers: { apikey, Authorization: `Bearer ${bearer}`, "Content-Type": "application/json", Prefer: "return=representation" },
    body: "{}",
  });
  const body = await res.json().catch(() => null);
  return { verdict: classifyWriteResponse(res.status, pgCodeOf(body)), status: res.status };
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
  const [leadEmail, setLeadEmail] = useState("");
  const [leadStatus, setLeadStatus] = useState<"idle" | "submitting" | "ok" | "error">("idle");
  const [leadErr, setLeadErr] = useState("");

  async function submitLead(e: React.FormEvent) {
    e.preventDefault();
    if (!result) return;
    setLeadStatus("submitting");
    setLeadErr("");
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Only the email + a coarse, count-only summary are sent. The project URL and anon
        // key are never included — they stay in the browser, keeping the tool's core promise.
        body: JSON.stringify({ kind: "checker-lead", email: leadEmail, summary: coarseSummary(result) }),
      });
      if (res.ok) {
        setLeadStatus("ok");
      } else {
        const d = (await res.json().catch(() => ({}))) as { error?: string };
        setLeadErr(d.error || `Something went wrong. Please try again or email us at ${SUPPORT_EMAIL}.`);
        setLeadStatus("error");
      }
    } catch {
      setLeadErr(`Network error. Please try again or email us at ${SUPPORT_EMAIL}.`);
      setLeadStatus("error");
    }
  }

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
    let defs: Record<string, unknown> = {};
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
      defs = spec.definitions ?? {};
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
          const rows: unknown = await res.json();
          if (!Array.isArray(rows)) throw new Error("Expected a row collection");
          if (rows.length > 0) {
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

    // Write-attempt probe (#888). NON-DESTRUCTIVE by construction: an empty-body INSERT that a
    // required NOT-NULL column is guaranteed to reject (400/23502) BEFORE anything persists, while
    // still passing through the RLS WITH CHECK gate PostgreSQL evaluates first. A 400/not-null means
    // the write would have been permitted; 401/403 means it was denied. Tables with no required
    // column are skipped (disclosed) because an empty INSERT there could actually store a row.
    const writes: Probe[] = [];
    const anonWritable = new Set<string>();
    let writeSkipped = 0;
    for (const t of toProbe) {
      if (!canProbeWrite(defs[t])) {
        writeSkipped++;
        continue;
      }
      try {
        const { verdict, status: responseStatus } = await attemptWrite(base, anon, anon, t);
        if (verdict === "writable") {
          anonWritable.add(t);
          writes.push({
            table: t,
            status: "warn",
            label: "Anon can write",
            detail:
              "The public anon key was allowed to write to this table — only a deliberately-invalid payload stopped a row from being saved (nothing was). If anyone with your public key can INSERT here, that's an unauthorized-write risk. Confirm the write policy is intended.",
          });
        } else if (verdict === "denied") {
          writes.push({
            table: t,
            status: "ok",
            label: "Writes locked to anon",
            detail: "The anon role is denied writes — the public key can't INSERT into this table.",
          });
        } else if (verdict === "persisted") {
          writes.push({
            table: t,
            status: "warn",
            label: "May have written a row",
            detail:
              "The write unexpectedly succeeded despite an empty payload — a column default or trigger filled in the omitted field, so a row may have been created here. This tool never sends a full payload; review this table directly.",
          });
        } else {
          writes.push({ table: t, status: "info", label: "Write check inconclusive", detail: `Unexpected response (HTTP ${responseStatus}); write access was not assessed.` });
        }
      } catch {
        writes.push({ table: t, status: "info", label: "Write check inconclusive", detail: "Request failed; write access was not assessed." });
      }
    }
    const anonWarn = writes.filter((p) => p.status === "warn").length;
    const writeDenied = writes.filter((p) => p.status === "ok").length;
    const writeUnknown = writes.filter((p) => p.status === "info").length;
    const possiblyPersisted = writes.some((p) => p.label === "May have written a row");
    let writesNote = anonWarn > 0
      ? `${anonWarn} table${anonWarn === 1 ? "" : "s"} accepted a write from the public anon key. Review each result. ${possiblyPersisted ? "A row may have been created; review the affected table directly." : "The deliberately invalid payloads were rejected before a row was saved."}`
      : writeDenied > 0 && writeUnknown === 0
        ? `${writeDenied} tested table${writeDenied === 1 ? "" : "s"} denied the attempted INSERT from the public anon key.`
        : "Write access is inconclusive: no successful assessment establishes that these tables deny writes.";
    if (writeUnknown > 0) writesNote += ` ${writeUnknown} write check${writeUnknown === 1 ? "" : "s"} could not be assessed.`;
    if (writeSkipped > 0) {
      writesNote += ` (${writeSkipped} table${writeSkipped === 1 ? "" : "s"} skipped: no required column to probe safely without risking a stored row.)`;
    }

    // Cross-tenant read test: sign in as two real users and look for tables where both
    // see the SAME rows. Read-only reads — plus a non-destructive write-attempt as user A.
    const crossTenant: Probe[] = [];
    let crossNote =
      "Not run. Enter two real users from your project (each in a different tenant) to test whether one logged-in user can read another's rows — the leak a source scan can't prove.";
    if (wantCross) {
      try {
        const tokenA = await signIn(base, anon, emailA.trim(), passA.trim());
        const tokenB = await signIn(base, anon, emailB.trim(), passB.trim());
        let compared = 0;
        for (const t of toProbe) {
          try {
            const idsA = await readIds(base, anon, tokenA, t);
            const idsB = await readIds(base, anon, tokenB, t);
            if (idsA === null || idsB === null || idsA.size === 0 || idsB.size === 0) {
              crossTenant.push({ table: t, status: "info", label: "Cross-tenant check inconclusive", detail: "Both users must return non-empty row collections to compare isolation; a request failed, was denied, or returned no rows." });
              continue;
            }
            compared++;
            const shared = [...idsA].filter((id) => idsB.has(id));
            if (shared.length > 0) {
              crossTenant.push({
                table: t,
                status: "warn",
                label: "Cross-tenant read",
                detail: `Both signed-in users returned ${shared.length} of the same row${shared.length === 1 ? "" : "s"} from this table. If these are tenant-owned records (not shared reference data), one tenant is reading another's — an RLS isolation gap.`,
              });
            }
            // Non-destructive write-attempt as user A. An empty INSERT that passes RLS WITH CHECK
            // (400/not-null) means the policy accepts an unscoped row from ANY signed-in user — a
            // cross-tenant write exposure. Only surfaced when anon couldn't already write it (that's
            // the stronger finding, already reported above).
            if (canProbeWrite(defs[t]) && !anonWritable.has(t)) {
              const { verdict } = await attemptWrite(base, anon, tokenA, t);
              if (verdict === "writable") {
                crossTenant.push({
                  table: t,
                  status: "warn",
                  label: "Cross-tenant write",
                  detail:
                    "A signed-in user was allowed to write an unscoped row here (nothing was saved — the payload was invalid on purpose). A write policy that accepts a row not tied to the caller's tenant lets one tenant write into another's data. Confirm the WITH CHECK policy scopes writes to the owner.",
                });
              } else if (verdict === "persisted") {
                crossTenant.push({ table: t, status: "warn", label: "May have written a row", detail: "The signed-in write unexpectedly succeeded. A row may have been created; review the table directly." });
              } else if (verdict === "inconclusive") {
                crossTenant.push({ table: t, status: "info", label: "Signed-in write inconclusive", detail: "The response did not establish whether writes are allowed." });
              }
            }
          } catch {
            crossTenant.push({ table: t, status: "info", label: "Cross-tenant check inconclusive", detail: "A request failed; this table was not fully assessed." });
          }
        }
        const crossReads = crossTenant.filter((p) => p.label === "Cross-tenant read").length;
        const crossWrites = crossTenant.filter((p) => p.label === "Cross-tenant write").length;
        const unknown = crossTenant.filter((p) => p.status === "info").length;
        const persisted = crossTenant.some((p) => p.label === "May have written a row");
        crossNote = `${compared} table${compared === 1 ? "" : "s"} compared using non-empty rows from both users; ${crossReads} with overlapping rows, ${crossWrites} with an accepted unscoped write. `;
        crossNote += compared === 0 || unknown > 0
          ? "Tenant isolation remains inconclusive: empty, denied, malformed, or failed checks are not evidence of isolation."
          : "These sampled rows do not establish isolation for every row or route; review the individual results.";
        if (persisted) crossNote += " A signed-in write may have created a row; review the affected table directly.";
      } catch (signInErr) {
        crossNote = `Couldn't run: ${(signInErr as Error).message}. The anon-read, anon-write, storage, and RPC results below still ran. (Passwords are sent only to your own project's auth endpoint, never to Harvey.)`;
      }
    }

    // Storage: can the public anon key enumerate your storage buckets?
    let storage: Probe | null = null;
    try {
      const res = await fetch(`${base}/storage/v1/bucket`, { headers });
      if (res.status === 200) {
        const buckets: unknown = await res.json();
        if (!Array.isArray(buckets) || buckets.some((bucket) => !bucket || typeof bucket !== "object")) throw new Error("Expected a bucket collection");
        const list = buckets as Array<{ name?: string; public?: boolean }>;
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
      } else if (res.status === 401 || res.status === 403) {
        storage = {
          table: "storage buckets",
          status: "ok",
          label: "Buckets not enumerable",
          detail: "The anon key can't list your storage buckets over the API. (Individual public buckets, if any, are still directly reachable by name.)",
        };
      } else {
        storage = { table: "storage buckets", status: "info", label: "Storage check inconclusive", detail: `Unexpected response (HTTP ${res.status}); storage access was not assessed.` };
      }
    } catch {
      storage = { table: "storage buckets", status: "info", label: "Storage check inconclusive", detail: "Request failed or returned an invalid bucket collection; storage access was not assessed." };
    }

    const warnCount = probes.filter((p) => p.status === "warn").length;
    setResult({
      tables: tableNames.length,
      probes,
      writes: { probes: writes, note: writesNote },
      crossTenant: { probes: crossTenant, note: crossNote },
      rpc: rpcNames.slice(0, 12),
      storage,
      note:
        warnCount > 0
          ? `${warnCount} table${warnCount === 1 ? "" : "s"} returned data to the public anon key. If any of those aren't meant to be public, that's a data-exposure risk worth a closer look.`
          : probes.length === 0 || probes.some((p) => p.status === "info")
            ? "Read access remains inconclusive. Empty tables, unexpected responses, and failed requests do not establish that access is denied."
            : "The tested tables denied these anonymous reads. This only covers the sampled tables and requests; it does not establish access control for every route.",
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
              <Link href="/">Harvey</Link> / Free RLS checker
            </span>
            <span className="eyebrow" style={{ marginTop: "14px" }}>
              Free tool
            </span>
            <h1>Free Supabase RLS checker.</h1>
            <div className="answer-first" style={{ marginTop: "22px" }}>
              Paste your Supabase project URL and public anon key. This tool asks your project — <b>from your browser</b>
              , using your public key — which tables that key can read, and whether it can write to them (a
              deliberately invalid INSERT intended to be rejected before a row is saved). Unexpected success is
              reported for review. Add two logins and it also tests whether one logged-in user
              can read or write another&apos;s rows. Everything runs in your browser; nothing is sent to Harvey.
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
                  both see the same rows — the tenant-isolation leak a source scan can&apos;t prove. It also tries a
                  non-destructive write as one user: every write attempt uses a deliberately-invalid payload that the
                  database should reject before saving. If it unexpectedly succeeds, the result warns that a row may
                  have been created.
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

                <h3 style={{ marginTop: 26 }}>Write access (non-destructive)</h3>
                <p className="sub">{result.writes.note}</p>
                {result.writes.probes.map((p) => (
                  <div className="probe" key={`w-${p.table}`}>
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
                  <b>Still a thin slice, not an audit.</b> Even with the cross-tenant and write tests, this only probes
                  tables the API advertises, and its write check is limited to INSERT (it never tests UPDATE or DELETE
                  authorization, which can&apos;t be probed without risking a change). It can&apos;t test every RPC&apos;s
                  internals, whether a <code>service_role</code> key leaks to the client, or whether your app-layer routes
                  check ownership. A real audit stands up a seeded copy of your stack and proves each path.
                </div>

                {/* Opt-in lead capture (#749). Everything above ran in-browser and sent Harvey nothing;
                    this step is different and says so. It transmits only the typed email + a coarse,
                    count-only summary — never the project URL or anon key. */}
                <div
                  className="tool"
                  style={{ marginTop: 22, borderTop: "3px solid var(--accent, #6366f1)", background: "transparent" }}
                >
                  <span className="eyebrow" style={{ color: "var(--accent, #6366f1)" }}>
                    Optional — this step sends data to Harvey
                  </span>
                  <h3 style={{ marginTop: 10 }}>Want us to take a closer look?</h3>
                  <p className="sub">
                    Everything above ran <b>in your browser</b> — your URL, key, and logins were never sent to Harvey.
                    This box is the one exception, and only if you choose it: leave your email and we&apos;ll send{" "}
                    <b>just your address and a short count-only summary</b> (no project URL, no key, no table names) so we
                    can follow up with a deeper read.
                  </p>
                  {leadStatus === "ok" ? (
                    <p className="sub" style={{ color: "var(--accent, #6366f1)", fontWeight: 600 }}>
                      Thanks — we&apos;ve got it and we&apos;ll be in touch. Nothing but your email and that summary was
                      sent.
                    </p>
                  ) : (
                    <form onSubmit={submitLead}>
                      <div className="field">
                        <label htmlFor="lead-email">Your email</label>
                        <input
                          id="lead-email"
                          type="email"
                          required
                          value={leadEmail}
                          onChange={(e) => setLeadEmail(e.target.value)}
                          placeholder="you@yourstartup.com"
                          autoComplete="email"
                        />
                      </div>
                      <p className="sub" style={{ fontSize: 14 }}>
                        We&apos;ll send exactly this summary: <code>{coarseSummary(result)}</code>. That&apos;s the whole
                        payload alongside your email.
                      </p>
                      {leadStatus === "error" && <p className="tool-err">{leadErr}</p>}
                      <button type="submit" className="btn btn-primary" disabled={leadStatus === "submitting"}>
                        {leadStatus === "submitting" ? "Sending…" : "Send my email to Harvey →"}
                      </button>
                    </form>
                  )}
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
                <Link href="/#scan" className="btn btn-primary">
                  Run the free scan →
                </Link>
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
