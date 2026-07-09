"use client";

// The browser wizard. Reads the core's session.state from the server and renders the matching
// screen; each action POSTs to an /api route that performs the matching core transition (design §3).
// It holds no model key or tracker token — those live only in the server routes.

import { useState } from "react";

interface Question { question: string; assumption: string }
interface ManifestEntry { title: string; scope: string; sizing: string }
interface Story { file: string; title: string; status: string }
interface View {
  slug: string;
  state: string;
  reviewTarget: string | null;
  body: string | null;
  stories: Story[];
  summary: string | null;
  applied?: boolean;
  diff?: string;
  unresolvedComments?: boolean;
}

const STEPS = ["intake", "clarify", "epic", "stories", "publish"];
function stepIndex(state: string): number {
  if (state === "intake") return 0;
  if (state === "clarify") return 1;
  if (state === "epic-draft" || state === "epic-review") return 2;
  if (state === "stories-fan-out" || state === "stories-review") return 3;
  return 4;
}

async function api<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error ?? "request failed");
  return json as T;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path);
  const json = await res.json();
  if (!res.ok) throw new Error(json.error ?? "request failed");
  return json as T;
}

export default function Wizard() {
  const [slug, setSlug] = useState<string | null>(null);
  const [view, setView] = useState<View | null>(null);
  const [questions, setQuestions] = useState<Question[] | null>(null);
  const [manifest, setManifest] = useState<ManifestEntry[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // form fields
  const [prompt, setPrompt] = useState("");
  const [answers, setAnswers] = useState("");
  const [draft, setDraft] = useState("");
  const [instruction, setInstruction] = useState("");
  const [publishResult, setPublishResult] = useState<string | null>(null);

  function fail(e: unknown) { setError(e instanceof Error ? e.message : String(e)); }
  async function run(fn: () => Promise<void>) {
    setBusy(true); setError("");
    try { await fn(); } catch (e) { fail(e); } finally { setBusy(false); }
  }
  function land(v: View) {
    setView(v);
    setDraft(v.body ?? "");
    setQuestions(null);
    setManifest(null);
  }

  async function startEpic() {
    await run(async () => {
      const r = await api<{ slug: string; questions: Question[] }>("/api/session", { prompt });
      setSlug(r.slug);
      setQuestions(r.questions);
      setView(null);
    });
  }
  async function submitClarify() {
    await run(async () => land(await api<View>("/api/clarify", { slug, answers })));
  }
  async function review(action: string, extra: Record<string, unknown> = {}) {
    await run(async () => land(await api<View>("/api/review", { slug, target: view!.reviewTarget, action, ...extra })));
  }
  async function loadManifest() {
    await run(async () => {
      const r = await get<{ entries: ManifestEntry[] }>(`/api/fanout?slug=${encodeURIComponent(slug!)}`);
      setManifest(r.entries);
    });
  }
  async function fanOut(keep: number[]) {
    await run(async () => land(await api<View>("/api/fanout", { slug, keep })));
  }
  async function publish(dryRun: boolean) {
    await run(async () => {
      const r = await api<{ summary: string }>("/api/publish", { slug, dryRun });
      setPublishResult(r.summary);
      land(await get<View>(`/api/session?slug=${encodeURIComponent(slug!)}`));
    });
  }

  const state = questions ? "clarify" : (view?.state ?? "intake");

  return (
    <main>
      <h1>Epic Builder</h1>
      <p className="sub">One paragraph in, a published epic + user stories out.</p>
      <div className="crumbs">
        {STEPS.map((s, i) => (
          <span key={s} className={i === stepIndex(state) ? "on" : ""}>{i + 1}. {s}</span>
        ))}
      </div>
      {error && <p className="err">Error: {error}</p>}

      {/* intake */}
      {!slug && (
        <section className="panel">
          <label htmlFor="prompt">Product idea (one paragraph)</label>
          <textarea id="prompt" style={{ minHeight: 120 }} value={prompt} onChange={(e) => setPrompt(e.target.value)}
            placeholder="Customers should be able to export audit findings as CSV..." />
          <div className="row"><button disabled={busy || !prompt.trim()} onClick={startEpic}>Start</button></div>
        </section>
      )}

      {/* clarify */}
      {questions && (
        <section className="panel">
          <h2>Clarifying questions</h2>
          {questions.map((q, i) => (
            <div className="q" key={i}>{i + 1}. {q.question} <span className="assume">[assume: {q.assumption}]</span></div>
          ))}
          <label htmlFor="answers">Answers (by number, e.g. &quot;1: admins only, 2: yes&quot;) — or leave blank for defaults</label>
          <textarea id="answers" style={{ minHeight: 100 }} value={answers} onChange={(e) => setAnswers(e.target.value)} />
          <div className="row"><button disabled={busy} onClick={submitClarify}>Draft the epic</button></div>
        </section>
      )}

      {/* epic / story review */}
      {view && (view.state === "epic-review" || view.state === "stories-review") && view.reviewTarget && (
        <section className="panel">
          <h2>Review: {view.reviewTarget} <span className="badge">{view.state}</span></h2>
          <label htmlFor="draft">Draft (edit directly, or insert <code>&gt; [!comment]</code> blocks then Apply comments)</label>
          <textarea id="draft" value={draft} onChange={(e) => setDraft(e.target.value)} />
          {view.diff && (
            <>
              <h2>Last revision diff</h2>
              <pre className="diff">{view.diff.split("\n").map((l, i) => (
                <span key={i} className={l.startsWith("+ ") ? "a" : l.startsWith("- ") ? "d" : ""}>{l}{"\n"}</span>
              ))}</pre>
              {view.unresolvedComments && <p className="err">Some comment blocks were not resolved — review the draft.</p>}
            </>
          )}
          <label htmlFor="instruction">One-line revise instruction (optional)</label>
          <input id="instruction" type="text" value={instruction} onChange={(e) => setInstruction(e.target.value)} />
          <div className="row">
            <button disabled={busy} onClick={() => review("accept")}>Accept</button>
            <button className="ghost" disabled={busy} onClick={() => review("edit", { body: draft })}>Save edits</button>
            <button className="ghost" disabled={busy} onClick={() => review("comment", { body: draft })}>Apply comments</button>
            <button className="ghost" disabled={busy || !instruction.trim()} onClick={() => review("revise", { instruction, body: draft })}>Revise</button>
            {view.state === "stories-review" && <button className="ghost" disabled={busy} onClick={() => review("skip")}>Skip</button>}
          </div>
          {view.stories.length > 0 && (
            <ul className="storylist">
              {view.stories.map((s) => (
                <li key={s.file}>{s.title} <span className="badge">{s.status}</span></li>
              ))}
            </ul>
          )}
        </section>
      )}

      {/* story fan-out */}
      {view && view.state === "stories-fan-out" && (
        <section className="panel">
          <h2>Story fan-out</h2>
          {!manifest ? (
            <div className="row"><button disabled={busy} onClick={loadManifest}>Preview proposed stories</button></div>
          ) : (
            <ManifestPicker entries={manifest} busy={busy} onConfirm={fanOut} />
          )}
        </section>
      )}

      {/* publish */}
      {view && (view.state === "publish" || view.state === "summary" || view.state === "done") && (
        <section className="panel">
          <h2>Publish</h2>
          <p className="sub">Dry run previews the GitHub issue set without creating anything. Publish creates the issues (safe to re-run).</p>
          <div className="row">
            <button className="ghost" disabled={busy} onClick={() => publish(true)}>Dry run</button>
            <button disabled={busy} onClick={() => publish(false)}>Publish to GitHub</button>
          </div>
          {publishResult && <pre className="summary">{publishResult}</pre>}
        </section>
      )}
    </main>
  );
}

function ManifestPicker({ entries, busy, onConfirm }: { entries: ManifestEntry[]; busy: boolean; onConfirm: (keep: number[]) => void }) {
  const [keep, setKeep] = useState<boolean[]>(entries.map(() => true));
  return (
    <>
      {entries.map((e, i) => (
        <div className="q" key={i}>
          <label style={{ display: "inline-flex", gap: 8, fontWeight: 400 }}>
            <input type="checkbox" checked={keep[i]} onChange={() => setKeep((k) => k.map((v, j) => (j === i ? !v : v)))} />
            <span>{e.title} <span className="badge">{e.sizing}</span> — <span className="assume">{e.scope}</span></span>
          </label>
        </div>
      ))}
      <div className="row">
        <button disabled={busy} onClick={() => onConfirm(entries.map((_, i) => i).filter((i) => keep[i]))}>Draft these stories</button>
      </div>
    </>
  );
}
