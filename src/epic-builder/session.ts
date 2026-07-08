// Session controller (design §2–§3, §6). Composes the model-call seam, the workspace, and the pure
// state machine into the workflow steps the CLI drives. Every step persists to disk before it
// returns, so a resume picks up exactly where a crash left off. IO (asking the user a question,
// confirming a diff) is injected as callbacks so the whole controller is testable with a fake model
// and no terminal.

import type {
  ClarifyQuestion,
  DraftSession,
  ModelClient,
  StoryManifestEntry,
  StoryState,
  Tier,
} from "./types.js";
import { selectTier, revisionFlags } from "./tier-policy.js";
import { transition } from "./state-machine.js";
import { extractComments, hasUnresolvedComments, renderDiff } from "./revision.js";
import { missingSections } from "./render.js";
import {
  appendAction,
  readDraft,
  readFileRaw,
  saveSession,
  slugify,
  writeDraft,
  writeFile,
} from "./workspace.js";

export interface Templates {
  epic: string;
  story: string;
  brief: string;
}

// --- Clarify (design §2.2): batched questions, hard cap of 2 rounds ---

export async function runClarify(
  dir: string,
  session: DraftSession,
  model: ModelClient,
  answer: (questions: ClarifyQuestion[], round: number) => Promise<string>,
): Promise<DraftSession> {
  session.state = transition(session.state, "clarify-start");
  saveSession(dir, session);

  let transcript = `# Intake: ${session.slug}\n\n**Prompt:** ${session.prompt}\n\n## Clarifying Q&A\n`;
  const priorQA: string[] = [];
  for (let round = 1; round <= 2; round++) {
    const tier = selectTier({ task: "clarify", revisionCount: 0, flags: [] });
    const questions = await model.clarify({ prompt: session.prompt, round, priorQA: priorQA.join("\n") }, tier);
    if (questions.length === 0) break;
    const rendered = questions.map((q, i) => `${i + 1}. ${q.question} [assume: ${q.assumption}]`).join("\n");
    const reply = await answer(questions, round);
    transcript += `\n### Round ${round}\n${rendered}\n\n**Answers:** ${reply}\n`;
    priorQA.push(rendered, reply);
    session.clarifyRounds = round;
    saveSession(dir, session);
    if (reply.trim().toLowerCase() === "defaults") break;
  }
  writeFile(dir, "intake.md", `${transcript}\n`);
  session.state = transition(session.state, "clarify-done");
  saveSession(dir, session);
  return session;
}

// --- Epic draft (design §3, §4.2) ---

export async function draftEpic(
  dir: string,
  session: DraftSession,
  model: ModelClient,
  templates: Templates,
): Promise<DraftSession> {
  const intake = readFileRaw(dir, "intake.md");
  const tier = selectTier({ task: "epic-draft", revisionCount: session.epic.revisions, flags: revisionFlags(session.epic.revisions) });
  const body = await model.draftEpic({ prompt: session.prompt, intake, template: templates.epic }, tier);
  const title = extractTitle(body) ?? session.prompt;
  writeDraft(dir, "epic.md", {
    data: { kind: "epic", epic: session.slug, title, status: "in-review" },
    body,
  });
  session.epic.status = "in-review";
  session.state = transition(session.state, "epic-drafted");
  saveSession(dir, session);
  return session;
}

// --- Review-loop actions (design §2.3, §4.4) ---

export function acceptEpic(dir: string, session: DraftSession): DraftSession {
  setStatus(dir, "epic.md", "accepted");
  session.epic.status = "accepted";
  session.state = transition(session.state, "epic-accept");
  appendAction(dir, { kind: "accept", target: "epic.md" });
  saveSession(dir, session);
  return session;
}

export function acceptStory(dir: string, session: DraftSession, file: string): DraftSession {
  setStatus(dir, file, "accepted");
  storyState(session, file).status = "accepted";
  appendAction(dir, { kind: "accept", target: file });
  if (session.stories.every((s) => s.status === "accepted" || s.status === "skipped")) {
    session.state = transition(session.state, "stories-accept");
  }
  saveSession(dir, session);
  return session;
}

export function skipStory(dir: string, session: DraftSession, file: string): DraftSession {
  setStatus(dir, file, "skipped");
  storyState(session, file).status = "skipped";
  appendAction(dir, { kind: "skip", target: file });
  saveSession(dir, session);
  return session;
}

// Direct edit: the user is the author, so the on-disk file is authoritative and no diff is shown
// (design §4.4). We just re-read to pick up their change and record the action.
export function recordDirectEdit(dir: string, session: DraftSession, file: string): DraftSession {
  appendAction(dir, { kind: "direct-edit", target: file });
  saveSession(dir, session);
  return session;
}

interface RevisionResult {
  applied: boolean;
  diff: string;
  unresolvedComments: boolean;
}

// AI revision with diff-before-apply (design §4.3, §4.4). `c` (comment-driven) and `r` (one-line
// instruction) both land here. The proposed body is written to .revisions/ and shown as a diff; it
// only touches the real file when `confirm(diff)` resolves true.
export async function reviseArtifact(
  dir: string,
  session: DraftSession,
  model: ModelClient,
  file: string,
  instruction: string | undefined,
  confirm: (diff: string) => Promise<boolean>,
  userRequestedFlagship = false,
): Promise<RevisionResult> {
  const doc = readDraft(dir, file);
  const comments = extractComments(doc.body);
  const revisionCount = artifactRevisions(session, file);
  const flags = revisionFlags(revisionCount);
  if (userRequestedFlagship) flags.push("user-requested");
  const tier: Tier = selectTier({ task: "revise", revisionCount, flags });

  const newBody = await model.revise({ current: doc.body, instruction, comments }, tier);
  const diff = renderDiff(doc.body, newBody);
  const revPath = `.revisions/${file.replace(/\//g, "__")}`;
  writeFile(dir, revPath, newBody);
  appendAction(dir, instruction ? { kind: "revise", target: file, instruction } : { kind: "comment", target: file });

  const ok = await confirm(diff);
  appendAction(dir, { kind: "apply-revision", target: file, accepted: ok });
  if (!ok) return { applied: false, diff, unresolvedComments: false };

  writeDraft(dir, file, { data: doc.data, body: newBody });
  bumpRevisions(session, file);
  saveSession(dir, session);
  // Contract check (design §4.3): a revision must resolve every comment block.
  return { applied: true, diff, unresolvedComments: hasUnresolvedComments(newBody) };
}

// --- Story fan-out + consistency pass (design §6) ---

export async function fanOutStories(
  dir: string,
  session: DraftSession,
  model: ModelClient,
  templates: Templates,
  confirmManifest: (entries: StoryManifestEntry[]) => Promise<StoryManifestEntry[]>,
): Promise<DraftSession> {
  const epicBody = readDraft(dir, "epic.md").body;
  const intake = readFileRaw(dir, "intake.md");
  const manifestTier = selectTier({ task: "story-draft", revisionCount: 0, flags: [] });
  const proposed = await model.storyManifest({ epicBody, intake }, manifestTier);
  const entries = await confirmManifest(proposed);

  const drafts = await Promise.all(
    entries.map((entry, idx) =>
      model.draftStory(
        {
          epicBody,
          intake,
          entry,
          siblingTitles: entries.filter((_, i) => i !== idx).map((e) => e.title),
          storyTemplate: templates.story,
          briefTemplate: templates.brief,
        },
        selectTier({ task: "story-draft", revisionCount: 0, flags: [] }),
      ),
    ),
  );

  const stories: StoryState[] = [];
  entries.forEach((entry, idx) => {
    const seq = idx + 1;
    const slug = slugify(entry.title);
    const file = `stories/${String(seq).padStart(2, "0")}-${slug}.md`;
    const draft = drafts[idx]!;
    writeDraft(dir, file, {
      data: { kind: "story", epic: session.slug, sequence: seq, title: entry.title, status: "draft", sizing: entry.sizing, dependsOn: [] },
      body: draft.body,
    });
    writeFile(dir, `briefs/${String(seq).padStart(2, "0")}-${slug}.brief.md`, draft.brief);
    stories.push({ file, status: "draft", revisions: 0 });
  });
  session.stories = stories;

  consistencyPass(dir, session, templates);
  session.state = transition(session.state, "stories-drafted");
  saveSession(dir, session);
  return session;
}

// Structural consistency pass (design §6.2): verify the dependency graph is acyclic, renumber
// `sequence` topologically, and lint sizing (a story with >7 acceptance criteria is an epic in
// disguise — story-standards §1). Semantic coverage/dedup is a model-backed follow-up.
export function consistencyPass(dir: string, session: DraftSession, templates: Templates): string[] {
  const report: string[] = [];
  const bySlug = new Map<string, { file: string; deps: string[] }>();
  for (const s of session.stories) {
    const data = readDraft(dir, s.file).data;
    const deps = Array.isArray(data.dependsOn) ? data.dependsOn : [];
    bySlug.set(storyKey(s.file), { file: s.file, deps });
  }

  const order = topoSort(bySlug);
  if (order === null) {
    report.push("dependency cycle detected — left sequence unchanged");
  } else {
    order.forEach((key, idx) => {
      const entry = bySlug.get(key)!;
      const doc = readDraft(dir, entry.file);
      if (doc.data.sequence !== idx + 1) {
        doc.data.sequence = idx + 1;
        writeDraft(dir, entry.file, doc);
        report.push(`reordered ${entry.file} -> sequence ${idx + 1}`);
      }
    });
  }

  for (const s of session.stories) {
    const doc = readDraft(dir, s.file);
    const acCount = countAcceptanceCriteria(doc.body);
    if (acCount > 7) report.push(`${s.file}: ${acCount} acceptance criteria — consider a SPIDR split`);
    const missing = missingSections(templates.story, doc.body);
    if (missing.length) report.push(`${s.file}: missing sections ${missing.join(", ")}`);
  }
  return report;
}

// --- helpers ---

function extractTitle(body: string): string | null {
  for (const line of body.split("\n")) {
    const m = /^#\s+(?:Epic:\s*)?(.+)$/.exec(line.trim());
    if (m) return m[1]!.trim();
  }
  return null;
}

function setStatus(dir: string, file: string, status: string): void {
  const doc = readDraft(dir, file);
  doc.data.status = status;
  writeDraft(dir, file, doc);
}

function storyState(session: DraftSession, file: string): StoryState {
  const s = session.stories.find((x) => x.file === file);
  if (!s) throw new Error(`unknown story: ${file}`);
  return s;
}

function artifactRevisions(session: DraftSession, file: string): number {
  return file === "epic.md" ? session.epic.revisions : storyState(session, file).revisions;
}

function bumpRevisions(session: DraftSession, file: string): void {
  if (file === "epic.md") session.epic.revisions++;
  else storyState(session, file).revisions++;
}

function storyKey(file: string): string {
  return file.replace(/^stories\//, "").replace(/\.md$/, "");
}

function countAcceptanceCriteria(body: string): number {
  const lines = body.split("\n");
  let inAc = false;
  let count = 0;
  for (const line of lines) {
    if (line.startsWith("## ")) inAc = /acceptance criteria/i.test(line);
    else if (inAc && /^\s*(\d+\.|[-*])\s+/.test(line)) count++;
  }
  return count;
}

// Kahn's algorithm; returns null on a cycle. Keys are story slugs; a dep that names a non-existent
// story is ignored (it can't constrain ordering).
function topoSort(graph: Map<string, { deps: string[] }>): string[] | null {
  // Edge: prerequisite -> dependent. indegree counts the prerequisites of each node.
  const indeg = new Map<string, number>();
  const dependents = new Map<string, string[]>();
  for (const key of graph.keys()) {
    indeg.set(key, 0);
    dependents.set(key, []);
  }
  for (const [key, { deps }] of graph) {
    for (const d of deps) {
      if (!graph.has(d)) continue;
      dependents.get(d)!.push(key);
      indeg.set(key, (indeg.get(key) ?? 0) + 1);
    }
  }
  const queue = [...indeg].filter(([, n]) => n === 0).map(([k]) => k).sort();
  const out: string[] = [];
  while (queue.length) {
    const node = queue.shift()!;
    out.push(node);
    for (const dep of dependents.get(node)!) {
      indeg.set(dep, (indeg.get(dep) ?? 0) - 1);
      if (indeg.get(dep) === 0) queue.push(dep);
    }
    queue.sort();
  }
  return out.length === graph.size ? out : null;
}
