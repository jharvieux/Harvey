// The wrap layer (design docs/design/epic-builder-web.md §2). This is the ONLY new flow logic in
// the web app: it adapts stateless HTTP request/response onto the existing src/epic-builder core,
// whose controller functions expect synchronous human-decision callbacks. Every function takes its
// dependencies injected (model, per-user workspace root, templates, tracker factory) so the whole
// draft->revise->publish path is provable in-process with a fake model and a mocked tracker — no
// Next server, no live model, no live GitHub. The core itself is imported unmodified.

import type { Templates } from "../../src/epic-builder/session.js";
import {
  acceptEpic,
  acceptStory,
  draftEpic,
  fanOutStories,
  recordDirectEdit,
  reviseArtifact,
  runClarify,
  skipStory,
} from "../../src/epic-builder/session.js";
import { publish, NoopTracker } from "../../src/epic-builder/publish.js";
import {
  createWorkspace,
  loadSession,
  readDraft,
  readFileRaw,
  saveSession,
  workspaceDir,
  workspaceExists,
  writeDraft,
} from "../../src/epic-builder/workspace.js";
import type {
  ClarifyQuestion,
  DraftSession,
  ModelClient,
  SessionState,
  StoryManifestEntry,
} from "../../src/epic-builder/types.js";
import type { Tracker } from "../../src/trackers/types.js";

export interface CoreDeps {
  model: ModelClient;
  /** Per-user workspace root; the core creates ${cwd}/.epic-builder/<slug>/ under it. */
  cwd: string;
  templates: Templates;
  /** Real GitHubTracker for a live publish, NoopTracker for a dry run. */
  makeTracker: (dryRun: boolean) => Tracker;
}

// The shape every screen needs: workflow position plus the artifact currently under review.
export interface ViewState {
  slug: string;
  state: SessionState;
  reviewTarget: string | null; // "epic.md" | "stories/NN-*.md" | null
  body: string | null; // body of reviewTarget (frontmatter stripped), for the editor
  stories: { file: string; title: string; status: string }[];
  summary: string | null;
}

function dirFor(deps: CoreDeps, slug: string): string {
  if (!workspaceExists(deps.cwd, slug)) throw new Error(`no workspace: ${slug}`);
  return workspaceDir(deps.cwd, slug);
}

// The artifact the current state wants a decision on: the epic in epic-review, else the first story
// still awaiting review. null in non-review states (fan-out, publish, done).
function currentTarget(session: DraftSession): string | null {
  if (session.state === "epic-draft" || session.state === "epic-review") return "epic.md";
  if (session.state === "stories-review") {
    const next = session.stories.find((s) => s.status === "draft" || s.status === "in-review");
    return next ? next.file : null;
  }
  return null;
}

function view(dir: string, session: DraftSession): ViewState {
  const target = currentTarget(session);
  const stories = session.stories.map((s) => {
    const data = readDraft(dir, s.file).data;
    return { file: s.file, title: String(data.title ?? s.file), status: s.status };
  });
  const summary =
    session.state === "summary" || session.state === "done" ? safeRead(dir, "summary.md") : null;
  return {
    slug: session.slug,
    state: session.state,
    reviewTarget: target,
    body: target ? readDraft(dir, target).body : null,
    stories,
    summary,
  };
}

function safeRead(dir: string, rel: string): string | null {
  try {
    return readFileRaw(dir, rel);
  } catch {
    return null;
  }
}

// --- intake: create the workspace, preview round-1 clarifying questions (design §3) ---
export async function startSession(
  deps: CoreDeps,
  prompt: string,
): Promise<{ slug: string; questions: ClarifyQuestion[] }> {
  const { session } = createWorkspace(deps.cwd, prompt);
  const questions = await deps.model.clarify({ prompt, round: 1, priorQA: "" }, "standard");
  return { slug: session.slug, questions };
}

// --- clarify -> epic draft. runClarify is driven with an answer callback that returns the posted
// answers for round 1 and "defaults" after, so a single web submission completes the (MVP: one-round)
// clarify loop; then draft the epic and land in epic-review. ---
export async function submitClarify(deps: CoreDeps, slug: string, answers: string): Promise<ViewState> {
  const dir = dirFor(deps, slug);
  const session = loadSession(dir);
  let answered = false;
  await runClarify(dir, session, deps.model, async () => {
    if (answered) return "defaults";
    answered = true;
    return answers.trim() || "defaults";
  });
  await draftEpic(dir, session, deps.model, deps.templates);
  return view(dir, session);
}

export function getState(deps: CoreDeps, slug: string): ViewState {
  const dir = dirFor(deps, slug);
  return view(dir, loadSession(dir));
}

export type ReviewInput =
  | { action: "accept"; target: string }
  | { action: "skip"; target: string }
  | { action: "edit"; target: string; body: string }
  | { action: "revise"; target: string; instruction: string; body?: string }
  | { action: "comment"; target: string; body: string };

export interface ReviewResult extends ViewState {
  applied?: boolean;
  diff?: string;
  unresolvedComments?: boolean;
}

// One review-menu action against the epic or a story (design §2.3, §3). Revise/comment auto-apply and
// return the diff for the browser to show (the web MVP's apply-then-show-diff, §3); direct edit writes
// the posted body verbatim (the user is the author, no diff).
export async function reviewAction(deps: CoreDeps, slug: string, input: ReviewInput): Promise<ReviewResult> {
  const dir = dirFor(deps, slug);
  const session = loadSession(dir);

  switch (input.action) {
    case "accept": {
      if (input.target === "epic.md") acceptEpic(dir, session);
      else acceptStory(dir, session, input.target);
      return view(dir, session);
    }
    case "skip": {
      skipStory(dir, session, input.target);
      return view(dir, session);
    }
    case "edit": {
      writeBody(dir, input.target, input.body);
      recordDirectEdit(dir, session, input.target);
      return view(dir, session);
    }
    case "revise":
    case "comment": {
      if (input.body !== undefined) writeBody(dir, input.target, input.body);
      const instruction = input.action === "revise" ? input.instruction : undefined;
      const result = await reviseArtifact(dir, session, deps.model, input.target, instruction, async () => true);
      return {
        ...view(dir, loadSession(dir)),
        applied: result.applied,
        diff: result.diff,
        unresolvedComments: result.unresolvedComments,
      };
    }
  }
}

// --- story fan-out (design §6). Preview the manifest, then draft the kept subset. ---
export async function previewManifest(deps: CoreDeps, slug: string): Promise<StoryManifestEntry[]> {
  const dir = dirFor(deps, slug);
  const session = loadSession(dir);
  const epicBody = readDraft(dir, "epic.md").body;
  const intake = readFileRaw(dir, "intake.md");
  return deps.model.storyManifest({ epicBody, intake }, "standard");
}

export async function fanOut(deps: CoreDeps, slug: string, keep?: number[]): Promise<ViewState> {
  const dir = dirFor(deps, slug);
  const session = loadSession(dir);
  const keepSet = keep ? new Set(keep) : null;
  await fanOutStories(dir, session, deps.model, deps.templates, async (entries) =>
    keepSet ? entries.filter((_, i) => keepSet.has(i)) : entries,
  );
  return view(dir, session);
}

// --- publish (design §8). Dry run uses NoopTracker; a real run uses the injected GitHubTracker and,
// on success, marks the session done. Safe to re-run: the orchestrator only creates what has no
// published record yet. ---
export interface PublishResult {
  summary: string;
  created: number;
  skipped: number;
  dryRun: boolean;
  epicUrl: string;
  storyUrls: { file: string; url: string }[];
}

export async function runPublish(deps: CoreDeps, slug: string, dryRun: boolean): Promise<PublishResult> {
  const dir = dirFor(deps, slug);
  const session = loadSession(dir);
  if (session.state !== "publish" && session.state !== "summary" && session.state !== "done") {
    throw new Error(`workspace ${slug} is in state "${session.state}" — accept the epic and all stories first`);
  }
  session.publish.attempts++;
  saveSession(dir, session);
  const outcome = await publish(dir, session, deps.makeTracker(dryRun), { dryRun });
  if (!dryRun) {
    session.state = "done";
    saveSession(dir, session);
  }
  return {
    summary: outcome.summary,
    created: outcome.created,
    skipped: outcome.skipped,
    dryRun,
    epicUrl: outcome.epicRef.url,
    storyUrls: outcome.storyRefs.map((r) => ({ file: r.file, url: r.ref.url })),
  };
}

// Write only the body of a draft, preserving the core-managed frontmatter (design §3 direct-edit).
function writeBody(dir: string, file: string, body: string): void {
  const doc = readDraft(dir, file);
  writeDraft(dir, file, { data: doc.data, body });
}

export { NoopTracker };
