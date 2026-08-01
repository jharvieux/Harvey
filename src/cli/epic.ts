// Epic builder CLI (design §2.1). Operator-run, single readline REPL — no TUI.
//
//   pnpm epic new "<one-paragraph idea>"      start a workspace and walk the flow
//   pnpm epic resume <slug>                    resume at the saved state
//   pnpm epic list                             list workspaces and their states
//   pnpm epic publish <slug> [--dry-run]       publish (or preview) to the tracker
//
// The "AI" steps use the offline ScaffoldModelClient by default; wire a live model by swapping it.
// Publishing needs GITHUB_TOKEN + GITHUB_OWNER + GITHUB_REPO (skipped for --dry-run).

import "./sync-stdio.js";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { GitHubTracker } from "../trackers/github.js";
import type { Tracker } from "../trackers/types.js";
import { ScaffoldModelClient } from "../epic-builder/model-scaffold.js";
import type { ClarifyQuestion, DraftSession, ModelClient, StoryManifestEntry } from "../epic-builder/types.js";
import { publish, NoopTracker } from "../epic-builder/publish.js";
import {
  acceptEpic,
  acceptStory,
  draftEpic,
  fanOutStories,
  recordDirectEdit,
  reviseArtifact,
  runClarify,
  skipStory,
  type Templates,
} from "../epic-builder/session.js";
import {
  createWorkspace,
  listWorkspaces,
  loadSession,
  readFileRaw,
  saveSession,
  workspaceDir,
  workspaceExists,
} from "../epic-builder/workspace.js";

function loadTemplates(cwd: string): Templates {
  const read = (name: string) => readFileSync(join(cwd, "docs", "templates", name), "utf8");
  return { epic: read("epic.md"), story: read("user-story.md"), brief: read("implementation-brief.md") };
}

// A prompt reader that queues every input line via the 'line' event, so lines that arrive between
// two prompts (the common case with piped/batch input) are never dropped — the failure mode of
// awaiting readline/promises' question() sequentially.
interface Prompter {
  question(prompt: string): Promise<string>;
  close(): void;
}

function makePrompter(): Prompter {
  const rl = createInterface({ input: process.stdin, terminal: false });
  const queue: string[] = [];
  const waiters: ((line: string) => void)[] = [];
  let closed = false;
  rl.on("line", (line) => {
    const waiter = waiters.shift();
    if (waiter) waiter(line);
    else queue.push(line);
  });
  rl.on("close", () => {
    closed = true;
    while (waiters.length) waiters.shift()!("");
  });
  return {
    question(prompt: string): Promise<string> {
      process.stdout.write(prompt);
      const queued = queue.shift();
      if (queued !== undefined) return Promise.resolve(queued);
      if (closed) return Promise.resolve("");
      return new Promise((resolve) => waiters.push(resolve));
    },
    close: () => rl.close(),
  };
}

async function reviewLoop(
  rl: Prompter,
  dir: string,
  session: DraftSession,
  model: ModelClient,
  file: string,
  allowSkip: boolean,
): Promise<"accepted" | "skipped" | "quit"> {
  for (;;) {
    console.log(`\n--- ${file} ---\n${readFileRaw(dir, file)}\n`);
    const menu = `[a] accept  [e] edit in $EDITOR  [c] apply comments  [r] revise (one line)${allowSkip ? "  [s] skip" : ""}  [q] quit`;
    const choice = (await rl.question(`${menu}\n> `)).trim().toLowerCase();
    if (choice === "a") return "accepted";
    if (choice === "s" && allowSkip) return "skipped";
    if (choice === "q") return "quit";
    if (choice === "e") {
      openEditor(join(dir, file));
      recordDirectEdit(dir, session, file);
      continue;
    }
    if (choice === "c" || choice === "r" || choice === "r!") {
      const instruction = choice.startsWith("r") ? await rl.question("Instruction: ") : undefined;
      const result = await reviseArtifact(
        dir,
        session,
        model,
        file,
        instruction,
        async (diff) => {
          console.log(`\n${diff}\n`);
          return (await rl.question("Apply this revision? [y] apply  [n] discard\n> ")).trim().toLowerCase() === "y";
        },
        choice === "r!",
      );
      if (result.applied && result.unresolvedComments) {
        console.log("⚠ some comment blocks were not resolved by the revision — review the file.");
      }
      continue;
    }
    console.log("Unrecognized choice.");
  }
}

function openEditor(path: string): void {
  const editor = process.env.EDITOR ?? "vi";
  spawnSync(editor, [path], { stdio: "inherit" });
}

async function runNew(rl: Prompter, cwd: string, prompt: string, model: ModelClient): Promise<void> {
  const { dir, session } = createWorkspace(cwd, prompt);
  console.log(`Created workspace ${session.slug} at ${workspaceDir(cwd, session.slug)}`);
  await drive(rl, cwd, dir, session, model);
}

async function runResume(rl: Prompter, cwd: string, slug: string, model: ModelClient): Promise<void> {
  if (!workspaceExists(cwd, slug)) throw new Error(`no workspace: ${slug}`);
  const dir = workspaceDir(cwd, slug);
  const session = loadSession(dir);
  if (session.state === "done") {
    console.log(readFileRaw(dir, "summary.md"));
    return;
  }
  await drive(rl, cwd, dir, session, model);
}

// Walk the state machine from wherever the session currently is.
async function drive(rl: Prompter, cwd: string, dir: string, session: DraftSession, model: ModelClient): Promise<void> {
  const templates = loadTemplates(cwd);

  if (session.state === "intake" || session.state === "clarify") {
    await runClarify(dir, session, model, async (questions: ClarifyQuestion[], round: number) => {
      console.log(`\nClarifying questions (round ${round}):`);
      questions.forEach((q, i) => console.log(`  ${i + 1}. ${q.question} [assume: ${q.assumption}]`));
      return rl.question('Answer by number, or "defaults": ');
    });
  }
  if (session.state === "epic-draft") await draftEpic(dir, session, model, templates);
  if (session.state === "epic-review") {
    const outcome = await reviewLoop(rl, dir, session, model, "epic.md", false);
    if (outcome === "quit") return void console.log("Session saved.");
    acceptEpic(dir, session);
  }
  if (session.state === "stories-fan-out") {
    await fanOutStories(dir, session, model, templates, async (entries: StoryManifestEntry[]) => {
      console.log("\nProposed stories:");
      entries.forEach((e, i) => console.log(`  ${i + 1}. ${e.title} (${e.sizing}) — ${e.scope}`));
      const reply = (await rl.question('Accept manifest? [enter] yes, or comma-separated numbers to keep: ')).trim();
      if (!reply) return entries;
      const keep = new Set(reply.split(",").map((s) => Number(s.trim()) - 1));
      return entries.filter((_, i) => keep.has(i));
    });
  }
  if (session.state === "stories-review") {
    for (const story of session.stories) {
      if (story.status === "accepted" || story.status === "skipped") continue;
      const outcome = await reviewLoop(rl, dir, session, model, story.file, true);
      if (outcome === "quit") return void console.log("Session saved.");
      if (outcome === "skipped") skipStory(dir, session, story.file);
      else acceptStory(dir, session, story.file);
    }
  }
  if (session.state === "publish") {
    console.log(`\nAll stories accepted. Run: pnpm epic publish ${session.slug} --dry-run`);
  }
}

function makeTracker(dryRun: boolean): Tracker {
  if (dryRun) return new NoopTracker();
  const token = requireEnv("GITHUB_TOKEN");
  const owner = requireEnv("GITHUB_OWNER");
  const repo = requireEnv("GITHUB_REPO");
  return new GitHubTracker({ token, owner, repo });
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required for publishing (use --dry-run to preview without it)`);
  return v;
}

async function runPublish(cwd: string, slug: string, dryRun: boolean): Promise<void> {
  if (!workspaceExists(cwd, slug)) throw new Error(`no workspace: ${slug}`);
  const dir = workspaceDir(cwd, slug);
  const session = loadSession(dir);
  if (session.state !== "publish" && session.state !== "summary" && session.state !== "done") {
    throw new Error(`workspace ${slug} is in state "${session.state}" — accept the epic and all stories first`);
  }
  session.publish.attempts++;
  saveSession(dir, session);
  // publish() throws (via trackerFetch) on any adapter failure, so reaching here means the whole
  // plan succeeded and the session is terminal. A partial failure leaves the state at "publish" for
  // an idempotent re-run.
  const outcome = await publish(dir, session, makeTracker(dryRun), { dryRun });
  console.log(`\n${outcome.summary}`);
  console.log(`${dryRun ? "[dry-run] " : ""}created ${outcome.created}, skipped ${outcome.skipped}`);
  if (!dryRun) {
    session.state = "done";
    saveSession(dir, session);
  }
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const cwd = process.cwd();
  const model = new ScaffoldModelClient();

  if (command === "list") {
    for (const w of listWorkspaces(cwd)) console.log(`${w.slug.padEnd(30)} ${w.state}`);
    return;
  }
  if (command === "publish") {
    const slug = rest.find((a) => !a.startsWith("--"));
    if (!slug) throw new Error("usage: epic publish <slug> [--dry-run]");
    await runPublish(cwd, slug, rest.includes("--dry-run"));
    return;
  }

  const rl = makePrompter();
  try {
    if (command === "new") {
      const prompt = rest.join(" ").trim();
      if (!prompt) throw new Error('usage: epic new "<one-paragraph idea>"');
      await runNew(rl, cwd, prompt, model);
    } else if (command === "resume") {
      const slug = rest[0];
      if (!slug) throw new Error("usage: epic resume <slug>");
      await runResume(rl, cwd, slug, model);
    } else {
      console.error('usage: epic <new|resume|list|publish> ...');
      process.exitCode = 2;
    }
  } finally {
    rl.close();
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
