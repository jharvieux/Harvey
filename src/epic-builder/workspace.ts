// Filesystem-backed workspace (design §3.2, §4.1). The filesystem is the source of truth: session
// state lives in session.json (rewritten atomically on every transition), draft content lives in
// the .md files. A crash or Ctrl-C between calls loses nothing because every mutation lands on disk.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { SESSION_STATES, type DraftSession, type ReviewAction, type SessionState, type StoryManifestEntry } from "./types.js";
import { parseFrontmatter, serializeFrontmatter, type ParsedDoc } from "./frontmatter.js";

const ROOT_DIR = ".epic-builder";

export function slugify(prompt: string): string {
  const words = prompt
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 5);
  const slug = words.join("-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  return slug || "epic";
}

export function validateStoryManifest(value: unknown, source = "model"): StoryManifestEntry[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${source} story manifest must contain at least one entry`);
  }
  const titles = new Set<string>();
  const slugs = new Set<string>();
  return value.map((candidate, index) => {
    if (!candidate || typeof candidate !== "object") {
      throw new Error(`${source} story manifest entry ${index + 1} is not an object`);
    }
    const entry = candidate as Partial<StoryManifestEntry>;
    if (typeof entry.title !== "string" || entry.title.trim() === ""
        || typeof entry.scope !== "string" || entry.scope.trim() === ""
        || (entry.sizing !== "S" && entry.sizing !== "M" && entry.sizing !== "L")) {
      throw new Error(`${source} story manifest entry ${index + 1} needs a nonempty title/scope and sizing S, M, or L`);
    }
    const titleKey = entry.title.trim().toLocaleLowerCase("en-US");
    const slug = slugify(entry.title);
    if (titles.has(titleKey) || slugs.has(slug)) {
      throw new Error(`${source} story manifest entry ${index + 1} duplicates an earlier title or file slug`);
    }
    titles.add(titleKey);
    slugs.add(slug);
    return { title: entry.title, scope: entry.scope, sizing: entry.sizing };
  });
}

export function workspaceDir(cwd: string, slug: string): string {
  return join(cwd, ROOT_DIR, slug);
}

export function workspaceExists(cwd: string, slug: string): boolean {
  return existsSync(join(workspaceDir(cwd, slug), "session.json"));
}

export function createWorkspace(cwd: string, prompt: string): { slug: string; dir: string; session: DraftSession } {
  let slug = slugify(prompt);
  // Avoid clobbering an existing workspace with the same derived slug.
  if (workspaceExists(cwd, slug)) {
    let n = 2;
    while (workspaceExists(cwd, `${slug}-${n}`)) n++;
    slug = `${slug}-${n}`;
  }
  const dir = workspaceDir(cwd, slug);
  mkdirSync(join(dir, "stories"), { recursive: true });
  mkdirSync(join(dir, "briefs"), { recursive: true });
  const session: DraftSession = {
    version: 1,
    slug,
    state: "intake",
    prompt,
    createdAt: new Date().toISOString(),
    clarifyRounds: 0,
    epic: { status: "draft", revisions: 0 },
    stories: [],
    publish: { adapter: "github", attempts: 0 },
  };
  saveSession(dir, session);
  return { slug, dir, session };
}

export function loadSession(dir: string): DraftSession {
  const parsed = JSON.parse(readFileSync(join(dir, "session.json"), "utf8")) as Partial<DraftSession>;
  if (!SESSION_STATES.includes(parsed.state as SessionState)) {
    throw new Error(`session.json has invalid state ${JSON.stringify(parsed.state)}`);
  }
  return parsed as DraftSession;
}

// Atomic: write a temp file then rename, so a crash mid-write can never leave a truncated session.
export function saveSession(dir: string, session: DraftSession): void {
  const target = join(dir, "session.json");
  const tmp = `${target}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(session, null, 2)}\n`);
  renameSync(tmp, target);
}

export function readDraft(dir: string, relPath: string): ParsedDoc {
  return parseFrontmatter(readFileSync(join(dir, relPath), "utf8"), { required: true });
}

export function draftExists(dir: string, relPath: string): boolean {
  return existsSync(join(dir, relPath));
}

export function readFileRaw(dir: string, relPath: string): string {
  return readFileSync(join(dir, relPath), "utf8");
}

export function writeDraft(dir: string, relPath: string, doc: ParsedDoc): void {
  const target = join(dir, relPath);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, serializeFrontmatter(doc.data, doc.body));
}

export function writeFile(dir: string, relPath: string, contents: string): void {
  const target = join(dir, relPath);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

export function appendAction(dir: string, action: ReviewAction): void {
  const target = join(dir, "actions.log");
  const prior = existsSync(target) ? readFileSync(target, "utf8") : "";
  writeFileSync(target, `${prior}${JSON.stringify(action)}\n`);
}

export function listWorkspaces(cwd: string): { slug: string; state: string }[] {
  const root = join(cwd, ROOT_DIR);
  if (!existsSync(root)) return [];
  const out: { slug: string; state: string }[] = [];
  for (const entry of readEntriesSafe(root).entries) {
    if (!entry.isDirectory) continue;
    const dir = join(root, entry.name);
    if (!existsSync(join(dir, "session.json"))) continue;
    out.push({ slug: entry.name, state: loadSession(dir).state });
  }
  return out;
}
