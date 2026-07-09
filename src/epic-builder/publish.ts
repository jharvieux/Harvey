// Publish orchestrator (design §8.2–§8.4). Adapters are dumb transport; this owns sequencing
// (epic -> stories in dependency order -> briefs), idempotency, and partial-failure recovery.
//
// Idempotency is belt-and-suspenders (design §8.2):
//   1. Local record: each artifact's `published` frontmatter block is written immediately after
//      its create call succeeds, and a re-run skips any artifact that already carries one.
//   2. Remote marker (#50): when an artifact has no local record, the orchestrator calls
//      `tracker.findByMarker()` for the hidden marker comment before creating anything. A hit
//      means a prior run created the item remotely but crashed before the frontmatter write —
//      the local record is repaired from the found ref instead of creating a duplicate.
//
// Brief linking (#50): a story's brief URL is only known after createStory returns, so once
// attachBrief succeeds the orchestrator calls `tracker.updateStory()` to push a brief link line
// into the story's remote body (frontmatter alone isn't visible to whoever reads the tracker item).

import type { Tracker, CreatedRef, ItemInput, AttachedRef } from "../trackers/types.js";
import type { DraftSession, PublishedRef, StoryState } from "./types.js";
import { draftExists, readDraft, readFileRaw, writeDraft, writeFile } from "./workspace.js";
import { contentHash, renderStoryBody, renderSummary, type SummaryRow } from "./render.js";
import type { FrontmatterData } from "./frontmatter.js";

interface PublishOptions {
  dryRun?: boolean;
}

interface PublishOutcome {
  epicRef: PublishedRef;
  storyRefs: { file: string; ref: PublishedRef }[];
  created: number;
  skipped: number;
  summary: string;
}

function markerText(slug: string, artifact: string): string {
  return `<!-- epic-builder:${slug}/${artifact} -->`;
}

function marker(slug: string, artifact: string): string {
  return `\n\n${markerText(slug, artifact)}\n`;
}

function readPublished(data: FrontmatterData): PublishedRef | null {
  const p = data.published;
  if (!p || typeof p !== "object" || Array.isArray(p)) return null;
  const rec = p as Record<string, string>;
  if (!rec.ref || !rec.url) return null;
  return { adapter: rec.adapter ?? "github", ref: rec.ref, url: rec.url, contentHash: rec.contentHash ?? "" };
}

function writePublished(data: FrontmatterData, ref: PublishedRef): void {
  data.status = "accepted";
  data.published = { adapter: ref.adapter, ref: ref.ref, url: ref.url, contentHash: ref.contentHash };
}

// Publish an already-accepted workspace. Safe to run repeatedly: only creates what has no
// `published` record yet. On a content-hash mismatch it warns and skips (update is post-MVP, §8.2).
export async function publish(
  dir: string,
  session: DraftSession,
  tracker: Tracker,
  opts: PublishOptions = {},
): Promise<PublishOutcome> {
  const persist = !opts.dryRun;
  const warnings: string[] = [];
  let created = 0;
  let skipped = 0;

  // --- Epic ---
  const epicDoc = readDraft(dir, "epic.md");
  const epicTitle = String(epicDoc.data.title ?? session.slug);
  const epicHash = contentHash(epicDoc.body);
  let epicRef = readPublished(epicDoc.data);
  if (epicRef) {
    if (epicRef.contentHash !== epicHash) warnings.push(`epic changed since publish — skipping (re-publish not supported in MVP)`);
    skipped++;
  } else {
    const recovered = await tracker.findByMarker(markerText(session.slug, "epic"));
    if (recovered) {
      epicRef = { adapter: "github", ref: recovered.id, url: recovered.url, contentHash: epicHash };
      if (persist) {
        writePublished(epicDoc.data, epicRef);
        writeDraft(dir, "epic.md", epicDoc);
      }
      skipped++;
    } else {
      const input: ItemInput = { title: epicTitle, description: epicDoc.body + marker(session.slug, "epic") };
      const ref = await createEpicRef(tracker, input, epicHash);
      epicRef = ref;
      if (persist) {
        await tracker.setLabels(ref.ref, ["epic"]);
        writePublished(epicDoc.data, ref);
        writeDraft(dir, "epic.md", epicDoc);
      }
      created++;
    }
  }

  // --- Stories, in dependency (sequence) order ---
  const ordered = [...session.stories].filter((s) => s.status !== "skipped").sort(bySequence(dir));
  const storyRefs: { file: string; ref: PublishedRef }[] = [];
  const refByStorySlug = new Map<string, PublishedRef>();

  for (const story of ordered) {
    const doc = readDraft(dir, story.file);
    const storyTitle = String(doc.data.title ?? story.file);
    const bodyHash = contentHash(doc.body);
    let ref = readPublished(doc.data);
    if (ref) {
      if (ref.contentHash !== bodyHash) warnings.push(`${story.file} changed since publish — skipping`);
      skipped++;
    } else {
      const slug = storySlug(story.file);
      const recovered = await tracker.findByMarker(markerText(session.slug, slug));
      if (recovered) {
        ref = { adapter: "github", ref: recovered.id, url: recovered.url, contentHash: bodyHash };
        if (persist) {
          writePublished(doc.data, ref);
          writeDraft(dir, story.file, doc);
        }
        skipped++;
      } else {
        const depSlugs = Array.isArray(doc.data.dependsOn) ? doc.data.dependsOn : [];
        const depRefs = depSlugs
          .map((s) => refByStorySlug.get(s))
          .filter((r): r is PublishedRef => r !== undefined)
          .map((r) => `#${r.ref}`);
        const body = renderStoryBody(doc.body, depRefs) + marker(session.slug, slug);
        const createdRef: CreatedRef = await tracker.createStory({ title: storyTitle, description: body }, epicRef.ref);
        ref = { adapter: "github", ref: createdRef.id, url: createdRef.url, contentHash: bodyHash };
        if (persist) {
          const sizing = String(doc.data.sizing ?? "M");
          await tracker.setLabels(ref.ref, ["story", `size:${sizing}`]);
          const brief = readBrief(dir, story.file);
          if (brief) {
            const attached: AttachedRef = await tracker.attachBrief(ref.ref, brief);
            (doc.data as FrontmatterData).brief = attached.url;
            const linked = `${body}\n\n📄 Implementation brief: ${attached.url}\n`;
            await tracker.updateStory(ref.ref, { body: linked });
          }
          writePublished(doc.data, ref);
          writeDraft(dir, story.file, doc);
        }
        created++;
      }
    }
    refByStorySlug.set(storySlug(story.file), ref);
    storyRefs.push({ file: story.file, ref });
  }

  const summary = buildSummary(dir, session, epicRef, storyRefs, warnings);
  if (persist) writeFile(dir, "summary.md", summary);
  return { epicRef, storyRefs, created, skipped, summary };
}

async function createEpicRef(tracker: Tracker, input: ItemInput, hash: string): Promise<PublishedRef> {
  const ref: CreatedRef = await tracker.createEpic(input);
  return { adapter: "github", ref: ref.id, url: ref.url, contentHash: hash };
}

function bySequence(dir: string): (a: StoryState, b: StoryState) => number {
  const seq = (s: StoryState) => Number(readDraft(dir, s.file).data.sequence ?? 0);
  return (a, b) => seq(a) - seq(b);
}

function storySlug(file: string): string {
  return file.replace(/^stories\//, "").replace(/\.md$/, "");
}

function readBrief(dir: string, storyFile: string): string | null {
  const briefPath = `briefs/${storySlug(storyFile)}.brief.md`;
  return draftExists(dir, briefPath) ? readFileRaw(dir, briefPath) : null;
}

function buildSummary(
  dir: string,
  session: DraftSession,
  epicRef: PublishedRef,
  storyRefs: { file: string; ref: PublishedRef }[],
  warnings: string[],
): string {
  const rows: SummaryRow[] = [
    { seq: "—", title: String(readDraft(dir, "epic.md").data.title ?? session.slug), type: "epic", size: "—", ref: epicRef.ref, brief: "—" },
  ];
  for (const { file, ref } of storyRefs) {
    const doc = readDraft(dir, file);
    rows.push({
      seq: String(doc.data.sequence ?? "").padStart(2, "0"),
      title: String(doc.data.title ?? file),
      type: "story",
      size: String(doc.data.sizing ?? "—"),
      ref: ref.ref,
      brief: doc.data.brief ? "linked ✓" : "—",
    });
  }
  const table = renderSummary(rows, epicRef.url);
  return warnings.length ? `${table}\nWarnings:\n${warnings.map((w) => `  - ${w}`).join("\n")}\n` : table;
}

// No-op tracker for `--dry-run`: fabricates deterministic refs so the full plan can be printed
// without touching the remote (design §8.3).
export class NoopTracker implements Tracker {
  #n = 0;
  async createEpic(): Promise<CreatedRef> {
    return this.#next();
  }
  async createStory(): Promise<CreatedRef> {
    return this.#next();
  }
  async setLabels(): Promise<void> {}
  async setEstimate(): Promise<void> {}
  async attachBrief(id: string): Promise<AttachedRef> {
    return { url: `dry-run://brief/${id}` };
  }
  // A dry run fabricates a fresh plan every time — nothing pre-exists remotely to recover.
  async findByMarker(): Promise<CreatedRef | null> {
    return null;
  }
  async updateStory(): Promise<void> {}
  #next(): CreatedRef {
    const id = ++this.#n;
    return { id: `DRY-${id}`, url: `dry-run://item/${id}` };
  }
}
