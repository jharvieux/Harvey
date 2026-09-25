// Publish orchestrator (design §8.2–§8.4). Adapters are dumb transport; this owns sequencing
// (epic -> stories in dependency order -> briefs), idempotency, and partial-failure recovery.
//
// Remote identity and each completed publication stage are recorded separately. A recovered
// identity proves creation, not completion of labels, links or brief delivery.

import type { Tracker, CreatedRef, ItemInput, AttachedRef } from "../trackers/types.js";
import type { DraftSession, PublishedRef, StoryState } from "./types.js";
import { draftExists, readDraft, readFileRaw, writeDraft, writeFile } from "./workspace.js";
import { contentHash, renderStoryBody, renderSummary, type SummaryRow } from "./render.js";
import { assertTrackerRef, PartialTrackerWriteError } from "../trackers/recovery.js";
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

// Stage receipts distinguish remote creation from completion. Legacy receipts resume
// metadata and brief stages from their saved remote identity.
function publication(data: FrontmatterData): Record<string, string> | undefined {
  const value = data.publication;
  return value && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}

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
  const save = (file: string, doc: ReturnType<typeof readDraft>): void => {
    if (persist) writeDraft(dir, file, doc);
  };
  const reference = (ref: CreatedRef, hash: string): PublishedRef => ({ adapter: "github", ref: ref.id, url: ref.url, contentHash: hash });
  const remember = (file: string, doc: ReturnType<typeof readDraft>, ref: PublishedRef): void => {
    writePublished(doc.data, ref);
    doc.data.publication = { state: "pending" };
    save(file, doc);
  };
  const completeMetadata = async (ref: PublishedRef, input: ItemInput, labels: string[], epicId?: string): Promise<void> => {
    if (!tracker.completeStory) throw new Error("Tracker cannot safely resume incomplete publication metadata");
    await tracker.completeStory(ref.ref, input, labels, epicId);
  };

  const epicDoc = readDraft(dir, "epic.md");
  const epicHash = contentHash(epicDoc.body);
  const epicInput = { title: String(epicDoc.data.title ?? session.slug), description: epicDoc.body + marker(session.slug, "epic") };
  let epicRef = readPublished(epicDoc.data);
  let epicCreated = false;
  if (epicRef) {
    if (!publication(epicDoc.data) && epicRef.contentHash === epicHash) {
      epicDoc.data.publication = { state: "pending" };
      save("epic.md", epicDoc);
    }
    if (epicRef.contentHash !== epicHash) {
      if (publication(epicDoc.data)?.state === "pending") throw new Error("Epic changed during incomplete publication; restore the accepted draft before resuming");
      warnings.push("epic changed since publish — skipping (re-publish not supported in MVP)");
    }
    skipped++;
  } else {
    const recovered = await tracker.findByMarker(markerText(session.slug, "epic"));
    const remote = recovered ?? await tracker.createEpic(epicInput);
    epicRef = reference(remote, epicHash);
    remember("epic.md", epicDoc, epicRef);
    if (recovered) skipped++;
    else { created++; epicCreated = true; }
  }
  if (persist && publication(epicDoc.data)?.state === "pending") {
    try {
      if (epicCreated) await tracker.setLabels(epicRef.ref, ["epic"]);
      else await completeMetadata(epicRef, epicInput, ["epic"]);
      epicDoc.data.publication = { state: "complete" };
      save("epic.md", epicDoc);
    } catch (error) { throw new PartialTrackerWriteError({ id: epicRef.ref, url: epicRef.url }, "epic labels", error); }
  }

  const ordered = [...session.stories].filter((s) => s.status !== "skipped").sort(bySequence(dir));
  const storyRefs: { file: string; ref: PublishedRef }[] = [];
  const refByStorySlug = new Map<string, PublishedRef>();
  for (const story of ordered) {
    const doc = readDraft(dir, story.file);
    const bodyHash = contentHash(doc.body);
    const slug = storySlug(story.file);
    const depSlugs = Array.isArray(doc.data.dependsOn) ? doc.data.dependsOn : [];
    const depRefs = depSlugs.map(s => refByStorySlug.get(s)).filter((r): r is PublishedRef => r !== undefined).map(r => `#${r.ref}`);
    const input = { title: String(doc.data.title ?? story.file), description: renderStoryBody(doc.body, depRefs) + marker(session.slug, slug) };
    let ref = readPublished(doc.data);
    let storyCreated = false;
    if (ref) {
      if (!publication(doc.data) && ref.contentHash === bodyHash) {
        doc.data.publication = { state: "pending", ...(typeof doc.data.brief === "string" ? { briefUrl: doc.data.brief } : {}) };
        save(story.file, doc);
      }
      if (ref.contentHash !== bodyHash) {
        if (publication(doc.data)?.state === "pending") throw new Error(`${story.file} changed during incomplete publication; restore the accepted draft before resuming`);
        warnings.push(`${story.file} changed since publish — skipping`);
      }
      skipped++;
    } else {
      const recovered = await tracker.findByMarker(markerText(session.slug, slug));
      if (recovered) { ref = reference(recovered, bodyHash); skipped++; }
      else {
        try { ref = reference(await tracker.createStory(input, epicRef.ref), bodyHash); }
        catch (error) {
          if (error instanceof PartialTrackerWriteError) remember(story.file, doc, reference(error.ref, bodyHash));
          throw error;
        }
        storyCreated = true;
        created++;
      }
      remember(story.file, doc, ref);
    }
    const progress = publication(doc.data);
    if (persist && progress?.state === "pending") {
      let stage = "story metadata";
      try {
        if (progress.metadata !== "complete") {
          const labels = ["story", `size:${String(doc.data.sizing ?? "M")}`];
          if (storyCreated) await tracker.setLabels(ref.ref, labels);
          else await completeMetadata(ref, input, labels, epicRef.ref);
          progress.metadata = "complete";
          save(story.file, doc);
        }
        const brief = readBrief(dir, story.file);
        if (brief) {
          stage = "brief attachment";
          if (!progress.briefUrl) {
            const attached = await tracker.attachBrief(ref.ref, brief);
            progress.briefUrl = assertTrackerRef({ id: ref.ref, url: attached.url }).url;
            doc.data.brief = attached.url;
            save(story.file, doc);
          }
          stage = "brief link";
          await tracker.updateStory(ref.ref, { appendBody: `📄 Implementation brief: ${progress.briefUrl}` });
        }
        progress.state = "complete";
        save(story.file, doc);
      } catch (error) { throw new PartialTrackerWriteError({ id: ref.ref, url: ref.url }, stage, error); }
    }
    refByStorySlug.set(slug, ref);
    storyRefs.push({ file: story.file, ref });
  }
  const summary = buildSummary(dir, session, epicRef, storyRefs, warnings);
  if (persist) writeFile(dir, "summary.md", summary);
  return { epicRef, storyRefs, created, skipped, summary };
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
