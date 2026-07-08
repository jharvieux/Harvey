// Epic builder core types (issue #21). The design of record is docs/design/epic-builder.md;
// these types mirror §5 of that doc. The one deliberate divergence from the doc: publishing goes
// through the delivered Tracker interface (src/trackers/types.ts, #22) — createEpic / createStory /
// setLabels / setEstimate / attachBrief — not the aspirational TrackerAdapter sketched in §8.1
// (which had init/findByMarker/marker args that the shipped adapters never grew). See publish.ts.

export type SessionState =
  | "intake"
  | "clarify"
  | "epic-draft"
  | "epic-review"
  | "stories-fan-out"
  | "stories-review"
  | "publish"
  | "summary"
  | "done";

type ArtifactStatus = "draft" | "in-review" | "accepted" | "skipped";

export type Sizing = "S" | "M" | "L";

export interface ArtifactState {
  status: ArtifactStatus;
  revisions: number;
}

export interface StoryState extends ArtifactState {
  file: string; // workspace-relative, e.g. "stories/02-permission-filter.md"
}

export interface PublishedRef {
  adapter: string;
  ref: string; // adapter-native id, e.g. "jharvieux/Harvey#42"
  url: string;
  contentHash: string; // sha256 of body at publish time
}

export interface DraftSession {
  version: 1;
  slug: string;
  state: SessionState;
  prompt: string;
  createdAt: string; // ISO 8601
  clarifyRounds: number; // 0..2
  epic: ArtifactState;
  stories: StoryState[];
  publish: { adapter: string; attempts: number };
}

// A single user decision in a review loop (design §5). Appended to the workspace action log so a
// resumed session can reconstruct revision counts and workflow position.
export type ReviewAction =
  | { kind: "accept"; target: string }
  | { kind: "direct-edit"; target: string }
  | { kind: "comment"; target: string }
  | { kind: "revise"; target: string; instruction: string }
  | { kind: "apply-revision"; target: string; accepted: boolean }
  | { kind: "skip"; target: string }
  | { kind: "quit" };

// --- Model tiering (design §7) ---

export type Tier = "bulk" | "standard" | "flagship";

export type ModelTask = "clarify" | "epic-draft" | "story-draft" | "revise" | "consistency" | "qa";

export type EscalationFlag =
  | "revision-loop" // revisions >= 3 on one artifact -> escalate its next revision
  | "contradiction" // consistency pass found epic/story conflict -> escalate redraft
  | "sizing-anomaly" // story flagged >L twice -> escalate the split proposal
  | "user-requested"; // `r!` in the review menu forces flagship

export interface TierContext {
  task: ModelTask;
  revisionCount: number;
  flags: EscalationFlag[];
}

// --- Model-call boundary (design §7) ---
// The "AI" steps are behind this injectable seam. Tests drive it with a deterministic fake; the
// shipped CLI default is the offline ScaffoldModelClient (model-scaffold.ts). Wiring a live model
// (the #19 router) is a matter of supplying another implementation — no other code changes.

export interface ClarifyQuestion {
  question: string;
  assumption: string; // the AI's default, rendered in [assume: ...]
}

export interface StoryManifestEntry {
  title: string;
  scope: string; // one-line scope
  sizing: Sizing;
}

export interface DraftStoryInput {
  epicBody: string;
  intake: string;
  entry: StoryManifestEntry;
  siblingTitles: string[];
  storyTemplate: string;
  briefTemplate: string;
}

export interface DraftStoryResult {
  body: string;
  brief: string;
}

export interface ReviseInput {
  current: string; // full current draft body
  instruction?: string; // one-line instruction from the review menu (`r`)
  comments: string[]; // extracted `> [!comment]` block texts (`c`)
}

export interface ModelClient {
  clarify(input: { prompt: string; round: number; priorQA: string }, tier: Tier): Promise<ClarifyQuestion[]>;
  draftEpic(input: { prompt: string; intake: string; template: string }, tier: Tier): Promise<string>;
  storyManifest(input: { epicBody: string; intake: string }, tier: Tier): Promise<StoryManifestEntry[]>;
  draftStory(input: DraftStoryInput, tier: Tier): Promise<DraftStoryResult>;
  revise(input: ReviseInput, tier: Tier): Promise<string>;
}
