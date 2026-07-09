// Tracker publishing layer (issue #22): one interface, three adapters (GitHub, Jira Cloud,
// Azure DevOps) that the epic/story builder (#21) and the fix-implementation system (#23)
// publish through. The interface is deliberately tracker-agnostic — no GitHub-only assumptions
// leak into its shape — so a caller can swap adapters without changing call sites.
//
// Credential contract (the security-relevant core — see each adapter and credentials.test.ts):
//   - Adapters receive a PAT/OAuth token as an injected config field at construction time,
//     sourced from the CALLER's own per-engagement secret store (.env/vault/keychain). This
//     module does NOT implement persistence or a secret store of its own.
//   - The raw token is never persisted, logged, serialized, or put into an error message.
//     Secrets are held in private class fields (#token) so they never appear in JSON.stringify
//     output, and the shared request helper's errors carry only method/url/status/response-body.

export interface CreatedRef {
  id: string; // the tracker-native id the other methods accept: issue number, issue key, work-item id
  url: string; // canonical web URL of the created item
}

export interface AttachedRef {
  url: string; // canonical URL of the attached/committed brief
}

// Epics and stories take the same creation payload; createStory additionally links to an epic.
export interface ItemInput {
  title: string;
  description: string; // markdown
}

// Minimal patch payload for updateStory: only the fields the epic-builder's publish orchestrator
// needs to touch after creation. Omitted fields are left untouched by the adapter.
export interface UpdateStoryPatch {
  body?: string;
  labels?: string[];
}

export interface Tracker {
  createEpic(input: ItemInput): Promise<CreatedRef>;
  createStory(input: ItemInput, epicId: string): Promise<CreatedRef>;
  setLabels(id: string, labels: string[]): Promise<void>;
  setEstimate(id: string, estimate: number): Promise<void>;
  attachBrief(id: string, briefMarkdown: string): Promise<AttachedRef>;
  // Idempotency recovery (#50, design §8.2 mechanism 2): look up an item already created by a
  // prior run via the hidden marker the epic-builder stamps into every created body (see
  // publish.ts `marker()`). Returns null on no match — never throws for "not found".
  findByMarker(marker: string): Promise<CreatedRef | null>;
  // Update an existing story's body and/or labels (#50). Needed because the implementation
  // brief's URL is only known after createStory returns, so the brief link is pushed into the
  // body with a follow-up updateStory call rather than being included at creation time.
  updateStory(id: string, patch: UpdateStoryPatch): Promise<void>;
}
