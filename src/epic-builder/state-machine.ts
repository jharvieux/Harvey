// Pure state-machine transitions (design §3.1). Kept free of I/O so the whole workflow graph is
// unit-testable and every transition is a deterministic function of (state, event). The session
// controller (session.ts) is the only thing that persists the result.

import type { SessionState } from "./types.js";

export type WorkflowEvent =
  | "clarify-start" // intake captured -> begin clarifying questions
  | "clarify-done" // clarify rounds finished -> draft the epic
  | "epic-drafted" // an epic draft (or redraft) is on disk, ready for review
  | "epic-revise" // reviewer asked for an AI revision of the epic
  | "epic-accept" // reviewer accepted the epic
  | "stories-drafted" // fan-out + consistency pass complete
  | "story-redraft" // a story needs a full redraft -> re-enter fan-out
  | "stories-accept" // every story accepted -> publish
  | "publish-ok" // publish (or dry-run) succeeded
  | "publish-partial" // some creates failed -> stay in publish for idempotent re-run
  | "summary-shown"; // results rendered -> terminal

const TRANSITIONS: Record<SessionState, Partial<Record<WorkflowEvent, SessionState>>> = {
  intake: { "clarify-start": "clarify" },
  clarify: { "clarify-done": "epic-draft" },
  "epic-draft": { "epic-drafted": "epic-review" },
  "epic-review": { "epic-revise": "epic-draft", "epic-accept": "stories-fan-out" },
  "stories-fan-out": { "stories-drafted": "stories-review" },
  "stories-review": { "story-redraft": "stories-fan-out", "stories-accept": "publish" },
  publish: { "publish-ok": "summary", "publish-partial": "publish" },
  summary: { "summary-shown": "done" },
  done: {},
};

export function canTransition(state: SessionState, event: WorkflowEvent): boolean {
  return TRANSITIONS[state][event] !== undefined;
}

export function transition(state: SessionState, event: WorkflowEvent): SessionState {
  if (!canTransition(state, event)) {
    throw new Error(`invalid transition: ${event} is not allowed from state "${state}"`);
  }
  return TRANSITIONS[state][event]!;
}
