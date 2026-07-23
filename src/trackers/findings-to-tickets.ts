// Findings -> tickets orchestration (#736, remainder of #733). Turns a Harvey audit's `Finding[]`
// (src/findings.ts, the shape run-audit --findings-out emits) into tracker items through the
// tracker-agnostic `Tracker` interface (src/trackers/types.ts). The adapters are dumb transport;
// this module owns the mapping, grouping, and idempotency — one place, so every tracker files the
// same content.
//
// Three bounded pieces (the split-off tail — rate-limiting, scoped-token auth intake, a full CLI —
// is tracked separately; see the PR):
//   1. Mapping (findingToTicket): Finding -> title/body/labels. Single source of truth. The body
//      leads with the report's severity/confidence framing — the coverage-honesty brand guardrail:
//      a "Review"-confidence finding must never read as a confirmed one.
//   2. Grouping (planTickets): "flat" = one issue per finding; "grouped" = one epic per finding
//      CATEGORY with each finding a story under it (findings carry no M1–M10 module tag, so
//      `category` is the grouping field that actually exists on a Finding).
//   3. Dedup (fileFindings): every created item is stamped with a STABLE marker derived from the
//      #457 finding-identity model (src/audit-diff.ts), so a re-audit's findByMarker lookup finds
//      the prior ticket and SKIPS it instead of filing a duplicate.
//
// Dry-run is structural, not a flag: planTickets is a PURE function that takes no Tracker, so a
// preview provably cannot touch the network. fileFindings is the only path that writes.

import { createHash } from "node:crypto";
import type { Finding } from "../findings.js";
import { findingIdentity } from "../audit-diff.js";
import type { CreatedRef, ItemInput, Tracker } from "./types.js";

export type Grouping = "flat" | "grouped";

export interface FileOptions {
  grouping?: Grouping; // default "grouped"
  // Disambiguates markers across engagements sharing one tracker (e.g. two clients' audits filed to
  // the same Jira project). Folded into every marker's hash. Default "harvey".
  engagement?: string;
}

// A single finding mapped to what a tracker item should contain. `marker` is also embedded at the
// end of `body`; it is surfaced separately so the orchestrator can look it up without re-parsing.
export interface PlannedTicket {
  finding: Finding;
  title: string;
  body: string; // markdown, marker appended
  labels: string[];
  marker: string;
  group: string; // the finding's category; "" in flat mode
}

// A category epic to create in grouped mode (its own dedup marker so a re-audit reuses it).
export interface PlannedEpic {
  category: string;
  title: string;
  body: string;
  marker: string;
}

export interface TicketPlan {
  grouping: Grouping;
  epics: PlannedEpic[]; // [] in flat mode
  tickets: PlannedTicket[];
}

export interface FileResult {
  created: { marker: string; ref: CreatedRef }[];
  skipped: { marker: string; ref: CreatedRef }[]; // already filed by a prior run
  epicsCreated: number;
  epicsReused: number;
}

// A compact, searchable dedup token. The #457 identity string carries spaces and "::"/"/"
// separators that make a phrase search fragile across GitHub in:body, Jira `text ~`, and Azure
// WIQL CONTAINS; a short hex hash of it is stable across runs (identity is) and clean to search.
function markerFor(prefix: string, key: string): string {
  const hash = createHash("sha1").update(key).digest("hex").slice(0, 12);
  return `<!-- harvey-${prefix}:${hash} -->`;
}

export function findingMarker(f: Finding, engagement = "harvey"): string {
  return markerFor("finding", `${engagement}::${findingIdentity(f)}`);
}

function epicMarker(category: string, engagement: string): string {
  return markerFor("epic", `${engagement}::${category}`);
}

// Severity/confidence labels are lowercased and namespaced so a client can filter/triage by them
// and tell Harvey-filed tickets from their own. `needs-triage` on anything not Confirmed keeps the
// confidence framing visible in the label set too, not just the body.
export function ticketLabels(f: Finding): string[] {
  const labels = ["harvey", `harvey:severity:${f.severity.toLowerCase()}`, `harvey:confidence:${f.confidence.toLowerCase()}`];
  if (f.confidence !== "Confirmed") labels.push("harvey:needs-triage");
  return labels;
}

function ticketBody(f: Finding, marker: string): string {
  const lines: string[] = [`**Severity:** ${f.severity} · **Confidence:** ${f.confidence}`, ""];
  if (f.impact) lines.push(`**Impact:** ${f.impact}`, "");
  lines.push(`**Location:** \`${f.location}\``, "");
  if (f.evidence) lines.push("**Evidence:**", "", f.evidence, "");
  if (f.fix) lines.push("**Fix:** " + f.fix, "");
  const meta: string[] = [];
  if (f.taxonomy) meta.push(`taxonomy: ${f.taxonomy}`);
  if (f.category) meta.push(`category: ${f.category}`);
  if (f.cwe?.length) meta.push(`CWE: ${f.cwe.join(", ")}`);
  if (f.owasp?.length) meta.push(`OWASP: ${f.owasp.join(", ")}`);
  if (meta.length) lines.push("---", meta.join(" · "), "");
  lines.push(marker);
  return lines.join("\n");
}

// Finding -> tracker item. The single source of truth for what a filed ticket says.
export function findingToTicket(f: Finding, opts: FileOptions = {}): PlannedTicket {
  const engagement = opts.engagement ?? "harvey";
  const marker = findingMarker(f, engagement);
  return {
    finding: f,
    title: `[${f.severity}] ${f.title}`,
    body: ticketBody(f, marker),
    labels: ticketLabels(f),
    marker,
    group: opts.grouping === "flat" ? "" : f.category,
  };
}

// Pure preview: the whole plan, computed without a Tracker — a dry-run cannot make an API call
// because there is nothing here to call it with.
export function planTickets(findings: Finding[], opts: FileOptions = {}): TicketPlan {
  const grouping: Grouping = opts.grouping ?? "grouped";
  const engagement = opts.engagement ?? "harvey";
  const tickets = findings.map((f) => findingToTicket(f, { ...opts, grouping }));

  if (grouping === "flat") return { grouping, epics: [], tickets };

  const epics: PlannedEpic[] = [];
  const seen = new Set<string>();
  for (const t of tickets) {
    const category = t.group || "Uncategorized";
    if (seen.has(category)) continue;
    seen.add(category);
    const marker = epicMarker(category, engagement);
    epics.push({
      category,
      title: `Harvey findings: ${category}`,
      body: `Audit findings in category **${category}**, filed by Harvey.\n\n${marker}`,
      marker,
    });
  }
  return { grouping, epics, tickets };
}

// File the plan through a tracker, skipping anything a prior run already filed (dedup via the
// stable marker). This is the ONLY path that writes — callers gate it behind explicit
// authorization. Grouped mode creates/reuses a category epic before filing its stories under it.
export async function fileFindings(tracker: Tracker, findings: Finding[], opts: FileOptions = {}): Promise<FileResult> {
  const plan = planTickets(findings, opts);
  const result: FileResult = { created: [], skipped: [], epicsCreated: 0, epicsReused: 0 };

  const epicIdByCategory = new Map<string, string>();
  for (const epic of plan.epics) {
    const existing = await tracker.findByMarker(epic.marker);
    if (existing) {
      epicIdByCategory.set(epic.category, existing.id);
      result.epicsReused++;
      continue;
    }
    const ref = await tracker.createEpic({ title: epic.title, description: epic.body });
    epicIdByCategory.set(epic.category, ref.id);
    result.epicsCreated++;
  }

  for (const t of plan.tickets) {
    const existing = await tracker.findByMarker(t.marker);
    if (existing) {
      result.skipped.push({ marker: t.marker, ref: existing });
      continue;
    }
    const input: ItemInput = { title: t.title, description: t.body };
    const epicId = plan.grouping === "grouped" ? epicIdByCategory.get(t.group || "Uncategorized") : undefined;
    const ref = epicId ? await tracker.createStory(input, epicId) : await tracker.createEpic(input);
    await tracker.setLabels(ref.id, t.labels);
    result.created.push({ marker: t.marker, ref });
  }

  return result;
}
