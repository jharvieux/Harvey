// Pipeline decision core: intake (screen the client-approved subset) and
// batching (group non-conflicting fixes for parallel worktrees). These stages
// are side-effect-free — they decide *what* the implementer and verifier will
// do, so they can run in --dry-run with zero worktrees and zero pushes.
// See docs/design/fix-implementation.md §1.1, §1.3.

import type { Finding, FindingsDocument } from "../findings.js";
import { screenFinding, type FixPlan, type Screen } from "./plan.js";
import { checkBlastRadius, type DiffCap, type RailCheck } from "./rails.js";

export interface EngagementManifest {
  client: string;
  baselineCommit: string; // must match findings meta.commit or operator re-baselines
  approvedFindingIds: string[]; // client sign-off — no approval, no fix
  enabledCategories: string[];
  allowlist: string[]; // path allowlist agreed with the client
  sensitivePaths?: string[];
  diffCap?: DiffCap;
  operator: string;
}

export interface ScreenedFinding {
  finding: Finding;
  screen: Screen;
}

interface IntakeResult {
  baselineMatches: boolean; // meta.commit === manifest.baselineCommit
  auto: ScreenedFinding[];
  manual: ScreenedFinding[];
  recommendOnly: ScreenedFinding[];
  notApproved: string[]; // finding ids present in the doc but not client-approved
  unknownApprovedIds: string[]; // approved ids that aren't in the findings doc
}

export function intake(doc: FindingsDocument, manifest: EngagementManifest): IntakeResult {
  const approved = new Set(manifest.approvedFindingIds);
  const seen = new Set<string>();
  const result: IntakeResult = {
    baselineMatches: doc.meta.commit === manifest.baselineCommit,
    auto: [],
    manual: [],
    recommendOnly: [],
    notApproved: [],
    unknownApprovedIds: [],
  };

  const opts = { enabledCategories: manifest.enabledCategories, sensitivePaths: manifest.sensitivePaths };
  for (const finding of doc.findings) {
    seen.add(finding.id);
    if (!approved.has(finding.id)) {
      result.notApproved.push(finding.id);
      continue;
    }
    const screen = screenFinding(finding, opts);
    const entry = { finding, screen };
    if (screen.mode === "auto") result.auto.push(entry);
    else if (screen.mode === "manual") result.manual.push(entry);
    else result.recommendOnly.push(entry);
  }

  result.unknownApprovedIds = manifest.approvedFindingIds.filter((id) => !seen.has(id));
  return result;
}

// Conflict graph over eligible plans: an edge means overlapping files. Connected
// components serialize internally; independent components run in parallel (§1.3).
// File-level overlap only — directory overlap is not an edge.
export function batch(plans: Pick<FixPlan, "findingId" | "blastRadius">[]): string[][] {
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let root = x;
    while (parent.get(root) !== root) root = parent.get(root) as string;
    parent.set(x, root);
    return root;
  };
  const union = (a: string, b: string) => parent.set(find(a), find(b));

  for (const p of plans) parent.set(p.findingId, p.findingId);

  const owners = new Map<string, string>(); // file -> first finding that touched it
  for (const p of plans) {
    for (const file of [...p.blastRadius.files, ...p.blastRadius.createdFiles]) {
      const prior = owners.get(file);
      if (prior !== undefined) union(p.findingId, prior);
      else owners.set(file, p.findingId);
    }
  }

  const components = new Map<string, string[]>();
  for (const p of plans) {
    const root = find(p.findingId);
    const group = components.get(root) ?? [];
    group.push(p.findingId);
    components.set(root, group);
  }
  return [...components.values()];
}

// Rail pre-check at plan time: a plan whose blast radius exceeds the rails is
// downgraded cheaply, before a worktree ever spins up (§1.2, §3.1).
export function checkPlanRails(plan: FixPlan, manifest: EngagementManifest): RailCheck {
  return checkBlastRadius(plan.blastRadius, manifest.allowlist, manifest.diffCap);
}
