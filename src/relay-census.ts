import { checkAcceptance, type IssueLookup, type IssueRecord } from "./acceptance-conservation.js";

export interface RelayCensusNode {
  number: number;
  state: "OPEN" | "CLOSED";
  url: string;
  body: string;
  comments: { totalCount: number; nodes: { url: string; body: string }[] };
  closedByPullRequestsReferences: { totalCount: number; nodes: { number: number; body: string }[] };
  /** A test-only representation of the tempting superset. The gate and census deliberately ignore it. */
  unlinkedPullRequests?: { number: number; body: string }[];
}

interface RelayCensusRow {
  issue: number;
  index: number;
  text: string;
  status: "live" | "superseded";
  detail?: string;
  retired?: { venue: string; line: number; detail: string };
  retiredBy?: { venue: string; line: number; disposition: string; detail: string };
}

interface DuplicateDispositionRow {
  issue: number;
  index: number;
  text: string;
  problem: string;
}

/**
 * Build the census through `checkAcceptance`, so its venue surface is the gate's surface by
 * construction: issue comments plus linked closing PR bodies, never every PR that mentions #N.
 */
export function collectRelayCensus(nodes: readonly RelayCensusNode[]): {
  rows: RelayCensusRow[];
  duplicates: DuplicateDispositionRow[];
} {
  const lookup: IssueLookup = (issue, repo) => {
    if (repo) return undefined;
    const n = nodes.find((candidate) => candidate.number === issue);
    if (!n) return undefined;
    const record: IssueRecord = {
      number: n.number,
      state: n.state,
      body: n.body ?? "",
      comments: n.comments.nodes.map((comment) => ({ body: comment.body ?? "", url: comment.url })),
      linkedPrs: n.closedByPullRequestsReferences.nodes.map((pr) => ({ ref: `#${pr.number}`, body: pr.body ?? "" })),
    };
    return record;
  };

  const rows: RelayCensusRow[] = [];
  const duplicates: DuplicateDispositionRow[] = [];
  for (const n of nodes) {
    const report = checkAcceptance(`Closes #${n.number}`, lookup);
    for (const issue of report.issues) {
      if (issue.issue !== n.number) continue;
      for (const criterion of issue.criteria) {
        const duplicate = criterion.problems.find((problem) => /\bis mapped \d+ times\b/.test(problem));
        if (duplicate) {
          duplicates.push({ issue: n.number, index: criterion.index, text: criterion.text, problem: duplicate });
        }
        if (criterion.superseded) {
          rows.push({
            issue: n.number,
            index: criterion.index,
            text: criterion.text,
            status: "superseded",
            detail: criterion.detail,
            retired: {
              venue: criterion.superseded.venue,
              line: criterion.superseded.line,
              detail: criterion.superseded.detail,
            },
            retiredBy: criterion.superseded.by,
          });
        } else if (criterion.disposition === "relayed") {
          rows.push({ issue: n.number, index: criterion.index, text: criterion.text, status: "live", detail: criterion.detail });
        }
      }
    }
  }
  return { rows, duplicates };
}
