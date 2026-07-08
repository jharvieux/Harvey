// Comment protocol + diff rendering (design §4.3, §4.4). Reviewers comment by inserting
// `> [!comment]` alert blocks directly in a draft; the AI must address every block and delete it
// (or replace it with `> [!note] AI:` when it disagrees), so a surviving `> [!comment]` after a
// revision is a contract violation the caller must surface. AI revisions are always shown as a
// diff and confirmed before they touch the file — renderDiff produces that view.

const COMMENT_MARKER = "> [!comment]";

// Extract the text of each `> [!comment]` block: the blockquote lines following the marker, with
// the leading "> " stripped, so it can be handed to the model as the instruction context.
export function extractComments(body: string): string[] {
  const lines = body.split("\n");
  const comments: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]?.trim() !== COMMENT_MARKER) continue;
    const collected: string[] = [];
    let j = i + 1;
    while (j < lines.length && lines[j]?.startsWith(">")) {
      collected.push(lines[j]!.replace(/^>\s?/, ""));
      j++;
    }
    comments.push(collected.join("\n").trim());
    i = j - 1;
  }
  return comments;
}

export function hasUnresolvedComments(body: string): boolean {
  return body.split("\n").some((line) => line.trim() === COMMENT_MARKER);
}

// Minimal LCS-based unified diff for the confirm view. Not byte-perfect git output — just an honest,
// readable "what will change" so a reviewer can approve or reject a machine-authored revision.
export function renderDiff(oldText: string, newText: string): string {
  const a = oldText.split("\n");
  const b = newText.split("\n");
  const lcs = lcsMatrix(a, b);
  const out: string[] = [];

  let i = a.length;
  let j = b.length;
  const rev: string[] = [];
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      rev.push(`  ${a[i - 1]}`);
      i--;
      j--;
    } else if ((lcs[i - 1]?.[j] ?? 0) >= (lcs[i]?.[j - 1] ?? 0)) {
      rev.push(`- ${a[i - 1]}`);
      i--;
    } else {
      rev.push(`+ ${b[j - 1]}`);
      j--;
    }
  }
  while (i > 0) rev.push(`- ${a[--i]}`);
  while (j > 0) rev.push(`+ ${b[--j]}`);
  out.push(...rev.reverse());
  return out.join("\n");
}

function lcsMatrix(a: string[], b: string[]): number[][] {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i]![j] = a[i - 1] === b[j - 1] ? dp[i - 1]![j - 1]! + 1 : Math.max(dp[i - 1]![j]!, dp[i]![j - 1]!);
    }
  }
  return dp;
}
