import { SEMANTIC_CORPUS, type SemanticTarget } from "./scan/semantic-corpus.js";

export interface SemanticTriageIdentity {
  measurement: string;
  slug: string;
  repo: string;
  commit: string;
  scope?: string;
}

export const SEMANTIC_TARGET_COMMITS: Readonly<Record<string, string>> = {
  "nocode-rescue": "81350ee96e1aa223f0ce55e5ea91b6b1ffde1595",
  superredhat: "104b81dfd54b86b441124c7e12fdf0a9e96bd55c",
  supatest: "38da50608433ec114cf555f5692a478952aae8b1",
  cipherx: "b6f0d9d7fa1e956ef91903f11d7dddcc628ba869",
};

type PinnedSemanticTarget = SemanticTarget & { commit: string };

function normalizedRepo(value: string): string {
  return value
    .trim()
    .replace(/^git@github\.com:/i, "")
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/^ssh:\/\/git@github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/^\/+|\/+$/g, "")
    .toLowerCase();
}

/**
 * Fail-closed identity check for the one context allowed to relax the generic "intended design"
 * exclusion. A branch name is insufficient: every accepted target is bound to the immutable commit
 * that the checked-in answer key describes.
 */
export function requireSemanticTriageTarget(
  identity: SemanticTriageIdentity,
  corpus: readonly SemanticTarget[] = SEMANTIC_CORPUS,
): PinnedSemanticTarget {
  if (identity.measurement !== "semantic-recall") {
    throw new Error(`intentional-vulnerability exception requires measurement=semantic-recall, got ${identity.measurement || "<empty>"}`);
  }
  const target = corpus.find((candidate) => candidate.slug === identity.slug);
  if (!target) throw new Error(`unknown semantic corpus target: ${identity.slug}`);
  const commit = SEMANTIC_TARGET_COMMITS[target.slug];
  if (!commit) throw new Error(`semantic corpus target has no immutable commit pin: ${identity.slug}`);
  if (normalizedRepo(identity.repo) !== normalizedRepo(target.repo)) {
    throw new Error(`semantic corpus repository mismatch for ${identity.slug}: expected ${target.repo}, got ${identity.repo}`);
  }
  if (identity.commit.toLowerCase() !== commit.toLowerCase()) {
    throw new Error(`semantic corpus commit mismatch for ${identity.slug}: expected ${commit}, got ${identity.commit}`);
  }
  if ((identity.scope ?? "") !== (target.scope ?? "")) {
    throw new Error(`semantic corpus scope mismatch for ${identity.slug}: expected ${target.scope ?? "<repo-root>"}, got ${identity.scope ?? "<repo-root>"}`);
  }
  return { ...target, commit };
}

/** Build the effective triage rules for one exact, pinned semantic-recall measurement. */
export function semanticCorpusTriageRules(
  baseRules: string,
  identity: SemanticTriageIdentity,
  corpus: readonly SemanticTarget[] = SEMANTIC_CORPUS,
): string {
  const target = requireSemanticTriageTarget(identity, corpus);
  return `${baseRules.trimEnd()}

## Semantic-recall planted-vulnerability exception (#1947)

ACTIVE ONLY FOR THIS MEASUREMENT: semantic-recall of ${target.repo}@${target.commit}${target.scope ? `/${target.scope}` : ""} (corpus slug ${target.slug}). The generating command verified the repository remote, exact HEAD, scope, and measurement name before writing this file. Do not reuse it for an ordinary audit, another target, another commit, or another measurement.

- A target comment or README label such as \`intentionally vulnerable\`, \`training\`, \`demo\`, or \`challenge\` is NOT, by itself, an accepted-risk justification in this measurement. Do not apply generic exclusion rule 3 or the organization "intentional, documented exception" rule solely because the target deliberately planted the behavior being measured.
- The exception changes no technical burden of proof. Read the implementation, establish reachability and impact, preserve independent votes, and reject candidates that are not real vulnerabilities. All other generic and organization rules remain active.
- Precision controls remain active in particular: mock dependency data is not a real vulnerable dependency, and a Supabase anon/publishable key is not a secret. The exception must not turn either recorded corpus negative into a finding.
`;
}
