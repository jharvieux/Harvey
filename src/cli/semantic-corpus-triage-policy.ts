// Produce the one-off effective fp-rules file for a pinned semantic-recall corpus measurement.
// Ordinary audits keep using briefs/fp-rules.txt; this CLI refuses every other measurement, repo,
// commit and scope before appending the narrow planted-vulnerability exception.
import "./sync-stdio.js";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readGitCheckoutIdentity } from "../git-checkout-identity.js";
import { semanticCorpusTriageRules } from "../semantic-triage.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};

const measurement = flag("--measurement");
const slug = flag("--slug");
const repoDir = flag("--repo");
const scope = flag("--scope");
const out = flag("--out");
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const baseRulesPath = join(repoRoot, "briefs", "fp-rules.txt");

if (!measurement || !slug || !repoDir || !out) {
  console.error("usage: pnpm exec tsx src/cli/semantic-corpus-triage-policy.ts --measurement semantic-recall --slug <corpus-slug> --repo <clone-root> [--scope <subdir>] --out <rules.txt>");
  process.exit(2);
}

try {
  const root = resolve(repoDir);
  const { repo, commit } = readGitCheckoutIdentity(root);
  const rules = semanticCorpusTriageRules(readFileSync(baseRulesPath, "utf8"), {
    measurement,
    slug,
    repo,
    commit,
    scope,
  });
  const path = resolve(out);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, rules);
  console.error(`Recorded exact semantic-recall triage policy for ${repo}@${commit}${scope ? `/${scope}` : ""} → ${path}`);
} catch (error) {
  console.error(`semantic-corpus-triage-policy: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
