// Measures the POPULATION available to a commit-level self-admitted-GenAI density comparison
// across the pinned corpus (#1600 step 2).
//
//   pnpm genai-admission-census
//
// WHY THIS EXISTS. docs/design/m6-corpus-frequency.md used to publish an "AI code carries the
// hand-rolled catalogue at ~Nx professional density" ratio computed across per-repo `provenance`
// tiers that WE assigned by inspection. Nothing verified those labels, so the ratio inherited their
// uncertainty completely — and the ratio was the whole claim. #1600's operator ruling retired the
// number and asked for a re-founding on ground truth that does not come from us guessing.
//
// The lead was commit-level SELF-ADMISSION: a commit whose own author declares GenAI involvement.
// Its appeal is that the label is DECLARED rather than inferred, and that commit granularity holds
// repo, language, era and team constant — killing the confound that sinks a per-repo tier
// comparison. Concept and signal split: Xiao et al., arXiv:2507.10422 (read in full 2026-07-30).
//
// This tool does NOT compute a density ratio. It answers the question that must be settled first,
// and that a density ratio leaves unanswered for itself: IS THERE A POPULATION TO MEASURE? A within-repo
// commit-level comparison needs BOTH ARMS inside the SAME repo — admitted and unadmitted commits,
// both touching product source. A repo that is 0% or ~100% admitted contributes no contrast, and
// pooling such repos across the corpus reconstructs the per-repo confound the design exists to
// remove, wearing a commit-shaped coat.
//
// "A limit with a population of zero is a guess" (CLAUDE.md). So this measures the population
// rather than asserting one.
//
// History is read at the PINNED commit, not at the default branch head, so a re-run reproduces.
// Blobless clone (--filter=blob:none): trees are present so --name-only resolves offline, blobs are
// never fetched, so cost does not scale with tree size.
//
// NOT part of `pnpm verify` (network: clones the corpus), same stance as corpus-drift.ts and
// handrolled-frequency.ts. The classification it depends on IS covered by verify, via
// src/scan/genai-admission.test.ts.
//
// CADENCE. This tool now has one: .github/workflows/genai-census.yml, monthly on the 3rd, plus a PR
// trigger on the corpus and the classifier. That closes the specific failure mode #1600 was opened
// about — the withdrawn ~3.4x ratio survived a 3x growth of the corpus precisely because
// src/cli/handrolled-frequency.ts is invoked by no test and no workflow, so nothing re-measured it.
//
// The block below used to record NO CADENCE as decisional, blocked on `.github/workflows/` being a
// supervised path. #1691 called that a false decline and it was: supervision stops the EDIT, never
// the CRITERION, and workflow edits are granted routinely. What remains empirical is the SCOPE of
// the cadence, and that is what the reason records now.
//
// REASON: the monthly re-measure covers the CENSUS only — `--density`, the arm-vs-arm ratio, is not on any cadence, because it needs a FULL-history clone plus a per-file `git blame` of every product source in each two-armed repo rather than the blobless fetch the census uses
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-31 — the workflow runs `pnpm genai-admission-census` without `--density`; the density half re-clones each usable repo at full depth (`git fetch` with no `--filter`) and blames every product file, which is why it is opt-in in the tool and off the schedule. Any ratio quoted from it is POINT-IN-TIME: quote it with its date and the corpus base commit, never as a standing fact.
// FALSIFIER: test -f .github/workflows/genai-census.yml || exit 127; git grep -qF 'genai-admission-census.ts --density' -- '.github/workflows/genai-census.yml' && exit 0 || exit 1
// TOUCHES: src/cli/genai-admission-census.ts .github/workflows/genai-census.yml

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { recordMeasured } from "../ci-liveness.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import {
  ADMISSION_FORMAT,
  admittedCommits,
  allZeroAdmissionError,
  blameLineShas,
  CENSUS_FORMAT,
  censusOfLog,
  density,
  hasBothArms,
  isProductSource,
  MIN_ARM,
  type ArmTally,
  type CommitCensus,
} from "../scan/genai-admission.js";
import { buildFrequencyTargets } from "../scan/handrolled-frequency.js";

// `--density` adds the second half: for each repo the census finds two-armed, attribute every
// product line and every M6 indicator finding to the commit that last wrote it, and report the
// hand-rolled density of the declared-AI arm against the not-declared arm WITHIN that repo. This is
// the measurement the withdrawn per-tier ratio could not be: same repo, same team, same era, and a
// label the commit's own author wrote. It needs full history (blame), so it is opt-in.
const WITH_DENSITY = process.argv.includes("--density");

interface RepoCensus extends CommitCensus {
  slug: string;
  tier: string;
}

const targets = buildFrequencyTargets();
const rows: RepoCensus[] = [];
for (const t of targets) {
  const dir = mkdtempSync(join(tmpdir(), `harvey-admit-${t.slug}-`));
  console.error(`=== ${t.slug} [${t.tier}] ${t.repo}@${t.commit.slice(0, 8)} ===`);
  try {
    execFileSync("git", ["init", "-q", dir], { stdio: "ignore" });
    execFileSync("git", ["-C", dir, "remote", "add", "origin", `https://github.com/${t.repo}`], { stdio: "ignore" });
    execFileSync("git", ["-C", dir, "fetch", "-q", "--filter=blob:none", "origin", t.commit], { stdio: ["ignore", "ignore", "pipe"] });
    const log = execFileSync("git", ["-C", dir, "log", t.commit, "--no-merges", "--name-only", `--format=${CENSUS_FORMAT}`], { maxBuffer: 512 * 1024 * 1024 }).toString();
    rows.push({ slug: t.slug, tier: t.tier, ...censusOfLog(log) });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Full-history clone of one repo, then blame every product file to split its lines — and the M6
 * indicator findings sitting on them — into the declared-AI arm and the not-declared arm.
 *
 * Blame attributes a line to the commit that LAST wrote it. That is the honest unit here (a line
 * standing at the pin was last authored by that commit) but it is not "who invented this logic": an
 * admitted commit that reformats a file inherits every line it touched. Stated with the results.
 */
function tallyFor(target: { slug: string; repo: string; commit: string }): ArmTally {
  const dir = mkdtempSync(join(tmpdir(), `harvey-blame-${target.slug}-`));
  console.error(`--- blame ${target.slug} ---`);
  try {
    execFileSync("git", ["init", "-q", dir], { stdio: "ignore" });
    execFileSync("git", ["-C", dir, "remote", "add", "origin", `https://github.com/${target.repo}`], { stdio: "ignore" });
    execFileSync("git", ["-C", dir, "fetch", "-q", "origin", target.commit], { stdio: ["ignore", "ignore", "pipe"] });
    execFileSync("git", ["-C", dir, "checkout", "-q", target.commit], { stdio: "ignore" });

    const log = execFileSync("git", ["-C", dir, "log", target.commit, "--no-merges", `--format=${ADMISSION_FORMAT}`], { maxBuffer: 512 * 1024 * 1024 }).toString();
    const admitted = admittedCommits(log);

    // Findings are keyed by the same relative paths loadSources yields, which is what blame is
    // given, so the two stay in step.
    const files = loadSources(dir).filter((f) => !NON_PRODUCT.test(f.path));
    const findingLines = new Map<string, number[]>();
    for (const f of detectHandrolledFindings(files)) {
      const i = f.location.lastIndexOf(":");
      const path = f.location.slice(0, i);
      const line = Number(f.location.slice(i + 1));
      if (!Number.isFinite(line)) continue;
      findingLines.set(path, [...(findingLines.get(path) ?? []), line]);
    }

    const t: ArmTally = { linesAdmitted: 0, linesUnadmitted: 0, findingsAdmitted: 0, findingsUnadmitted: 0 };
    for (const f of files) {
      if (!isProductSource(f.path)) continue;
      let porcelain: string;
      try {
        porcelain = execFileSync("git", ["-C", dir, "blame", "--line-porcelain", "--", f.path], { maxBuffer: 1 << 28, stdio: ["ignore", "pipe", "ignore"] }).toString();
      } catch {
        continue; // untracked in the pinned tree — contributes to neither arm rather than to a guess
      }
      const shas = blameLineShas(porcelain);
      for (const sha of shas) {
        if (admitted.has(sha)) t.linesAdmitted += 1;
        else t.linesUnadmitted += 1;
      }
      for (const line of findingLines.get(f.path) ?? []) {
        const sha = shas[line - 1];
        if (sha === undefined) continue;
        if (admitted.has(sha)) t.findingsAdmitted += 1;
        else t.findingsUnadmitted += 1;
      }
    }
    return t;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const out: string[] = [];
out.push(`Commit-level self-admitted-GenAI census over the pinned corpus (${rows.length} repos).`);
out.push(`Product-source predicate: /\\.(ts|tsx|jsx|mjs)$/ minus NON_PRODUCT — identical to handrolled-frequency.ts.`);
out.push(`Merge commits excluded. History read at each repo's PINNED commit, so this is reproducible.`);
out.push("");
out.push(`| Repo | Tier | Commits | Product-touching | Admitted (trailer) | Admitted (prose only) | Product+admitted | Product+unadmitted | Both arms >= ${MIN_ARM}? |`);
out.push(`|---|---|---:|---:|---:|---:|---:|---:|---|`);
for (const r of rows) {
  out.push(
    `| ${r.slug} | ${r.tier} | ${r.commits} | ${r.productCommits} | ${r.trailerAdmitted} | ${r.proseOnlyAdmitted} | ${r.admittedProduct} | ${r.unadmittedProduct} | ${hasBothArms(r) ? "**YES**" : "no"} |`,
  );
}

const usable = rows.filter(hasBothArms);
const anyAdmission = rows.filter((r) => r.trailerAdmitted + r.proseOnlyAdmitted > 0);
const totals = rows.reduce(
  (a, r) => ({
    commits: a.commits + r.commits,
    product: a.product + r.productCommits,
    trailer: a.trailer + r.trailerAdmitted,
    prose: a.prose + r.proseOnlyAdmitted,
    admitted: a.admitted + r.admittedProduct,
    unadmitted: a.unadmitted + r.unadmittedProduct,
  }),
  { commits: 0, product: 0, trailer: 0, prose: 0, admitted: 0, unadmitted: 0 },
);

out.push("");
out.push("POPULATION");
out.push(`  commits in corpus history (no merges) : ${totals.commits}`);
out.push(`  touching product source              : ${totals.product}`);
out.push(`  ...self-admitted                     : ${totals.admitted}`);
out.push(`  ...not self-admitted                 : ${totals.unadmitted}`);
out.push(`  admissions by TRAILER (high prec.)   : ${totals.trailer}`);
out.push(`  admissions by PROSE only (low prec.) : ${totals.prose}`);
out.push(`  repos with ANY self-admission        : ${anyAdmission.length} of ${rows.length} (${anyAdmission.map((r) => r.slug).join(", ") || "none"})`);
out.push("");
out.push(`WITHIN-REPO TWO-ARM FEASIBILITY (both arms >= ${MIN_ARM} product-touching commits)`);
out.push(`  repos supplying a usable contrast: ${usable.length} of ${rows.length}${usable.length ? ` (${usable.map((r) => r.slug).join(", ")})` : ""}`);
out.push("");
out.push(
  usable.length === 0
    ? "VERDICT — NO within-repo commit-level comparison is available on this corpus. Pooling admitted\n" +
        "commits across repos would reconstruct the per-repo confound the design exists to remove, so\n" +
        "this is a negative result, not a smaller version of the same measurement."
    : `VERDICT — ${usable.length} of ${rows.length} repos supply both arms. A within-repo density comparison is\n` +
        "possible there, and only there; the other repos are single-armed and cannot be pooled in without\n" +
        "reintroducing the per-repo confound. Every limitation below applies to any figure that results.",
);
if (WITH_DENSITY && usable.length > 0) {
  out.push("");
  out.push("WITHIN-REPO DENSITY, declared-AI arm vs not-declared arm");
  out.push("  Every product line is attributed by `git blame` to the commit that LAST wrote it, and");
  out.push("  every M6 indicator finding to the arm of the line it sits on. Denominator is that arm's");
  out.push("  attributed lines, so the two arms are normalised against their own size.");
  out.push("");
  out.push("| Repo | AI-declared lines | findings | /KLOC | Not-declared lines | findings | /KLOC | ratio |");
  out.push("|---|---:|---:|---:|---:|---:|---:|---:|");
  for (const r of usable) {
    const t = tallyFor(targets.find((x) => x.slug === r.slug)!);
    const dA = density(t.findingsAdmitted, t.linesAdmitted);
    const dU = density(t.findingsUnadmitted, t.linesUnadmitted);
    const ratio = dA !== null && dU !== null && dU > 0 ? (dA / dU).toFixed(2) + "x" : "n/a";
    out.push(
      `| ${r.slug} | ${t.linesAdmitted} | ${t.findingsAdmitted} | ${dA?.toFixed(2) ?? "n/a"} | ${t.linesUnadmitted} | ${t.findingsUnadmitted} | ${dU?.toFixed(2) ?? "n/a"} | ${ratio} |`,
    );
  }
  out.push("");
  out.push("  Read each row on its own. These are three repos, not a sample of anything, and a ratio");
  out.push("  below is a statement about that repo's history — not about AI code in general.");
}

out.push("");
out.push("LIMITATIONS, stated so a number here is not read as more than it is:");
out.push("  • Self-admission is a BIASED sample. Xiao et al. (arXiv:2507.10422) Table 7 catalogues");
out.push("    projects whose policies PROHIBIT GenAI contributions outright; those repos cannot");
out.push("    produce an admission whatever their code contains. Absence of admission is not");
out.push("    absence of GenAI, and the unadmitted arm is therefore NOT a clean human control.");
out.push("  • Trailer practice is tool-driven, not developer-driven — an assistant that writes the");
out.push("    trailer by default produces admissions, one that does not produces none, independent");
out.push("    of how much code it wrote.");
out.push("  • Prose matches are LOW precision. The POPULATION table above reports them in their own");
out.push("    column, but the density comparison's declared-AI arm (admittedCommits) admits on trailer");
out.push("    OR message, so a prose-only commit lands in the declared arm too — it is not blended only");
out.push("    for reporting, it is blended for the density measurement itself. Xiao et al. kept 1,292 of");
out.push("    3,004 retrieved mentions (~43%) after manual review; this does none, so the declared arm");
out.push("    inherits that unreviewed risk, not only the not-declared arm.");
out.push("  • This is a census of COMMITS, not of lines or of surviving code. A commit-level label");
out.push("    does not tell you which lines still stand at the pinned commit.");

console.log(out.join("\n"));

// #1509's receipt, after the scoring rather than before it: this job clones 18 repos on a monthly
// schedule, so a run that dies in the fetch phase is invisible for 30 days and reads exactly like a
// quiet month. recordMeasured throws on units=0, so an empty census fails loud instead of reading
// as a clean one.
recordMeasured("genai-admission-census", rows.length, "pinned corpus repos censused for commit-level self-admission");

// Fail loud rather than let a broken classifier render as a negative result — see
// allZeroAdmissionError's own doc comment for why zero is treated as broken, not quiet, on this
// specific corpus.
const allZeroError = allZeroAdmissionError(totals.admitted, totals.commits, rows.length);
if (allZeroError) {
  console.error(`ERROR: ${allZeroError} Refusing to exit 0.`);
  process.exitCode = 1;
}
