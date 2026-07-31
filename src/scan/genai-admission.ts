// Classification for the commit-level self-admitted-GenAI census (#1600). Kept out of
// src/cli/genai-admission-census.ts, which clones the corpus at module scope, so the logic can be
// tested without a network fetch — the same split handrolled-frequency.ts uses.
//
// WHAT A "SELF-ADMISSION" IS, and why it is the ground truth the retired density ratio lacked.
// docs/design/m6-corpus-frequency.md used to publish an "AI code carries the hand-rolled catalogue
// at ~Nx professional density" ratio computed across per-repo `provenance` tiers that WE assigned
// by inspection. Nothing verified those labels. A self-admission is instead DECLARED by the commit's
// own author, and at commit granularity a comparison holds repo, language, era and team constant.
//
// Xiao et al., "Self-Admitted GenAI Usage in Open-Source Software" (arXiv:2507.10422, read in full
// 2026-07-30) is the source of the concept and of the two-signal split below.

import { NON_PRODUCT } from "../detectors/load-sources.js";

// Assistants whose name in a trailer or a message is a declaration of GenAI involvement. ChatGPT and
// Copilot are Xiao et al.'s own pair (the two most-used tools in the 2023 Stack Overflow survey);
// the rest postdate their February 2024 sample and are what this corpus's repos actually use —
// flori-web's trailers read `Claude <noreply@anthropic.com>`, which their ChatGPT/Copilot regex
// does not match.
const ASSISTANTS = /claude|copilot|chat\s?-?_?gpt|openai|cursor|codex|gemini|devin|aider|windsurf|sourcegraph|tabnine/i;

// Deliberately IDENTICAL to src/cli/handrolled-frequency.ts's product filter, so "commits in the
// population" and "code in the density figure" name the same files rather than two nearby ideas.
export const isProductSource = (path: string): boolean => /\.(ts|tsx|jsx|mjs)$/.test(path) && !NON_PRODUCT.test(path);

// Sentinels rather than `-z`: a NUL-delimited stream is what makes text tooling classify output as
// binary (CLAUDE.md's greppable-sources rule). TRAILERS and MESSAGE get their own sentinel rather
// than being told apart by line position — the first revision of this tool keyed the trailer off
// "the first line", read the newline `%n` emits after the record sentinel, and scored EVERY repo at
// 0 trailer admissions across an 18-repo run while the trailer text fell through to the
// low-precision prose bucket. It exited 0 and printed a plausible table.
const REC = "@@HARVEY-COMMIT@@";
const MSG = "@@HARVEY-MSG@@";
const FILES = "@@HARVEY-FILES@@";
export const CENSUS_FORMAT = `${REC}%n%(trailers:key=Co-authored-by,valueonly,separator=%x2C)%n${MSG}%n%B%n${FILES}`;

export interface CommitCensus {
  commits: number;
  productCommits: number;
  /** High-precision: a machine-written `Co-authored-by:` trailer naming an assistant. */
  trailerAdmitted: number;
  /** Low-precision: an assistant named in the message only. Xiao et al. kept 1,292 of 3,004
   *  retrieved prose mentions (~43%) after manual review; this does no review at all. */
  proseOnlyAdmitted: number;
  admittedProduct: number;
  unadmittedProduct: number;
}

const splitOnce = (s: string, sep: string): [string, string] => {
  const i = s.indexOf(sep);
  return i === -1 ? [s, ""] : [s.slice(0, i), s.slice(i + sep.length)];
};

/** Counts one repo's `git log --format=CENSUS_FORMAT --name-only` output. */
export function censusOfLog(log: string): CommitCensus {
  const c: CommitCensus = { commits: 0, productCommits: 0, trailerAdmitted: 0, proseOnlyAdmitted: 0, admittedProduct: 0, unadmittedProduct: 0 };
  for (const raw of log.split(REC)) {
    if (!raw.trim()) continue;
    c.commits += 1;
    const [trailerPart, rest] = splitOnce(raw, MSG);
    const [message, files] = splitOnce(rest, FILES);
    const byTrailer = ASSISTANTS.test(trailerPart);
    const byProse = !byTrailer && ASSISTANTS.test(message);
    if (byTrailer) c.trailerAdmitted += 1;
    if (byProse) c.proseOnlyAdmitted += 1;

    if (!files.split("\n").some((f) => f.trim() !== "" && isProductSource(f.trim()))) continue;
    c.productCommits += 1;
    if (byTrailer || byProse) c.admittedProduct += 1;
    else c.unadmittedProduct += 1;
  }
  return c;
}

// A repo supplies a usable within-repo contrast only if BOTH arms clear a floor. 30 is the smallest
// arm reported as usable: below that a per-repo density difference is dominated by which handful of
// commits happened to land, and the point of #1600 is to stop publishing ratios that rest on a
// sample too small to carry them.
export const MIN_ARM = 30;

export const hasBothArms = (c: CommitCensus): boolean => c.admittedProduct >= MIN_ARM && c.unadmittedProduct >= MIN_ARM;

/** Which commits in one repo's history declared GenAI involvement. Built from the same log the
 *  census reads, so the density pass and the feasibility verdict classify identically. */
export function admittedCommits(log: string): Set<string> {
  const admitted = new Set<string>();
  for (const raw of log.split(REC)) {
    if (!raw.trim()) continue;
    const [trailerPart, rest] = splitOnce(raw, MSG);
    const [message, tail] = splitOnce(rest, FILES);
    if (!ASSISTANTS.test(trailerPart) && !ASSISTANTS.test(message)) continue;
    const sha = tail.trim().split("\n")[0]?.trim();
    if (sha) admitted.add(sha);
  }
  return admitted;
}

/** Format for the commit->arm map: the census fields plus the sha, emitted after the FILES
 *  sentinel so `--name-only` output (which the density pass does not need) can be omitted. */
export const ADMISSION_FORMAT = `${REC}%n%(trailers:key=Co-authored-by,valueonly,separator=%x2C)%n${MSG}%n%B%n${FILES}%n%H`;

/** Per-line blame attribution, split into the two declared arms. `lines` is the denominator and
 *  `findings` the numerator of a within-repo density comparison. */
export interface ArmTally {
  linesAdmitted: number;
  linesUnadmitted: number;
  findingsAdmitted: number;
  findingsUnadmitted: number;
}

/** Parses `git blame --line-porcelain` into one commit sha per line, in file order. */
export function blameLineShas(porcelain: string): string[] {
  const shas: string[] = [];
  for (const line of porcelain.split("\n")) {
    // A line record opens with `<sha> <origLine> <finalLine>[ <numLines>]`; the sha repeats for
    // subsequent lines of the same group, so matching the header alone yields exactly one per line.
    const m = /^([0-9a-f]{40}) \d+ \d+/.exec(line);
    if (m?.[1]) shas.push(m[1]);
  }
  return shas;
}

export const density = (findings: number, lines: number): number | null => (lines === 0 ? null : findings / (lines / 1000));
