// #1402 — `set -e` DOES NOT WATCH THE COMMANDS INSIDE A MULTI-COMMAND `$( … )`.
//
// This is the sibling of #1422's pipefail defect (src/workflow-pipefail.test.ts) and it is a
// DIFFERENT mechanism, which is why it needs its own check: #1422 is about a step that loses a
// pipeline's exit code for want of `pipefail`, and it treats a step as guarded once `set -o
// pipefail` is in effect. The step this one was found in already had `set -euo pipefail` on its
// first line, and still swallowed a failure.
//
// MEASURED 2026-07-31, GNU bash 5.3.15, all four under `set -euo pipefail`:
//
//   x=$(false)                            -> exit 1   set -e SEES it
//   x=$(false; echo ok)                   -> exit 0   MASKED, x=ok
//   x=$( { false; echo ok; } )            -> exit 0   MASKED, x=ok
//   x=$( { false; echo ok; } | tail -1 )  -> exit 0   MASKED
//
// So the brace group is NOT the ingredient and neither is the pipeline: what matters is that the
// substitution runs MORE THAN ONE command, because the substitution's exit status is the LAST
// command's and that is the only status the enclosing assignment can see. A single-command
// substitution is safe and is the overwhelmingly common form in this repo.
//
// The live instance was `.github/workflows/owasp-ack-watch.yml`'s idempotence read, which captured
// two `gh issue view` calls in one substitution. With a stub `gh` whose first call exits 1, the step
// ran to completion with exit 0 and `last` holding only the SECOND call's output — silently losing
// the body-stamped state that the same block writes on its first report, so it re-announced a change
// it had already reported. Fixed by capturing each read as its own top-level assignment.
//
// WHAT THIS CHECK DOES NOT SEE, stated because an unstated bound reads as coverage. The extractor is
// textual, not a shell parser: it finds `$(`, walks to the matching `)` counting nesting, and asks
// whether the body contains a top-level `;` or newline. It deliberately does NOT track quoting, so a
// `;` inside a quoted argument (`jq -r '.a; .b'`) would be reported. That is over-reporting, which is
// the safe direction here and is measured to cost nothing today: the population of such cases across
// `.github` is currently ZERO, so the check runs with no exemption list. `$'…'`, backtick
// substitution and `${ …; }` command substitution (bash 5.3) are not modelled; backticks appear
// nowhere in `.github` and are their own defect if they do.

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { readNamesSafe } from "./fs-walk.js";

const GITHUB = join(process.cwd(), ".github");

/** Every `run:` script body in the workflows and the composite actions, with its source location. */
function runBlocks(): { file: string; line: number; script: string }[] {
  const files = [
    ...readNamesSafe(join(GITHUB, "workflows"))
      .filter((f) => f.endsWith(".yml"))
      .map((f) => join(GITHUB, "workflows", f)),
    ...readNamesSafe(join(GITHUB, "actions")).map((d) => join(GITHUB, "actions", d, "action.yml")),
  ];

  const out: { file: string; line: number; script: string }[] = [];
  for (const file of files) {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue; // an `actions/` entry that is a file, or has no action.yml
    }
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const m = /^(\s*)(?:- )?run: \|?\s*$/.exec(lines[i] as string);
      if (!m) continue;
      const indent = (m[1] as string).length + 2;
      const body: string[] = [];
      for (let j = i + 1; j < lines.length; j++) {
        const l = lines[j] as string;
        if (l.trim() !== "" && (l.length - l.trimStart().length) < indent) break;
        // Comments are not code. The fix for #1402 documents the bad shape in a comment directly
        // above the good one, and a check that cannot tell those apart flags its own remediation.
        body.push(/^\s*#/.test(l) ? "" : l);
      }
      out.push({ file: file.replace(process.cwd() + "/", ""), line: i + 1, script: body.join("\n") });
    }
  }
  return out;
}

/**
 * Bodies of every OUTERMOST `$( … )` in `script`, matched by counting nesting rather than by regex.
 * Outermost only: a nested substitution is part of its parent's single command, and reporting both
 * would double-count. Scanning resumes after the parent's closing paren.
 */
export function commandSubstitutions(script: string): string[] {
  const found: string[] = [];
  for (let i = 0; i < script.length - 1; i++) {
    if (script[i] !== "$" || script[i + 1] !== "(") continue;
    if (script[i + 2] === "(") continue; // $(( arithmetic ))
    let depth = 1;
    let quote: string | null = null;
    let j = i + 2;
    for (; j < script.length && depth > 0; j++) {
      const ch = script[j] as string;
      // Quote-aware, because it has to be: corpus-drift.yml's slug reader contains
      // `sed -E 's/.*\+([0-9]+).*/\1/'`, and a bare paren counter ends the substitution on that
      // regex's `)` and hands back a truncated body that then classifies as garbage.
      if (quote) {
        if (ch === quote) quote = null;
        continue;
      }
      if (ch === "'" || ch === '"') quote = ch;
      else if (ch === "(") depth++;
      else if (ch === ")") depth--;
    }
    if (depth !== 0) continue; // unbalanced even with quotes tracked — not something to guess at
    found.push(script.slice(i + 2, j - 1));
    i = j - 1;
  }
  return found;
}

/**
 * Compound constructs whose own `;` separators sit at brace/paren depth 0, so the flat splitter
 * below reads one `while … do … done` as several commands.
 *
 * This is the check's ONE exclusion and its population is ONE: `.github/workflows/corpus-drift.yml`'s
 * slug reader, a single pipeline ending `| while read -r ln; do … done | sort -u`. Modelling `do`/
 * `done`/`then`/`fi` as depth would make this a shell parser; excluding them costs the ability to see
 * a genuine two-command capture that also happens to contain a loop, which has never occurred here.
 */
const COMPOUND = /(^|\s)(do|done|then|fi|case|esac|elif)(\s|$)/;

/**
 * True when a substitution body runs more than one command, so `set -e` cannot see the first fail.
 *
 * A PIPELINE is one command for this purpose and is deliberately not split on: its exit status is
 * governed by `pipefail`, which is #1422's check, not this one. A BACKSLASH-CONTINUED NEWLINE is not
 * a separator either — missing that was the first thing this check got wrong, and it over-reported
 * two real single-command reads in corpus-drift.yml and owasp-ack-watch.yml that are simply written
 * across lines.
 */
export function runsMoreThanOneCommand(body: string): boolean {
  const joined = body.replace(/\\\n/g, " ");
  if (/^\s*\{/.test(joined)) return true; // a brace group is multi-command by construction
  if (COMPOUND.test(joined)) return false; // see COMPOUND — one excluded shape, population one
  let depth = 0;
  const parts: string[] = [];
  let current = "";
  for (const ch of joined) {
    if (ch === "(" || ch === "{") depth++;
    else if (ch === ")" || ch === "}") depth--;
    if (depth === 0 && (ch === ";" || ch === "\n")) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts.filter((p) => p.trim() !== "").length > 1;
}

describe("#1402 a multi-command $( … ) hides its first command's failure from set -e", () => {
  // The premise, executed rather than asserted. If bash ever stopped masking, this check would be
  // guarding nothing and should be deleted — so the ratchet below is only meaningful while this
  // passes. Both directions in one place.
  it("bash really does mask the failure, and really does not for a single command", () => {
    const run = (script: string) => {
      try {
        execFileSync("bash", ["-c", `set -euo pipefail; ${script}`], { encoding: "utf8" });
        return 0;
      } catch (e) {
        return (e as { status: number }).status;
      }
    };
    expect(run("x=$(false); echo unreachable")).toBe(1);
    expect(run("x=$(false; echo ok); [ \"$x\" = ok ]")).toBe(0);
    expect(run("x=$( { false; echo ok; } ); [ \"$x\" = ok ]")).toBe(0);
    expect(run("x=$( { false; echo ok; } | tail -1 ); [ \"$x\" = ok ]")).toBe(0);
  });

  it("classifies the shapes it is built to tell apart", () => {
    expect(runsMoreThanOneCommand("gh issue list --json number")).toBe(false);
    expect(runsMoreThanOneCommand("git diff --name-only 'a' HEAD")).toBe(false);
    // A pipeline is ONE command here — `pipefail` owns its exit code (#1422), not this check.
    expect(runsMoreThanOneCommand("git diff | grep -E '^@'")).toBe(false);
    // Both live over-reports this check produced on its first run, now the regression cases.
    expect(runsMoreThanOneCommand("git diff -U0 'a' HEAD -- src/x.ts \\\n  | grep -E '^@'")).toBe(false);
    expect(runsMoreThanOneCommand("gh api \"repos/x/issues/1/comments\" \\\n  --jq '.[-1] | \"c\"'")).toBe(false);
    // The COMPOUND exclusion, named so its cost is visible: this is corpus-drift.yml's slug reader,
    // one pipeline whose `while … do … done` carries depth-0 semicolons.
    expect(runsMoreThanOneCommand("git diff | while read -r ln; do head -n \"$ln\" f; done | sort -u")).toBe(false);
    // And the cost itself — a genuine two-command capture is NOT seen when it contains a loop.
    expect(runsMoreThanOneCommand("gh issue view 1\nwhile read -r x; do echo \"$x\"; done")).toBe(false);
    expect(runsMoreThanOneCommand("gh issue view 1 --json body\ngh issue view 1 --json comments")).toBe(true);
    expect(runsMoreThanOneCommand(" { gh issue view 1; gh issue view 2; } | tail -1 ")).toBe(true);
    // The exact live instance, verbatim from owasp-ack-watch.yml before the fix.
    expect(
      runsMoreThanOneCommand(` { gh issue view "$existing" --json body --jq '.body'
                      gh issue view "$existing" --json comments --jq '.comments[].body'; } \\
                    | sed -n 's/x/y/p' | tail -1 `),
    ).toBe(true);
  });

  it("finds substitutions by nesting, so an inner $( … ) does not end the outer one", () => {
    expect(commandSubstitutions('a=$(echo "$(date) x")')).toEqual(['echo "$(date) x"']);
    expect(commandSubstitutions("a=$((1 + 2))")).toEqual([]);
  });

  // The ratchet. No exemption list on purpose: the population is zero today, and a suppression entry
  // is indistinguishable from the silence this exists to remove.
  it("no `run:` in .github captures more than one command in a single $( … )", () => {
    const offenders = runBlocks().flatMap(({ file, line, script }) =>
      commandSubstitutions(script)
        .filter(runsMoreThanOneCommand)
        .map((body) => `${file}:${line} — $(${body.trim().slice(0, 120)})`),
    );
    expect(offenders).toEqual([]);
  });

  // Proof the ratchet reaches real files rather than an empty list — the #1065 shape, where a zero
  // from a scan that read nothing is indistinguishable from a clean one.
  it("actually read the workflows and their composite actions", () => {
    const blocks = runBlocks();
    expect(blocks.length).toBeGreaterThan(20);
    expect(blocks.some((b) => b.file.includes("owasp-ack-watch.yml"))).toBe(true);
    expect(blocks.some((b) => b.file.includes(".github/actions/"))).toBe(true);
    expect(blocks.flatMap((b) => commandSubstitutions(b.script)).length).toBeGreaterThan(5);
  });
});
