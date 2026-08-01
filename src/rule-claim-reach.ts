// #1665. Gate 4 (src/disclosure-venue.ts) checks that a bound written in a rule's COMMENTS reaches
// its `message`. That is one direction. The direction that reaches the client is the other one: a
// `message` advertising call sites the patterns never match tells a client a class was checked when
// the arms for it were dead. An under-claim annoys; an over-claim is a false negative wearing
// coverage.
//
// #1657 is the recorded instance. `harvey-ldap-injection` carried ONE block-level
// `focus-metavariable: $OPTS` over a four-arm `pattern-either`; only the `search` arms bind $OPTS,
// so `bind`, `compare` and `modify` matched nothing while the message enumerated all four.
//
// WHAT THIS CHECKS — the structural half, and the predicate is published rather than described:
// inside a `patterns:` conjunction carrying `focus-metavariable: $X`, an arm of a sibling
// `pattern-either` that never mentions $X is dead WHEN nothing else in the conjunction binds $X
// either. The two exemptions are load-bearing and were both measured against the live rule set:
//
//   - a conjunct outside the disjunction binds $X (`harvey-open-redirect`, `harvey-ssrf-fetch`:
//     the sanitizer's `pattern-inside` arms are context, and the sibling `pattern:` supplies $X).
//     Predicate without this exemption: 16 hits, all 16 of that shape, 0 real.
//   - the disjunction binds $X in NO arm at all — then it is a context constraint like the LDAP
//     rule's own import guard, not the binder.
//
// So the shape flagged is a PARTIALLY-binding disjunction under a focus nothing else backs, which
// is exactly the #1657 defect and is the only arrangement in which some arms match and their
// siblings silently do not.
//
// MEASURED 2026-07-31 over all 10 rule files / 114 rules: 101 `patterns:` blocks carry a focus, and
// the predicate reports 0 dead arms. So this ships as a ratchet against re-introduction, not as a
// backlog — the population it would have flagged is #1657's rule, which `deadFocusArmsInDoc` is
// tested against in its pre-fix form.
//
// WHAT IT DOES NOT CHECK, said here so a green run is not read as "no rule over-claims":
// #1665 also names a `pattern-inside` that excludes a listed form and a `metavariable-regex`
// narrower than the prose. Both need the message's PROSE read against the patterns. That
// message-side predicate was BUILT and MEASURED before being left out of the PASS/FAIL, rather
// than declined on inspection — `unreachedMessageTokens` below is it, and the gate prints its
// count on every run so the figure is re-derived instead of recalled.
//
// MEASURED 2026-07-31: 53 backticked identifier tokens across all 114 rule messages, 13 of them
// absent from their own rule's patterns, over 9 rules — `filter.escape`/`EqualityFilter`
// (harvey-ldap-injection), `fs`/`root` (harvey-path-traversal), `sax` (harvey-xxe-parse),
// `res.send` (harvey-csv-formula-injection), `algorithms` (harvey-jwt-verify-noalg) and 4 more.
// Read one by one, every hit is the fix the message recommends or a form the message itself names
// as excluded: 0 of 13 are over-claims. A PASS/FAIL on that predicate would fail 9 correct rules
// and none of the defective shape, so it is reported, not gated.

import { parse } from "yaml";

type DeadArm = {
  readonly file: string;
  readonly id: string;
  readonly focus: string;
  readonly arm: string;
};

type ReachReport = {
  readonly rules: number;
  readonly focusBlocks: number;
  readonly dead: readonly DeadArm[];
};

// Every string reachable under a pattern node EXCEPT the focus declarations themselves — a
// `focus-metavariable: $X` naming $X is the claim under test, so counting it as a binding would
// make the check vacuous.
function patternStrings(node: unknown, out: string[] = []): string[] {
  if (typeof node === "string") {
    out.push(node);
    return out;
  }
  if (Array.isArray(node)) {
    for (const n of node) patternStrings(n, out);
    return out;
  }
  if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k === "focus-metavariable") continue;
      patternStrings(v, out);
    }
  }
  return out;
}

// `$OPTS` must not be satisfied by `$OPTSX`; semgrep metavariable names run to a word boundary.
function binds(node: unknown, metavariable: string): boolean {
  return new RegExp(`\\${metavariable}(?![A-Za-z0-9_])`).test(patternStrings(node).join("\n"));
}

function focusesOf(conjuncts: readonly Record<string, unknown>[]): string[] {
  const found: string[] = [];
  for (const c of conjuncts) {
    const f = c?.["focus-metavariable"];
    if (typeof f === "string") found.push(f);
    else if (Array.isArray(f)) for (const x of f) if (typeof x === "string") found.push(x);
  }
  return found;
}

function walk(node: unknown, file: string, id: string, report: { focusBlocks: number; dead: DeadArm[] }): void {
  if (Array.isArray(node)) {
    for (const n of node) walk(n, file, id, report);
    return;
  }
  if (!node || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  if (Array.isArray(obj["patterns"])) {
    const conjuncts = (obj["patterns"] as unknown[]).filter(
      (c): c is Record<string, unknown> => !!c && typeof c === "object",
    );
    const focuses = focusesOf(conjuncts);
    if (focuses.length > 0) report.focusBlocks++;
    for (const metavariable of focuses) {
      const eithers = conjuncts.filter((c) => Array.isArray(c["pattern-either"]));
      const plain = conjuncts.filter((c) => !eithers.includes(c) && !("focus-metavariable" in c));
      const backed =
        plain.some((c) => binds(c, metavariable)) ||
        eithers.some((e) => (e["pattern-either"] as unknown[]).every((a) => binds(a, metavariable)));
      if (backed) continue;
      for (const e of eithers) {
        const arms = e["pattern-either"] as unknown[];
        const bound = arms.filter((a) => binds(a, metavariable));
        if (bound.length === 0 || bound.length === arms.length) continue;
        for (const a of arms) {
          if (!binds(a, metavariable)) {
            report.dead.push({ file, id, focus: metavariable, arm: JSON.stringify(a) });
          }
        }
      }
    }
  }
  for (const v of Object.values(obj)) walk(v, file, id, report);
}

export function deadFocusArmsInDoc(text: string, file: string): ReachReport {
  const doc = parse(text) as { rules?: Record<string, unknown>[] } | null;
  const rules = doc?.rules ?? [];
  const report = { focusBlocks: 0, dead: [] as DeadArm[] };
  for (const rule of rules) walk(rule, file, String(rule["id"] ?? "<unnamed>"), report);
  return { rules: rules.length, focusBlocks: report.focusBlocks, dead: report.dead };
}

export function auditRuleReach(files: ReadonlyMap<string, string>): ReachReport {
  let rules = 0;
  let focusBlocks = 0;
  const dead: DeadArm[] = [];
  for (const [file, text] of files) {
    const one = deadFocusArmsInDoc(text, file);
    rules += one.rules;
    focusBlocks += one.focusBlocks;
    dead.push(...one.dead);
  }
  return { rules, focusBlocks, dead };
}

// The message-side predicate measured above. Reported by the gate, never gated on: its 13 hits are
// remediation vocabulary, and the count is printed each run so a change in it is visible.
export function unreachedMessageTokens(files: ReadonlyMap<string, string>): { id: string; tokens: string[] }[] {
  const out: { id: string; tokens: string[] }[] = [];
  for (const [, text] of files) {
    const doc = parse(text) as { rules?: Record<string, unknown>[] } | null;
    for (const rule of doc?.rules ?? []) {
      const message = String(rule["message"] ?? "");
      const patterns = patternStrings(
        Object.fromEntries(Object.entries(rule).filter(([k]) => k.startsWith("pattern"))),
      ).join("\n");
      const tokens = [...message.matchAll(/`([^`]+)`/g)]
        .map((m) => m[1] ?? "")
        .filter((t) => /^[A-Za-z_$][\w.$]*$/.test(t))
        .filter((t) => !patterns.includes(t.split(".").pop() ?? t));
      if (tokens.length > 0) out.push({ id: String(rule["id"]), tokens });
    }
  }
  return out;
}
