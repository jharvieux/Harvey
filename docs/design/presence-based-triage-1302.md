# Presence-based finding classes vs. the triage reachability exclusion (#53 / #1302)

**Every number here is from a run on 2026-07-28. Nothing is recalled.** Re-run the procedure in §3
before quoting any of it — the subject is an LLM verifier, so these are samples, not constants.

## 1. The claim under test

#1302: the `/triage` verifier's exclusion rule 2 — *"Test-only code, **dead code**, example/fixture
code"* — is a **reachability** heuristic, and it was being applied to a **presence-based** class. A
committed credential is compromised the moment it is pushed, whether or not any code imports the
file. #53's live run against `targets/calibration` recorded the verifier dropping a genuine
hardcoded `service_role` JWT in `lib/admin.js` "because nothing currently imports that file".

The reachability exclusion is not wrong in general — it is the single largest true suppressor of
scanner noise. The defect is its **scope**, not its existence.

## 2. Verifying the defect before fixing it

**The drop did not reproduce.** Measured against a clean fixture with the real Phase 3a verifier
prompt from the `triage` skill and **no org rules loaded**, 3 of 3 independent verifiers returned
`TRUE_POSITIVE`. Each raised the presence-vs-reachability distinction unprompted, e.g.:

> "That reachability gap doesn't save the finding, though: this is a hardcoded-credential exposure,
> not an injection sink that needs a request to trigger it."

Two things follow, and both are recorded rather than resolved:

1. **#53's observation carried a confound it did not separate.** Its file sat in
   `targets/calibration/` — a path where the *example/fixture* clause of the very same exclusion
   applies for an independent and entirely legitimate reason. "Nothing imports it" may have been the
   verifier's stated rationale for a verdict that another clause also justified.
2. **Three votes on one fixture on one day is weak evidence of absence.** The behaviour is emergent
   from a model, not guaranteed by the prompt. That is precisely why it is worth converting into a
   stated contract: an emergent property is one model revision away from not holding, and nothing
   would fail loudly when it stopped.

So the rule added to `briefs/fp-rules.txt` **states a contract; it does not repair a live
regression.** Recording it the other way round would be a false reason attached to shipped work.

## 3. The measurement, so it can be re-run

**Fixture** — four files, a normal Next.js tree, git-initialised and committed. The point of the
layout is to isolate the variable: the credential file is *unimported*, but its path carries no
`test`/`fixture`/`example` marker — which is what exclusion rule 2's other clauses key on, and what
#53's `targets/calibration/` path did carry.

| file | role |
|---|---|
| `lib/legacyAdminClient.js` | **the subject** — a `service_role`-shaped JWT hardcoded at line 5, exported, imported by nothing |
| `lib/legacyReportQuery.js` | **the scope control** — template-literal SQL injection, also imported by nothing |
| `lib/supabaseClient.js` | a correct `process.env` anon-key client (the "project knows the right pattern" contrast) |
| `pages/api/profile.js` | the only route; uses `supabaseClient`, never the legacy files |

The JWT in the subject file is **fake** — a fake signature over a payload whose `ref` is
`measureref001` — matching the convention `targets/calibration/lib/admin.js` already uses. Its
payload decodes to `{"iss":"supabase","ref":"measureref001","role":"service_role",…}`, which is the
only signal that distinguishes a `service_role` key from a public `anon` key.

**Procedure.** Assemble the Phase 3a verifier prompt from the `triage` skill verbatim, append the
`FINDING UNDER REVIEW` block, and spawn 3 independent `general-purpose` verifiers per arm (the
skill's default `--votes 3`), each with a fresh context. The only difference between arms is whether
`briefs/fp-rules.txt` is appended under the `ORG-SPECIFIC RULES:` heading — which is exactly what
`/triage --fp-rules briefs/fp-rules.txt` does.

**CORRECTION 2026-07-31 (#1412).** The sentence above states the intended procedure, and the PR that
shipped this document repeated it as "3 independent general-purpose verifiers per arm". That is true
of arms A and B and **was not true of arm C, which ran at N=1** — the table below always said so, and
the two statements were never reconciled. Arm C is the *load-bearing control*: it is what
distinguishes "the brief narrowed the exclusion" from "the brief weakened reachability generally",
and one sample does not separate the two. Recorded here rather than only in a PR body, because a
PR body is swept by nothing.

## 4. Results

| arm | finding | org rules | N | verdict | detail |
|---|---|---|---|---|---|
| A | hardcoded `service_role` JWT, unimported | **no** | 3 | **3/3 TRUE_POSITIVE** | all three reasoned presence ≠ reachability unprompted; `EXCLUSION_RULE: none` |
| B | same finding | **yes** | 3 | **3/3 TRUE_POSITIVE** | all three cited the presence-based rule as the reason reachability does not decide it |
| C | SQL injection in dead code, unimported | **yes** | **1 — UNDER-SAMPLED, see below** | **1/1 FALSE_POSITIVE** | `EXCLUSION_RULE: 2 (dead code with no reachable caller)` |

Arm C is the one that makes arm B mean something. A rule that rescued the credential by weakening
reachability *generally* would have rescued the unreachable SQL injection too. It did not: the same
verifier, reading the same brief, suppressed the injection on rule 2 and said why —

> "This is not a presence-based class (credential-in-repo) — it's a reachability question, and the
> reachability test fails."

**The narrowing is a narrowing.** That is the property worth re-testing when this is re-run, more
than the arm-B result itself.

## 5. What is and is not gated

- **Gated in CI:** `src/fp-rules.test.ts` holds the carve-out to a CONTRACT, not to a word list
  (#1412). `carveOutDefects()` fails if the section loses one of the four presence classes, if any of
  its three overrides stops being a prohibition, if a hedging modal (`may`, `consider`, `generally`,
  …) appears on a `do NOT`/`never` line, if the class list stops declaring itself non-generalizing,
  if the verdict rule readmits the call path, or if reachability stops being decisive for everything
  else. This exists because #1302's root cause was not a wrong rule — it was a limitation recorded in
  a venue (`docs/tier1-runbook.md`) that no future engagement would read, and which did not survive a
  skill upgrade.
- **Gated in CI, the reason the above is not a word list:** six `#1412 NEGATIVE CONTROLS` cases each
  reword the section *without deleting anything* — turning `do NOT cite` into `you may cite`,
  inserting `generally` into an intact directive, readmitting the call path — and assert the contract
  goes red. Each also asserts the mutation actually applied, so a brief whose wording drifts fails
  loudly instead of passing vacuously. A seventh case rewords prose the contract does not depend on
  and asserts it still PASSES, so the check does not become a reason to leave the brief unimproved. The
  shipped #1302 test asserted only that certain phrases were PRESENT, which a brief reworded into
  uselessness satisfies.
- **NOT gated:** the verifier's actual behaviour. Harvey has no CI venue that runs a paid-LLM triage
  pass — the semantic gate (`validate-semantic.ts`) scores *recorded* pass artifacts for external
  targets with published answer keys, which this is not. §3/§4 are therefore a **dated measurement,
  re-runnable by hand**, not a standing gate. Treat the numbers as history the moment the model,
  the skill, or the brief moves.

## 6. Arm C's sample size, and why no gate re-runs the decision (#1412)

Two things #1412 asked for that this document now states rather than leaves in a PR body.

**Arm C is still N=1.** Re-running it needs three fresh general-purpose LLM verifiers spawned per
arm; the executor working #1412 on 2026-07-31 had no sub-agent capability in its tool set, so it
could not spawn even one. That is a statement about that session's tooling, not about the
experiment — the procedure in §3 is unchanged and runs in minutes for whoever has it. It is carried
open on #1412 rather than closed, because the control being under-sampled is precisely the defect
#1412 was filed on and re-recording it as done would repeat it.

**And no standing venue re-runs the decision.** #1412 offered two ways to satisfy that: build the
venue, or record the decision not to buy one. The second is the honest answer today, and it is a
product ruling about spend, not an engineering fact:

<!--
REASON: the presence-based triage decision has no standing CI venue — nothing re-runs a paid-LLM triage pass, so §3/§4 stay a dated hand-re-runnable measurement while the text-contract gate holds the brief
KIND: decisional
PROVENANCE: MEASURED 2026-07-31 — `pnpm validate-scored-gates` lists every scored gate and its cadence; no gate invokes an LLM triage pass, and validate-semantic.ts (the closest venue) scores RECORDED artifacts for external targets with published answer keys, which this fixture is not
OWNER: operator
DECISION: #1412 (asked there on 2026-07-31 with the proposed wording; unanswered at time of writing)
TOUCHES: briefs/fp-rules.txt, src/fp-rules.test.ts, docs/design/presence-based-triage-1302.md
-->

A decisional reason carries no `FALSIFIER` by design — re-running a command against a spend ruling is
a category error, and `pnpm validate-reasons` refuses it. What the reason buys is that the gap is now
swept: `validate-reasons` reads this block, and a decision that is never made stays visible instead of
living in a paragraph nobody re-reads.
