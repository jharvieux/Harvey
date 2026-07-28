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

## 4. Results

| arm | finding | org rules | verdict | detail |
|---|---|---|---|---|
| A | hardcoded `service_role` JWT, unimported | **no** | **3/3 TRUE_POSITIVE** | all three reasoned presence ≠ reachability unprompted; `EXCLUSION_RULE: none` |
| B | same finding | **yes** | **3/3 TRUE_POSITIVE** | all three cited the presence-based rule as the reason reachability does not decide it |
| C | SQL injection in dead code, unimported | **yes** | **1/1 FALSE_POSITIVE** | `EXCLUSION_RULE: 2 (dead code with no reachable caller)` |

Arm C is the one that makes arm B mean something. A rule that rescued the credential by weakening
reachability *generally* would have rescued the unreachable SQL injection too. It did not: the same
verifier, reading the same brief, suppressed the injection on rule 2 and said why —

> "This is not a presence-based class (credential-in-repo) — it's a reachability question, and the
> reachability test fails."

**The narrowing is a narrowing.** That is the property worth re-testing when this is re-run, more
than the arm-B result itself.

## 5. What is and is not gated

- **Gated in CI:** `src/fp-rules.test.ts` asserts the carve-out still names all four presence-based
  classes, still forbids the two exclusions that would drop a committed credential, still waives the
  call-site requirement, and still preserves reachability for everything else. This exists because
  #1302's root cause was not a wrong rule — it was a limitation recorded in a venue
  (`docs/tier1-runbook.md`) that no future engagement would read, and which did not survive a skill
  upgrade. A brief that silently loses the section now fails a test.
- **NOT gated:** the verifier's actual behaviour. Harvey has no CI venue that runs a paid-LLM triage
  pass — the semantic gate (`validate-semantic.ts`) scores *recorded* pass artifacts for external
  targets with published answer keys, which this is not. §3/§4 are therefore a **dated measurement,
  re-runnable by hand**, not a standing gate. Treat the numbers as history the moment the model,
  the skill, or the brief moves.
