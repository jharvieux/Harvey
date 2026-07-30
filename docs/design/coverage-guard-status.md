# Coverage guard — what it actually proves (status)

Moved out of the root `CLAUDE.md` on 2026-07-25 so that dated status stops loading into every
session. The guard's **doctrine** (fail loud, never silently omit a module, disclosed-not-silent
scope decisions, the runner/`audit-coverage`/`coverage-scorecard`/`assertComplete` mechanics)
stays in `CLAUDE.md`. This file holds only the running record of what has been closed and what
is still open — update it here, not there.

## Known gaps in what the guard actually proves

**2026-07-26 (#1064, invariants 4+5) — the guard proved a module was ACCOUNTED FOR, never that its
findings REACHED THE DELIVERABLE.** Everything in the #1040/#1045/#1050/#1043/#1061/#1062 class
lived in that gap: the detector worked, the finding was dropped at a producer→consumer seam, the
ledger read clean and the run exited 0 with `COVERAGE PASS`. Closed by a second gate alongside this
one — `pnpm exec tsx src/cli/validate-conservation.ts` runs the real ten-module orchestrator against
`targets/calibration`, assembles the real deliverable, and asserts per module that its **planted**
finding was both produced by that module's own probe and present in the assembled document. Zero
findings for a planted defect is a FAIL (zero is legitimate in the field, never on the fixture), and
the produced/delivered split is deliberate: M9 captures `detect-static` unfiltered, so a deliverable-
only check would still see M7's rows after M7's capture broke entirely — which is how #1062 hid.
M2 is the one module with no plant (it needs a stood-up stack) and is recorded in `UNEXERCISED` with
a #1033 falsifier rather than dropped. Full record: `docs/design/conservation-of-findings.md`.

**2026-07-26 (#1096, invariant 1) — the plant-and-assert watches ten rows, not the whole set.** It
asks whether the finding planted for module Mn arrived; it cannot see the other 595. The
conservation LEDGER closes that: at the produce→assemble seam,
`produced == delivered + deduped + suppressed + capped + not-applicable`, every non-delivered
finding carrying a reason, any unaccounted delta a non-zero exit. It is asserted on the real
engagement path (`run-audit --findings-out/--sarif-out` refuses to export an unbalanced document),
not only on the fixture, so it holds on a client engagement where nothing is planted. Measured
2026-07-26 on `targets/calibration`: produced 605 = delivered 575 + deduped 30 + unaccounted 0.
`--seed-unaccounted` proves it can fail — and note that the plant-and-assert gate PASSES on that
same seeded run, which is the point of having both.

**2026-07-26 (#1096, invariant 2, PARTIAL — three of ten probes) — "ran, 0 findings" was
unfalsifiable.** A probe could return `{ status: "ran", findings: [] }` and say nothing about what
it looked at, so a broken capture (#1062), a scan that loaded zero product files (#1065) and a
genuinely clean tool were one sentence in the ledger. The typed result (`Examined { findings,
unitsExamined, scope } | NotAssessed { reason, provenance, falsifier }`, `src/audit-runner.ts`)
makes the silent version a compile error, and an `Examined` reporting zero units throws.
**M6, M7 and M9 are migrated; M1–M5, M8 and M10 are not** — the split is declared in
`TYPED_PROBES`/`UNTYPED_PROBES` with a per-module reason, checked exhaustively at module load, so
the half-migration is a visible fact rather than a grep. Remainder tracked in #1109.

**Still open here:** M1–M5/M8/M10 still return the untyped `ProbeOutcome` (above). The scheduled
workflow gap is CLOSED — `.github/workflows/conservation.yml` runs the gate weekly and on PRs that
touch the pipeline, and its two negative-control steps assert that a seeded loss and a seeded
unaccounted drop both still FAIL it.

**2026-07-25 (#1065) — the zero-files guard was UNREACHABLE for nine months, and the tally it fed
was a false clean.** `#350`'s "a scan of zero files records `partial`/`requires-live-run`, never
`ran`" (below) was true of the code and false in effect: the shared source loader counts
`package.json` and `next.config.js` as source files, and every real target has a `package.json`, so
the count the guard read could not reach zero. Measured on `targets/vuln-seam-app` — Harvey's own
standing offline fixture, 12 authored `.js` files — `pnpm detect-static` printed `loaded 2 source
files` and `0 findings across 0 classes`, and M5/M6/M7/M8/M9 all recorded `ran`. The loader's
extension filter omitted `.js`/`.cjs` entirely, so on a plain-JavaScript app the AST passes read
nothing at all. Three things changed: the loader reads the whole JS/TS family (and every detector's
own re-filter now imports that one regex instead of keeping a copy); the guard counts PRODUCT
SOURCE files, not config files; and a new `M1-EXT-00` counted not-assessed row reports files LOADED
vs. source-like files PRESENT, measured against a yardstick deliberately independent of the loader's
own filter, so the next narrowing fires a row instead of shrinking the scan in silence.
**The lesson generalises: a guard whose input can never reach its trigger value is indistinguishable
from no guard, and it reads as proof.**


**Updated 2026-07-16** (the 2026-07-15 gaps below all CLOSED that sweep): the exit-0-as-evidence blindness is closed (#350) — M4/M5/M8/M9 now derive status from the tool's machine-readable output, and a scan of zero files (or an incomplete per-workspace scan, #505) records `partial`/`requires-live-run`, never `ran`. M6's never-run alarm can no longer be cleared by an unread review packet (#351) — it reports `partial` until a reviewed verdict is recorded. The coverage ledger now HAS a path into the client report (#349): `run-audit --findings-out` assembles the derived ledger into the engagement findings.json and `report-template` renders per-module coverage, so a module that never ran shows as a "Not run" row with its reason rather than silence. The orchestrator's **derive-`ran`-from-artifact path LANDED** (#416 read side + #448 emit side): `run-audit --artifacts-dir <dir>` derives `ran` for the out-of-orchestrator passes (M1 semantic/live, M2 dynamic, M3 vitals, M6 verdict) from a fresh, target-matching `<module>.pass.json` and folds its findings into the deliverable — a stale/wrong-target artifact is rejected, never a silent `ran`. **Since #1042 all TEN modules consume a recorded pass**, not just those four: M7 replaces its `M7_LIGHTHOUSE_NOT_RUN` claim with the recorded Lighthouse pass, and M4/M5/M8/M9/M10 merge the pass's findings and NAME it on the row (upgrading `requires-live-run` → `partial`) without claiming `ran`, because a pass covers one tier and the orchestrator has no evidence about the others. Before #1042 `record-pass` accepted all ten while only four were read, so a recorded M7 pass was written and then silently dropped. `pnpm record-pass` emits one from any operator/LLM pass; `pnpm dynamic-validate` is the M2 producer. Schema/flow: `docs/design/audit-pass-artifacts.md`. M7 advisors (#434), M8 surviving-mutants (#435), and M10's data-map → `Finding[]` (#436) landed 2026-07-17; M3/M8 capture + explicit non-collection landed in #420. The **M2 live stand-up is now AUTONOMOUS** (#545): `pnpm dynamic-validate <t> --execute` provisions its own local Supabase, applies every Supabase project's migrations (per-DB across a monorepo's projects, #610), seeds two tenants + two auth users (per-user owner columns inferred from FK-to-auth graph, e.g. `author_id`, #617), and runs the live PostgREST cross-tenant matrix, the pg_graphql cross-tenant matrix (#877), and the wired-in auth-attack probe (#658) — which also ages a session across logout / refresh reuse / privilege revocation / password change (#878) — plus invitation-state revoked-BOLA (#905), soft-delete/restore/tenant-teardown data-residue (#907/#954), share-link identity-class (#952), Supabase Storage object-authorization (#956), API-token credential-store (#997), and **guest / cross-org-collaborator identity-class** (#1023 — a THIRD guest-role principal is really seeded and signed in, `M2-GUEST-SCOPE`; where the applied schema cannot express a guest the class is still a named not-assessed row, never a silent two-persona run) probes and a control-gated Realtime subscribe-and-assert runtime probe opt-in behind `HARVEY_PROBE_REALTIME` (#951, superseding the #906 NOT-ASSESSED disclosure; Phoenix wire shape proven live against realtime v2.100.0 — both the leak and the tenant-scoped verdict — #1003, `docs/design/realtime-wire-shape-live-proof.md`; **now all three channel classes and every published table**: `postgres_changes` runs one `M2-REALTIME-SCOPE-<table>` verdict per seeded scoped table rather than `cfg.tables[0]` alone (#1030), and Broadcast + Presence are probed cross-identity alongside the private-channel/Realtime-Authorization posture as `M2-REALTIME-CHANNEL-SCOPE` (#1029)), with no operator step (`src/pentest/live-standup.ts`); the app-route probe tier is built and proven live (#552 — a real Critical on a booted target). Every probed run also emits an `M2-SCOPE-RECONSTRUCTION` disclosure + per-surface/per-identity ledger (#875). The M2 methodology's portability to NON-Supabase apps was measured against VAmPI and crAPI (#880/#941) and the measured gaps are CLOSED (#965): an OpenAPI→route adapter, a response-shape-aware and target-supplied leak-confirmation predicate, an externalized victim-id source (operator seed / victim self-read, no PostgREST oracle required), and a per-route multi-origin external-target runner (`pentest.ts --mode=external`) — proven live against a real VAmPI container, where IDOR-OBJECT reached proven on the headline cross-user BOLA that the prior measurement recorded as MISSED (offline controls: `src/pentest/{external-target,object-leak,openapi-routes}.test.ts`). An external run probes the route-adaptive tier only; the DB oracle, the Supabase platform surfaces, and every schema-derived probe are disclosed as not-probed rows, never as coverage. MASS-ASSIGNMENT off-Supabase still reports not-applicable rather than a false clean (it needs a read-back oracle an external target does not expose, #995). The inter-service seam probes are WIRED and reachability-proven live (#161 CLOSED — route-based seam-discovery populates `profile.seams` #714, precision-hardened #716, monorepo behind-the-gateway service detection #719, and ran live against a real Stripe webhook receiver reaching a correct verdict). The seam probes' and the NO-RATE-LIMIT loop's *proven* (finding-producing) branches have now ALSO been exercised live (#717/#159 CLOSED; the #718 fixture is built at `targets/vuln-seam-app/`): a `pnpm dynamic-validate targets/vuln-seam-app --execute` run reached 4/4 seams proven with zero controls flagged, guarded against regression by the offline `src/pentest/vuln-seam-app.test.ts` and recorded in `docs/design/vuln-seam-app-live-validation.md`. **2026-07-28 (#1364) — of #448's five named out-of-orchestrator passes, only M2 dynamic self-emitted
its own artifact; the other four still routed through the generic operator CLI (`record-pass`), and
M1 live did not even reach that cleanly — `detect-deeper` had no findings output at all, so
recording it meant capturing stdout and hand-extracting `.findings` first, the exact manual step #448
asked to remove.** Closed for three of the remaining four: `src/cli/hotspot-scan.ts --artifacts-dir`
now writes `M3.pass.json` directly (findings + top-K hotspots + which of the full/reduced/unranked
tiers produced them); `src/cli/m6-agreement.ts --target/--artifacts-dir` now writes `M6.pass.json`
from the two-reviewer protocol's UNANIMOUS-flag verdicts (a split still goes to the human
adjudicator, never auto-promoted); and `detect-deeper --findings-out` removes the hand-extraction
step in front of M1 live's `record-pass` call, even though that pass still does not self-emit.
**Still open:** M1 semantic (`/vuln-scan → /triage`) has no self-emit path and is not expected to
gain one — it is an interactive LLM/skill invocation with no CLI Harvey's own code can shell out to,
so `record-pass` stays its only write path. Recorded reason with a falsifier, exercised both
directions: `docs/design/audit-pass-artifacts.md`.

**2026-07-30 (#1522) — correcting "derives `ran` … for M1" above.** `<module>.pass.json` was ONE
slot per module while M1 has THREE out-of-orchestrator tiers (semantic, live, connected), so
recording one deleted another — and, because the M1 probe's un-run-tier disclosure was gated on the
newest pass being `semantic`, recording the connected tier ALSO removed the sentence saying the
other two had never run. MEASURED 2026-07-30: after `record-pass --module M1 --pass connected` the
row read `ran` with no reason at all. The slot now ACCUMULATES (superseded tiers move to
`priorPasses`, nothing is discarded), every fresh tier's findings reach the deliverable, and M1
yields `ran` only when all three tiers have an artifact — short of that the row is `partial` and
NAMES the ones that do not. Re-measured through the real orchestrator on `targets/calibration`:
`M1 partial`, reason `1 of M1's 3 out-of-orchestrator tiers has no artifact proving it ran … live
(pnpm detect-deeper)`, `LEDGER PASS`, `COVERAGE PASS`.