# Environment dependency census

Issue #1906 adds an internal census of committed evidence and its environment dependencies. The owning command is `src/cli/environment-dependency-census.ts`; its normalized output is `src/environment-dependency-inventory.json`. This inventory records known consumers alongside explicit unresolved content. It leaves finding and rendered-report contracts unchanged.

## Discovery and the limit of completeness

The discovery denominator is every Git blob in an exact commit, including source, ordinary inline strings and numbers, extensionless structured data, fixtures, baseline files, generated evidence, workflow records, historical reports, and recorded reasons. Discovery reads Git object bytes; it does not execute the inspected modules or reason falsifiers. Current comparison also includes tracked edits and unignored additions. Ignored uncommitted artifacts are outside that population.

Each blob has a byte digest, byte length, Git identity/mode, content-format disposition, owner and reason. TypeScript/JavaScript input additionally has an AST literal count and literal digest, so an ordinary numeric measurement in an otherwise unrelated source file still changes its receipt. Content-based JSON/YAML and gzip decoding reach data outside conventional fixture names. Opaque input remains counted with an explicit reason; symlink and Gitlink destinations are retained as references and are not followed. Working-tree discovery rejects a symlink in any descendant path ancestor before reading that file.

Three populations stay separate: blob receipts, conservative vocabulary/residual rows, and authoritative evidence records. Every blob retains exactly one unresolved-content row even after an adapter resolves some of its contents. Regeneration preserves that residual. Consequently receipt coverage is complete for the declared Git tree, while semantic classification remains partial. Unlabelled meanings, indirect or reflective consumers, runtime-generated inputs and external state remain explicit limitations rather than implied evidence of a bound environment.

Only two exact circular outputs are excluded from input digests: `src/environment-dependency-inventory.json` and this measured document. Their explicit output-derived reasons are serialized. Census source, CLI, tests, and future census-named source files remain ordinary inputs. The inventory validates its own schema and semantic comparison separately. Retained commit payload and per-path Git object identities reconstruct the original tree, including excluded objects, so validation does not depend on pre-squash history remaining reachable.

Known source registries are resolved from their actual exported binding with a bounded static data interpreter. Named imports, constants, inline records, spreads, templates, and finite data factories are supported. Discovery traverses the complete committed relative value-import graph, including unused bindings and side-effect imports. Every top-level statement and initializer receives explicit admission. Unknown effect shapes, static class blocks, decorators and unmodeled calls or loops fail generation. Array callbacks preserve native short-circuit, iteration and flattening behavior; replacement strings preserve native substitutions.

The interpreter checks unused initializers with mutation of selected registry data refused. Selected records must contain finite scalar, array and plain-object data; nested opaque values, closures, unsupported objects and cycles are rejected before an authoritative adapter can consume them. Shared acyclic data remains valid. Mutations stay within the active finite factory transaction, so lazy lookup cannot reorder effects across module initializers. Named imports require an actual named export; a default-only declaration does not satisfy them. The bounded grammar rejects duplicate canonical value bindings in modules and factory scopes, including ambiguous import/local collisions. Separate scopes, erased type declarations, overload signatures and ordinary property overwrites remain supported. Module initialization and local lexical bindings preserve declaration readiness: eager reads before initialization fail, while valid hoisted functions and deferred import cycles remain supported. Relative imports follow the shipping tsx resolver; this is not a claim about every JavaScript loader. Property and destructuring keys use decoded identifier/string values and canonical numeric names; prototype exclusions apply after decoding. Physical escaped-key controls compare consumer selection and assertion credit with the shipping scorer. Finite built-in Set construction is restricted to module scope without shadowing. A narrow inert-initializer grammar also handles regular expressions and source metadata. JSON reads use authenticated snapshot bytes; the host-only-file control rejects a missing committed input. The interpreter rejects opaque path/package values in admission conditions and selected registry data. Native/package initialization and the exact standalone-entry-point guard receive explicit unresolved boundary rows; those declarations establish no observed environment identity, executed assertion or runtime-import certification. Pure unused factories that allocate independent arrays stay valid, and unused sibling objects remain outside the registry. Physical controls compare admitted methods with native results and reject unsupported effects. The real-tree test compares exact member IDs with the trusted runtime exports of CORPUS, EXTERNAL_CORPUS and SEMANTIC_CORPUS.

## Record contract and owners

Every dependency row has an evidence location, authoritative or explicitly unresolved consumer, dependency class, observed identity and its source, declared identity and its source, pin source, assertion venue/scope, freshness requirement and timestamps/enforcer, binding state, resolution, owner, and rationale. Missing identities or assertions remain null with a reason. Links preserve relationships to existing registries and artifact families.

| Binding state | Meaning |
| --- | --- |
| `pinned` | An observed/retained identity agrees with its pin and has a named consumer and assertion. The pin's scope remains explicit. |
| `recorded` | An identity observation or declaration is retained without satisfying the pin contract. The two identity fields distinguish these cases. |
| `accepted` | A positively established acceptance decision is required. Merely having OWNER and DECISION fields does not establish approval. |
| `wholly-unbound` | The record carries an owned reason for an unresolved identity/binding, including decisions whose acceptance is not established by the retained evidence. |

Resolution (`identified`, `dynamic`, `unresolved`) is a separate axis. A mutable action ref or runner selector can have a recorded declaration and dynamic resolution. A fixture can have an actual tool pin and an output-schema assertion while its environment behavior stays unresolved. A workflow declaration never increments the observed-identity counter. The offline census treats decision fields as references and requires evidence of affirmative approval before assigning accepted status; it infers no operator ruling.

Assertion scopes are environment behavior, output schema, and artifact integrity, with absence counted separately. They name available source assertions; this offline command executes none of them. Calibration rows receive an environment assertion only when the actual untagged static mechanical subset or the exact dedicated M6 scorer consumes them. The shared CLI's per-module counts give other module/live-tier rows no behavior-assertion credit; those rows retain their suite/tier follow-up reason.

The narrower populations are reused rather than copied into a second fixture registry:

| Existing registry | Reconciled members | Owner | Recorded status |
| --- | ---: | --- | --- |
| `#1853 external-corpus schema` | 186 | #1853 | not-present-at-base |
| `CORPUS imported/spread entries` | 1076 | src/scan/calibration.ts | present |
| `SEMANTIC_CORPUS` | 4 | src/scan/semantic-corpus.ts | present |
| `dry-run/artifact-family.json` | 5 | src/dry-run-artifacts.ts | present |
| `fixture-drift contracts + OSV contract` | 10 | #1901 output schema; #1909 environment | identity-disagreement |
| `src/recorded-reasons.ts` | 69 | src/recorded-reasons.ts | present |
| `src/scan/__fixtures__/FIXTURE-INVENTORY.md` | 16 | captured fixture integrity (#1130) | present |
| `src/scan/__fixtures__/corpus-advisories/manifest.json` | 17 | src/corpus-advisory-snapshot.ts | present |

The external corpus contains 17 target pins and 186 target/module baselines at these snapshots. Finding-count records use scoreExternalBaseline; the six mutation records use scoreMutationBaseline through the --m8 path, and five not-run records use revalidateNotRunReasons. Mutation and not-run rows borrow no finding-count assertion. #1853's proposed versioned per-target loader is absent; the census reads the actual monolith and its baseline/not-run shapes. The separate advisory manifest already has schema 2 and 17 payload records; those facts are kept distinct. These dependency observations belong to the immutable source identified below. Re-evaluate the current #1853/#1901/#1909 code contracts on each new census pass; the observations establish no persistent negative readiness condition. #1853 remains the migration owner, #1901 the captured-output/property owner, and #1909 the shared stability-record/environment-binding owner.

The fixture reconciliation preserves the current Semgrep 1.173.0 and TruffleHog 3.97.0 pins. TruffleHog's active 3.97.0 capture paths conflict with 3.96.0 identity declarations in the retained provenance and inventory prose; those rows stay recorded with an identity-disagreement reason. The census does not silently rewrite that history. The historical mechanical-run fixture separately retains Semgrep 1.164.0, its Node observation and its mixed Git versions.

Additional direct records cover the advisory payload digest/expiry contract, guard-mutation runtime/tool receipts, linked dry-run artifact family and historical M2 input, workflow runner/shell/locale declarations, historical docs evidence packages, and ATC post-parse reports. The raw-tool fixture inventory's exclusion of post-parse ATC summaries does not exclude them from this broader committed-evidence denominator. A historical package with no established current consumer retains an explicit unresolved consumer.

## Immutable measurements

Measured 2026-09-13 with generator source `45af15dfaa702fa1c2cb8563bae51c0faec57003`. The original input is `1c07012a173cf4c0c33f06012edeb1ed7deec580` (tree `a71866cd8e5bf50c7eaeb4c970c1c7d273bf77e9`); the implementation-inclusive input is `45af15dfaa702fa1c2cb8563bae51c0faec57003` (tree `11cfa859e15cefaa0e07270e2bc9ed73e8385db6`). These are immutable measurements, not claims about future HEADs. This document and its output inventory are the only circular exclusions.

| Population | Original input | Implementation-inclusive input |
| --- | ---: | ---: |
| Git blob receipts | 2,610 | 2,624 |
| Venues with an authoritative adapter | 108 | 108 |
| Other conservative candidate venues | 2,499 | 2,513 |
| Opaque venues | 3 | 3 |
| Residual-content rows | 2,610 | 2,624 |
| Vocabulary candidate rows | 3,426 | 3,471 |
| Authoritative evidence/dependency records | 2,218 | 2,221 |
| Observed identities in authoritative records | 272 | 272 |
| Declared identities in authoritative records | 277 | 280 |
| Authoritative records with unresolved resolution | 1,512 | 1,515 |
| Authoritative records with dynamic resolution | 456 | 456 |

All 2,624 implementation-inclusive blobs retain residual unresolved scope (2,624/2,624, 100%). Among the separate 2,221 authoritative records, 1,515/2,221 (68.21%) have unresolved resolution and 456/2,221 (20.53%) have dynamic resolution. These percentages describe different dimensions from binding state and receipt coverage; they are not a semantic-completeness score.

Declared assertion locations: 1,120 environment-behavior, 10 output-schema, 21 artifact-integrity, and 7,165 absent. Each is an assertion-location count, not an executed-test count.

The following state/resolution columns cover all rows in each class. The first two columns preserve the distinction between authoritative records and conservative candidates. The unresolved class includes residual-content rows plus known evidence whose environment class remains unresolved.

| Class | Authoritative records | Candidates | Pinned | Recorded | Accepted | Wholly unbound | Dynamic | Unresolved |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| tool | 312 | 567 | 12 | 212 | 0 | 655 | 181 | 650 |
| runtime | 237 | 785 | 1 | 4 | 0 | 1017 | 1 | 1016 |
| package-manager | 69 | 539 | 1 | 2 | 0 | 605 | 8 | 597 |
| database | 31 | 765 | 0 | 1 | 0 | 795 | 8 | 788 |
| runner-image | 39 | 75 | 0 | 39 | 0 | 75 | 37 | 75 |
| shell | 156 | 129 | 0 | 13 | 0 | 272 | 156 | 129 |
| locale | 18 | 77 | 0 | 18 | 0 | 77 | 18 | 77 |
| clock | 20 | 177 | 0 | 1 | 0 | 196 | 18 | 178 |
| mutable-data | 26 | 296 | 17 | 0 | 0 | 305 | 25 | 297 |
| source-revision | 196 | 58 | 186 | 9 | 0 | 59 | 4 | 59 |
| hardware | 1 | 3 | 0 | 0 | 0 | 4 | 0 | 4 |
| unresolved | 1116 | 2624 | 0 | 0 | 0 | 3740 | 0 | 3740 |

Every supported class has at least one authoritative record in this measurement. The schema always emits all classes and an owned explanation for any class with zero authoritative records. Such a zero describes this analyzer’s positive record population; residual content still prevents an absence claim. Physical tests cover empty classes and unknown declared-class rejection.

Original normalized inventory SHA-256: `7e6922e547ebef70de82aa80f1cf8587f07913a81ae77417d1cb11ff6bc00df5`. Implementation-inclusive inventory SHA-256: `8e0ea435455aa15dd2dc5d9d0b7b684dc5c94ad3eb3a22383cb4e3b5f0d7c72f`. The corresponding source-population digests are `a901ac030486ecb122bac153a37325506340571abf8b843c24b1268beced48b4` and `5691e5a84febc2c4cffad26831e69621aa285e983a582a5acb2857bb4ae38b3e`. Normalization sorts object keys and stable row/member IDs and includes no invocation timestamp.

## Reproduction and failure directions

Run from the repository root with the measured generator source. Generation reads committed bytes even in a dirty checkout. Review and commit the input changes before generating a replacement inventory; generation is the owning writer of the JSON artifact.

```sh
pnpm_config_verify_deps_before_run=false pnpm exec tsx src/cli/environment-dependency-census.ts --ref 1c07012a173cf4c0c33f06012edeb1ed7deec580 --out /private/tmp/harvey-1906-base-a.json
pnpm_config_verify_deps_before_run=false pnpm exec tsx src/cli/environment-dependency-census.ts --ref 1c07012a173cf4c0c33f06012edeb1ed7deec580 --out /private/tmp/harvey-1906-base-b.json
cmp /private/tmp/harvey-1906-base-a.json /private/tmp/harvey-1906-base-b.json
pnpm_config_verify_deps_before_run=false pnpm exec tsx src/cli/environment-dependency-census.ts --ref 45af15dfaa702fa1c2cb8563bae51c0faec57003 --out src/environment-dependency-inventory.json
pnpm_config_verify_deps_before_run=false pnpm exec tsx src/cli/environment-dependency-census.ts --check
pnpm_config_verify_deps_before_run=false pnpm exec vitest run src/environment-dependency-census.test.ts src/cli/environment-dependency-census.test.ts
```

Those generation, byte-comparison, current-tree comparison and focused-test commands exited 0. The focused suite and its physical failure controls are rerun against the publication revision. Scoped typecheck and lint also exited 0. Explicit `--check --ref <revision>` checks an archival snapshot and prints that mode; default `--check` compares current tracked/unignored inputs and never rewrites the inventory.

| Physical change / control | Native result | Required normalized consequence |
| --- | --- | --- |
| Unchanged input; repeated immutable generation | 0; byte-identical JSON | Same input and row populations |
| Add an ordinary evidence venue | 1 on current check | `unregistered-venue` |
| Remove a retained venue | 1 on current check | `removed-venue` |
| Hidden ordinary inline numeric literal | 1 on current check | `changed-venue`; old-ref comparison stays archival |
| Regenerate after the hidden literal | 0 | Residual row stays wholly unbound with absent identity/pin/assertion |
| New extensionless workflow venue | 1 before regeneration; 0 on generation | New owned rows and persistent residual content |
| Add a supported dependency class to an existing file | 1 | `unregistered-dependency` |
| Explicit unknown dependency class | 1 on generation | Rejection; no replacement inventory |
| Hidden literal in adapted workflow or census source | Failing comparison in physical tests | Adapter/self naming grants no scope exemption |
| Factory-built member and unconsumed sibling object | Exact ID equality in physical and real-tree tests | Actual members included, phantom excluded; unsupported call rejected |
| Side-effecting unused initializer, cross-initializer mutation, static class block, loop, accessor or shadowed constructor | Generation rejected in physical tests | Potential registry mutations receive no implicit admission |
| Unknown nested selected data or invalid named import | Generation rejected in physical tests | No missing module or false behavior-assertion credit |
| Read a lexical binding before initialization, including eager import cycles | Generation rejected in physical tests | No authoritative row from a source program that fails initialization |
| Valid hoisted function or deferred import cycle | Native and census membership agree | Supported readiness paths remain usable |
| Escaped module/tier identifiers, string keys, destructuring or numeric keys | Native scorer and census agree | Excluded rows receive zero behavior assertions; decoded prototype keys remain rejected |
| Duplicate canonical module, import or factory bindings | Generation rejected before output | Ambiguous or invalid source declarations receive no authoritative records |
| Parent directory replaced with a symlink | Current discovery rejected | Descendant bytes are not read through the link |
| Workflow declaration or pending decision | Typed physical tests pass | No fabricated observation or acceptance |
| Disable the production comparator in a copied immutable source archive | 1, with 3 relevant tests failing | Actual add/remove/hidden-inline tests lose their expected red direction |
| Restore the production comparator | 0, same 3 tests pass | Failure direction restored |

Exact argv, cwd, environment override, native exits, stdout/stderr and normalized physical inventories are retained in the implementation handoff under `/private/tmp/harvey-1906-publication-preview` and the linked independent-review handoff; the committed tests reproduce the physical directions in disposable Git repositories. Production-removal testing changes only a copied source archive. Regeneration never refreshes historical observation dates, advisory expiry, hosted collector identities or historical M2 evidence.

The committed real-population test checks the current tree. After input changes, review the changed evidence and unresolved rows, commit the inputs, regenerate the inventory through its CLI, run the current-tree check, and complete the repository's path-sensitive verification gate. Binding unresolved environments, replaying live tiers, #1853's migration, and #1901's property harness remain with their existing owners.
