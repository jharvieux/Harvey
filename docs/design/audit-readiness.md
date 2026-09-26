# Audit readiness execution (#1897)

Readiness uses the discovered `ReadinessPlanV1` as its command source. The plan
digest binds stage IDs, prerequisites, tokenized commands and the workspace
inventory. A source sentinel captured before discovery binds content and Git
state to execution admission. The CLI collects M1–M10 first, then executes
readiness and delivers both sets of results. Readiness has its own statuses;
it contributes no audit findings or module score.

## Operator inputs

Discover and inspect the plan with `--readiness-plan-out`. Request execution
with `--readiness-execute-out` and `--readiness-authorizations`. The authorization
JSON contains `schemaVersion: 1`, the exact `planSha256`, `stageAuthorizations`
and `approvedEnvNames`. Each authorization names a stable `stageId`, an `effect`,
and the operator's `source`, `reason` and `falsifier`. `containment` selects
`kind: "docker-local"`, an owned local Unix `socketPath`, and an already-present
immutable `imageId` (`sha256:` plus 64 hexadecimal characters). Optional
`nodePath`, `envPath` and `toolchainPath` name tools inside that image. The
top-level `toolchainPath`, when supplied, must match the selected image path.
`disposableTempParent` selects a directory outside the original source that is
visible at the same path to the daemon; VM-backed runtimes may need an explicitly
shared parent. No image is pulled and no host tool directory is mounted.
`timeoutMs` sets the stage
deadline, up to one hour. Environment values come from the operator process,
through the approved name list. Values are excluded from the authorization file.

The install stage needs both `--allow-target-install` and a `target-install`
effect review, including its declared lifecycle scripts. Other executable stages
need their own `disposable-local` review. `network-or-service` and `unknown`
effects receive a not-assessed receipt. Install permission also retains its
existing M8 meaning; review that module's provisioning scope when using the flag.
The readiness adapter's copy and child commands stay separate from the source
audit target. Missing containment or prerequisites produce explicit not-assessed
receipts. There is no host-process fallback. The runtime has no external network;
an install requiring unavailable packages remains a failed or not-assessed stage.

## Execution and evidence

The disposable copy excludes dependency, VCS and build artifacts. Source entries
and Git HEAD/status form before/after sentinels. Admission checks the real command
cwd against the copy and original source. The image observer verifies canonical
toolchain directories, their ancestors and the initial executable are root-owned
and not writable by group or other users. Each child receives
an isolated home/cache/temp environment plus approved values; runtime-control
names such as `NODE_OPTIONS` and `NODE_V8_COVERAGE` are refused as operator inputs.

The runner uses tokenized `spawn` with `shell: false`, drains both streams through
close, retains byte counts and SHA-256 digests, and bounds redacted head/tail
excerpts. Its default deadline is 120 seconds, followed by 250 ms termination
grace and one second close grace. Timeout, process errors, incomplete drainage,
output truncation and unconfirmed termination produce failed stage evidence.
The readiness runner uses a private Linux PID namespace in the selected local
container. It binds only the verified disposable root, disables network access,
drops target capabilities and enables no-new-privileges. The target runs with
nonzero UID/GID. A trusted namespace-init observer retains only SETUID/SETGID;
the target cannot write its root-owned metadata or signal it. A private writable
image overlay holds that metadata and is recorded explicitly. Fixed limits are
64 PIDs, 512 MiB and two CPUs per container. Linux and macOS controllers require
an owned local Unix socket and a Linux daemon; unsupported configurations are
disclosed before target work.

Approved values enter the target environment through bounded private stdin,
never runtime argv or container configuration. Runtime inspection proves the
exact image, container, lease and isolation settings. Target exit/close metadata
is read separately from container termination; a container exit cannot substitute
for a target exit. A passed readiness receipt requires verified target identity,
complete lifecycle and streams, an observed terminal namespace, and removal of
the exact container. The native process-group implementation is retained only as
a physical comparison test fixture; its success never proves readiness descendant
containment.

The scheduler serializes undeclared shared output ownership. A failed prerequisite
withholds its descendants while independent stages continue. Install-covered
codegen refers to the actual successful install receipt. Final receipt closure
checks the exact plan stage population, ordering, prerequisite statuses, process
lifecycle and cleanup. Cleanup follows settled child work and reports removal and
source preservation separately. If namespace termination or runtime-lease removal
is unconfirmed, the scheduler retains the shared output lease, withholds further
stage admission, and preserves the disposable root with a failed cleanup receipt.
Missing target metadata is a counted failure even when terminal namespace and
container-removal observations permit safe copy cleanup.

Authorization JSON is captured once before discovery and console output. A rejected
grant with independently valid names can still register values solely for
redaction; it grants no execution authority and records no approved/present names.
Unsafe name sets are refused before their environment values are read.
Invalid authorization produces a complete zero-work not-assessed receipt set
when public identities can be preserved safely. A known value in a workspace,
stage, proof identity or observation scope selector withholds the public artifacts
with a fixed error; identities are never rewritten into a different plan.
An unexpected execution/evidence error leaves the requested execution artifact
undelivered and fails the delivery gate, after audit export. Requested readiness
files are written after module collection and disposable cleanup, including when
their paths are inside the target. Requested destinations are checked for lexical,
symlink and existing hardlink aliases before writing. Delivery requires matching
bytes and digests produced by this run; old files cannot satisfy the gate.

The execution export has a producer-owned `.validation.json` companion. Pure
offline validation checks exact bytes, digests, plan/source bindings, complete
workspace/stage/application/observation populations and shared receipt guards.
It invokes no commands and grants no execution authority. It proves the supplied
artifact's structure and bindings, not authenticity without a caller's trusted
anchor. A raw plan containing known values is withheld while independent audit
exports continue.

These boundaries begin after module import. The separate
[launcher diagnostic follow-up](https://github.com/jharvieux/Harvey/issues/2224)
records a synthetic inherited-value disclosure from `tsx`/esbuild startup with
`NODE_DEBUG=child_process`, before a CLI redactor can run. Do not interpret the
readiness adapter's diagnostic refusal as a global launcher secrecy guarantee.
Source observation refuses active Node `child_process` and `stream` diagnostics
before reading Git or non-Git sources or allocating a disposable copy. The check
uses the active logger's cached startup state, so clearing `NODE_DEBUG` after
import does not make execution safe. Restart without those diagnostics to retry.
Git observations use fixed arguments, the source path as cwd, and private
environment overrides to neutralize target-owned filters.

## Production controls

The physical suites in `disposable-target.test.ts`,
`audit-readiness-authority.test.ts`, `bounded-process.test.ts`,
`readiness-process-containment.test.ts`, `audit-readiness-artifacts.test.ts`,
`audit-readiness-receipts.test.ts`, `audit-readiness-exec.test.ts` and
`audit-readiness-run.test.ts` and `audit-readiness-containment-flow.test.ts`
cover admission, environment/redaction, signals,
drainage, missing executables, truncation, dependencies and cleanup. The real
`run-audit.test.ts` continuity matrix compares readiness disabled, successful and
failed: module observations, coverage, findings and conservation remain equal;
only readiness evidence and its failure exit differ. Actual local-container
fixtures require `HARVEY_READINESS_DOCKER_SOCKET`,
`HARVEY_READINESS_DOCKER_IMAGE`, and a runtime-visible
`HARVEY_READINESS_SHARED_PARENT`; an unconfigured light test run explicitly skips
those physical cases rather than supplying simulated containment proof. Schema
fixture validation alone is not physical acceptance. #1898 owns delivery into
engagement/report/re-audit/corpus consumers; #2140 owns pre-cleanup built-asset
analysis. Those consumers do not derive readiness from a green coverage ledger.
