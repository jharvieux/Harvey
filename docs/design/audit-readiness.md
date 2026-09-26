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
and the operator's `source`, `reason` and `falsifier`. Optional `toolchainPath`
identifies trusted directories outside the target; `timeoutMs` sets the stage
deadline, up to one hour. Environment values come from the operator process,
through the approved name list. Values are excluded from the authorization file.

The install stage needs both `--allow-target-install` and a `target-install`
effect review, including its declared lifecycle scripts. Other executable stages
need their own `disposable-local` review. `network-or-service` and `unknown`
effects receive a not-assessed receipt. Install permission also retains its
existing M8 meaning; review that module's provisioning scope when using the flag.
The readiness adapter's copy and child commands stay separate from the source
audit target.

## Execution and evidence

The disposable copy excludes dependency, VCS and build artifacts. Source entries
and Git HEAD/status form before/after sentinels. Admission checks the real command
cwd and toolchain paths against the copy and original source. Each child receives
an isolated home/cache/temp environment plus approved values; runtime-control
names such as `NODE_OPTIONS` and `NODE_V8_COVERAGE` are refused as operator inputs.

The runner uses tokenized `spawn` with `shell: false`, drains both streams through
close, retains byte counts and SHA-256 digests, and bounds redacted head/tail
excerpts. Its default deadline is 120 seconds, followed by 250 ms termination
grace and one second close grace. Timeout, process errors, incomplete drainage,
output truncation and unconfirmed termination produce failed stage evidence.
Process-group termination is supported on POSIX; other platforms receive an
explicit unsupported result. The disposable directory boundary is not an OS
sandbox for target code: effect review and authority precede target execution.

The scheduler serializes undeclared shared output ownership. A failed prerequisite
withholds its descendants while independent stages continue. Install-covered
codegen refers to the actual successful install receipt. Final receipt closure
checks the exact plan stage population, ordering, prerequisite statuses, process
lifecycle and cleanup. Cleanup follows settled child work and reports removal and
source preservation separately.

Invalid authorization produces a complete zero-work not-assessed receipt set.
An unexpected execution/evidence error leaves the requested execution artifact
undelivered and fails the delivery gate, after audit export. Requested readiness
files are written after module collection and disposable cleanup, including when
their paths are inside the target.

## Production controls

The physical suites in `disposable-target.test.ts`,
`audit-readiness-authority.test.ts`, `bounded-process.test.ts`,
`audit-readiness-receipts.test.ts`, `audit-readiness-exec.test.ts` and
`audit-readiness-run.test.ts` cover admission, environment/redaction, signals,
drainage, missing executables, truncation, dependencies and cleanup. The real
`run-audit.test.ts` continuity matrix compares readiness disabled, successful and
failed: module observations, coverage, findings and conservation remain equal;
only readiness evidence and its failure exit differ. #1898 owns delivery into
engagement/report/re-audit/corpus consumers; #2140 owns pre-cleanup built-asset
analysis. Those consumers do not derive readiness from a green coverage ledger.
