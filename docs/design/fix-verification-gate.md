# Fix-verification gate (#883) — findings → tickets → re-audit, closed loop

The seam this closes: findings become tickets (`src/trackers/findings-to-tickets.ts`), and the
re-audit diff (`run-audit --baseline`, #457) can compare two full audits — but nothing verified an
individual fix or ever closed a filed ticket. The gate joins the two using pieces that already
existed, adding no new detection surface.

## Shape

```
engagement findings.json ──▶ runGate(findings, clientCheckout) ──▶ fix-verify.json (GateReport)
                                   │  re-runs ONLY the detectors that              │
                                   │  produced the delivered findings              ▼
                                   │  (src/fix/detector-rerun.ts)        planWriteback (pure)
                                   ▼                                               │ --confirm
                       resolved / persistent / regressed /               writeBackVerification
                       unverifiable per finding                          (comment + close/reopen
                                                                          via TicketWriteback)
```

- **Scope** — the baseline is the engagement's delivered `findings.json`. The gate never speaks
  about code we did not already report on: no new scan, no new findings, only per-finding detector
  re-runs scoped to each finding's own file. General detection quality is never on trial here.
- **Identity** — findings match across runs by the #457 stable identity (taxonomy + normalized
  location, `src/audit-diff.ts`), and match their filed ticket by the marker
  `findings-to-tickets` stamped (`findingMarker`, same `--engagement` namespace).
- **Statuses** — `resolved` (detector no longer fires), `persistent` (still fires), `regressed`
  (a prior gate run verified it resolved and it fires again), `unverifiable` (the detector could
  not be re-run — no resolver for its taxonomy or the engine is unavailable).

## Honesty rules (load-bearing)

1. **An unrun detector is not a clean detector.** `unverifiable` is never `resolved`, never closes
   a ticket, and is always printed with its reason. This inherits `computeGreen`'s posture
   (`src/fix/verify.ts`) and the coverage doctrine: silent omission is worse than a wrong status.
2. **A ticket is closed only from a verified `resolved` row**, and only on a transition — a
   finding already verified resolved by the prior run is not re-closed, so repeated runs don't
   churn tickets.
3. **Write-back never clobbers.** The verification note is an appended comment (GitHub/GitLab
   comment, Jira ADF comment, Linear comment, Azure `System.History`), never a body/description
   update. State moves through each tracker's own workflow (`TicketWriteback.transitionState`);
   an adapter that cannot resolve a target state (Jira transitions, Linear workflow states)
   throws, and the failure is recorded per finding in the write-back result — the batch continues,
   nothing is silently skipped.
4. **Dry-run is structural.** `planWriteback` is pure (no tracker), mirroring `planTickets`; the
   CLI's default run needs no token and provably cannot write. Writes require `--confirm`,
   `--tracker`, and the tracker's env token.

## Running it

```
pnpm exec tsx src/cli/fix-verify.ts <findings.json> --target <client-checkout> \
  [--prior <prior fix-verify.json>] [--out fix-verify.json] [--engagement <label>] \
  [--tracker github|gitlab|jira|linear|azure] [--confirm]
```

Per-PR use is the same command on the PR's checkout with `--prior` pointing at the last report:
status deltas are exactly "this change resolves F-07" / "this reintroduces F-12", and exit code 1
on any regression (or write-back failure) is the CI red signal. The accumulated report chain is
the self-serve re-audit. Read-only against the target; the only outbound write is the opted-in
tracker write-back.

## Known limits

- Detector re-run resolvers currently cover the AST engines (M5/M6/M7/M9 taxonomies,
  `src/fix/detector-rerun.ts`). Findings from semgrep rules, live tiers (M1 live, M2, M7
  advisors, M10 live), M3/M4/M8 external tools, and LLM passes report `unverifiable` with that
  reason — disclosed, their tickets stay open, and a full re-audit of that tier remains the
  verification path. Extending resolvers (semgrep first, when the binary is present) widens the
  gate without changing its contract.
- Packaging decision made (#1013): one re-audit/rescan is included in the base engagement, if
  requested within 30 days of the original audit; additional rescans are a paid add-on at 50%
  of the original audit price, also within 30 days of the original audit. The gate itself still
  has no tier flag — encoding the add-on gate into `fix-verify.ts` (mirroring the #824
  paid-tier pattern) is unbuilt.
