# `trufflehog-3.96.0-git-history.json` — provenance

CAPTURED, not hand-written. This is the real record TruffleHog emits when it recovers the planted
GitHub PAT from git **history** (the P-SECRET-GIT-HISTORY path, #129), consumed by
`scoreGitHistoryResults` in `src/scan/git-history-secret-gate.test.ts`. Before #1150 the test built
`TruffleHogGitResult[]` literals by hand, encoding only `DetectorName` + `SourceMetadata.Data.Git.file`.

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
trufflehog --version: trufflehog 3.96.0
trufflehog git --no-verification --results=unverified --json file://<throwaway-repo>
```

Captured 2026-07-26 against a throwaway git repo built exactly as `buildGitHistoryFixture`
(`src/scan/git-history-secret-gate.ts`) builds it: `README` init commit, then
`lib/leaked-token.js` added with the fake PAT `ghp_…7N` and removed in the next commit, then a
benign `lib/build-info.js` added and removed. HEAD carries neither file, so the hit can only have
come from walking history. `--no-verification`/`--results=unverified` are the gate's own flags
(the fake token can never verify); the divergence from production's `--only-verified` is the
decisional REASON block recorded in `git-history-secret-gate.ts`.

## What the run emitted, and what was elided

TruffleHog emitted exactly **one** record — the `lib/leaked-token.js` PAT, detector `Github`. The
benign `lib/build-info.js` add/remove drew **nothing**, which is the whole point of the negative
control (a real trufflehog run cannot produce a benign-file hit — the "false positive" branch in
the test asserts scoring rejects a hit that trufflehog would never actually emit, so that branch's
benign record stays a synthetic control by necessity).

Records were **dropped, never edited**, with two path substitutions (the #1102 osv precedent):

- `SourceMetadata.Data.Git.repository` — the capturing machine's `file:///…/T/ghist.XXXX` temp path
  → `file://<fixture-repo>`.
- `SourceMetadata.Data.Git.repository_local_path` — trufflehog's own clone temp path →
  `<trufflehog-clone>`.

`commit` and `timestamp` are the real values from the capture run; they are run-specific (a fresh
`buildGitHistoryFixture` mints a new commit) and are not asserted by the test — it reads only
`DetectorName` and `SourceMetadata.Data.Git.file`.
