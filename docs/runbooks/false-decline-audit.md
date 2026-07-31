# Runbook: auditing this repo for false declines

Method record for the #1377 / #1378 false-decline audits, written up as #1548. **Read this before
starting another one** — it exists so the next sweep does not re-hunt a channel with no members, and
does not repeat a ~6x over-count.

A "false decline" is a recorded reason that turned out to be wrong: a blocker, a `not-run`
explanation, a refusal in impossibility's register that the repo had already overcome, or overcame
minutes later. The
doctrine is in `CLAUDE.md`; the machine-readable form and its gate are
`docs/design/recorded-reasons.md` and `pnpm validate-reasons`. This file is about **how to search**.

---

## 1. Where the declines actually live — populations, with the commands

Every figure below was re-measured **2026-07-31** for this write-up. Re-run them; do not quote them.
They grow daily, and a stored number is a claim about the past.

| population | size (2026-07-31) | how to measure it |
|---|---|---|
| closed issues | 782 | `issues(states: CLOSED)` GraphQL, paginated, count nodes |
| closed issues with ≥1 comment | 301 | same query, `comments(first:1){totalCount} > 0` |
| closed issues with NO comment | 481 | same query, `totalCount == 0` |
| merged PRs | 656 | `pullRequests(states: MERGED)` GraphQL, paginated |
| **PR reviews** | **0** | `reviews(first:1){totalCount}` summed over all merged PRs |
| **PR review comments** | **0** | `gh api "repos/jharvieux/Harvey/pulls/comments?per_page=100" --paginate --jq 'length'` |
| PR conversation comments | 413, across 367 PRs | `comments(first:30){nodes{body}}` over merged PRs |
| …of those, carrying claim vocabulary | 9, across 9 PRs | see §4 — **the predicate matters, publish it** |

The GraphQL shape that produced the first six rows:

```graphql
query($endCursor: String) {
  repository(owner: "jharvieux", name: "Harvey") {
    pullRequests(states: MERGED, first: 100, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { number reviews(first: 1) { totalCount } comments(first: 1) { totalCount } }
    }
  }
}
```

run as `gh api graphql --paginate -F query=@<file>.graphql`, aggregated with
`jq -s '[.[].data.repository.pullRequests.nodes[]] | length'` and friends.

## 2. PR reviews are a population of ZERO — do not hunt there again

**0 reviews and 0 review comments, repo-wide, across all 656 merged PRs.** Every PR in this repo is
authored and merged by the same account with no review step, so the review surface has never had a
single member. Re-measured 2026-07-31; it was also 0 on 2026-07-30 against 618 merged PRs.

#1378 opened by calling PR review comments *"plausibly the densest seam"*. That was an assertion
about a channel with no members — the shape `CLAUDE.md` names as **a limit with a population of zero
is a guess, not a limit**, arrived at from the other direction. Squash-commit messages are not a
separate surface either: they are the PR body concatenated.

**The surface that does exist is PR *conversation* comments** (§1), and it is small. Budget
accordingly: 413 comments is an afternoon of reading, not a sampling problem.

## 3. Pair by SIBLING ISSUE, not by closing PR

The 2026-07-30 seeded sample (seed 1377, 35 no-comment closed issues whose closing PR body carries
decline vocabulary) split like this:

| | count |
|---|---|
| pairs examined | 35 |
| PR declined a criterion **stated in the paired issue's acceptance** | 5 (14%) |
| vocabulary incidental — aimed at a *sibling* issue in the same multi-issue PR, a self-filed follow-up, or a branch the acceptance itself sanctioned | 30 (86%) |

So a naive "closing PR body contains decline vocabulary" filter over-counts genuine declines by
roughly **6x**. The structural cause is this repo's batching: 2–6 issues land per PR, and the decline
paragraph usually belongs to a *different* issue in the batch than the one being audited. Named
instances where the decline was well-measured but aimed elsewhere: PR #270 declining against #256
while the paired #258 was fully met, and the same shape in #858/#851, #1235/#1222, #1382/#1301,
#1397/#1342.

**Therefore: pair each decline paragraph to the sibling issue it actually names, then check THAT
issue's acceptance.** That is where the untested decline mass sits, and the 2026-07-30 audits left it
untouched.

## 4. Publish your predicate, not just your seed

The §1 vocabulary row reads **9 of 413**. #1548 recorded **13 of 409** on 2026-07-30. The
denominators differ by three days of growth; the numerators differ because **the two runs used
different predicates, and #1548 never published its own.**

The 9 here is reproducible because its predicate is named: the repo's own claim vocabulary,
`IMPOSSIBILITY_VOCABULARY` and `UNVERIFIED_VOCABULARY` in `src/recorded-reasons.ts` (lines 187-191),
applied case-insensitively and word-bounded to each comment body flattened to one line. The nine
carrying PRs are #359, #552, #1406, #1450, #1465, #1468, #1472, #1486, #1495 — the drawn ids, not
just the draw.

This is the same failure `CLAUDE.md` records for #1012's re-measure (48/384 under the code's own
`REGISTRY_RULE_SHAPE`, not the 54/390 first recorded with a bare dot predicate): **a figure tagged
MEASURED, computed with a different predicate than the code.** A sample without its draw is not
reproducible; a count without its predicate is not comparable. Publish both.

## 5. The two highest-yield checks, confirmed repeatedly

Both are one line, and both were what actually found the confirmed cases.

**(a) Did the capability already exist when the decline was written?**

```bash
git log --oneline --until=<PR merge date> -- <path of the capability the decline says is missing>
```

Found #431's *"no proposit source is present"* (`cloneAtPin` had shipped 2 days earlier **in the same
file**), and previously #370 and #873.

**(b) How long did the blocker survive after it was recorded?**

```bash
git log --since=<PR merge date> -- <path>
```

Confirmed lifetimes: 140 seconds (#409), 14 min (#1151), 21 min (#800), 69 min (#1481), 96 min
(#572), 20 h (#431). **A blocker with a lifetime measured in minutes was a budget claim wearing
impossibility's clothes** — which is exactly what `CLAUDE.md`'s vocabulary rule exists to prevent.

**A caution on (a) and (b): a `grep` returning nothing is not proof of absence.** A tracked file
holding a literal NUL byte is classified as binary and plain `grep` silently returns nothing for the
whole file. `src/greppable-sources.test.ts` fails loud on a new one; when a zero is load-bearing,
re-confirm with `grep -a` or `git grep`.

## 6. Unaudited remainder, carried forward

Restated rather than dropped. These are the parts of the 2026-07-30 audits nobody has read, scaled to
the populations as they stood then:

- ~237 no-comment closed issues whose closing PR carries vocabulary, outside the 35-issue seeded sample.
- ~229 merged PR bodies with vocabulary, outside the 62 high-signal + 40 seeded reads.
- **All** vocabulary-bearing PR conversation comments — 9 under the §4 predicate, 13 under #1548's.
  Population is small; there is no reason left to skip it.
- **All** sibling-issue declines in multi-issue PRs — §3 argues this is the densest remaining seam,
  and it has a population of zero reads.

Whoever works the next round: re-measure §1 first, work §3's seam, and re-state whatever is still
outstanding here rather than letting it go quiet. An absent row never appears in a tally.

---

Refs #1548, #1377, #1378, #1345. Convention for recording what you find:
`docs/design/recorded-reasons.md`.
