# Corpus drift remeasurement history evidence

This directory is the retained evidence for issues #1742 and #1870. It binds two frozen
populations:

- 14 first-parent merges that changed counted baselines, digest
  `sha256:fbf1c851063542319308bf44bf51038992692e3a07aa2752ac476dbce702c997`;
- 35 merged pull requests from `2026-08-11T19:06:13Z` through
  `2026-08-25T19:06:13Z`, digest
  `sha256:aa5db4c0c4ece092f943b5614ca00bb75c8a1282aa98751998a062176318135a`.

`manifest.json` records the byte length and SHA-256 of every retained file. `summary.json` is the
small review surface. The gzip files retain the full evidence:

- `raw-forge-receipts.json.gz` — GitHub pull, commit, file, run, attempt, job, step, and selected
  failed-log receipts;
- `baseline-chronology.json.gz` — deterministic chronology and disposition of all 14
  baseline-mutating merges;
- `recent-relevance-replay.json.gz` — all 117 historical workflow heads, 129 attempts, complete
  classifier receipts, and conservative gross-savings accounting.

The scripts are executable documentation of collection, reduction, replay, and deterministic
packaging. They use native `gh`, `git`, Node/tsx, and Python. Reproduction requires authenticated
GitHub read access and the immutable Git objects named in the receipts.

The chronology classifies 9 rows deliberate, 2 gate-discovered, 1 mixed, and 2 unproven. The proven
denominator is 12: strict gate-prompted movement is 2/12 (16.7%), and gate-involved movement is 3/12
(25%). PR #1712 is the required negative control and is classified gate-discovered from its failed
run, repair commit, and succeeding run.

The recent replay declares 3/35 final PR heads disjoint. It retains superseded and failed attempts:
one actually-scored superseded head would have avoided 55.0 gross runner-minutes and 11.0
critical-path minutes. The receipt deliberately does not estimate hosted net savings; setup and
classifier overhead are separate measurements, and jobs that never reached corpus execution count
as zero avoided work.
