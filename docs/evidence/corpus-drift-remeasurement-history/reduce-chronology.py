#!/usr/bin/env python3
"""Reduce the retained D16 forge receipt to deterministic chronology evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


CLASSIFICATIONS: dict[int, dict[str, Any]] = {
    1593: {
        "category": "deliberate",
        "reason": "The initial baseline commit predates PR creation, its patch records the measured commands and date, and the first hosted corpus run on that head succeeded; no hosted failure preceded the selected population.",
        "anchors": {"commit": "12bc5d066a07bfdef09cdd3765baf2d6534afdf6", "run": 30595180560},
    },
    1629: {
        "category": "deliberate",
        "reason": "The only baseline-mutating commit was already the initial PR head and the first hosted corpus run succeeded; no amended baseline followed a failure.",
        "anchors": {"commit": "d65ac857", "run": 30606476264},
    },
    1654: {
        "category": "mixed",
        "reason": "Two baseline changes predated the first run, but that run then exposed cravab M5-slop +9 (467 to 476) and commit 94f9d9d amended exactly that row before the succeeding run.",
        "anchors": {"failureRun": 30610553850, "repairCommit": "94f9d9d5", "successRun": 30612814398},
    },
    1651: {
        "category": "unproven",
        "reason": "An initial note-only baseline edit preceded a successful run, but a later main merge imported additional counted-line changes. The retained chronology cannot prove selection and measurement of the complete merge delta by this PR.",
        "anchors": {"initialCommit": "fcb839de", "mergeCommit": "1c231cb6", "runs": [30609829305, 30615729394]},
    },
    1667: {
        "category": "deliberate",
        "reason": "Both count-preserving baseline-note commits predate PR creation and the first hosted run succeeded with no amendment after a failure.",
        "anchors": {"commits": ["b0cc4bb5", "9a5641d1"], "run": 30617719447},
    },
    1683: {
        "category": "deliberate",
        "reason": "The count-changing baseline commit predates the first hosted run. That run failed a separate free-tier semantic assertion, and the later corpus edits did not rebaseline the counted value before success.",
        "anchors": {"baselineCommit": "1f9f7aff", "nonCountFailureRun": 30634899914, "successRun": 30638506324},
    },
    1712: {
        "category": "gate-discovered",
        "reason": "The initial head ran first and failed on rallly M9 -3 (expected 5, got 2); commit 8665c1d changed that baseline afterward and the final run passed.",
        "anchors": {"failureRun": 30654589073, "repairCommit": "8665c1d0", "successRun": 30657750707},
    },
    1744: {
        "category": "deliberate",
        "reason": "The sole baseline-mutating commit predates PR creation. The first run was superseded/cancelled, the unchanged baseline was retained, and the next complete run succeeded without a drift-prompted amendment.",
        "anchors": {"commit": "f4bcec85", "cancelledRun": 30667831621, "successRun": 30667899219},
    },
    1782: {
        "category": "deliberate",
        "reason": "The baseline mutation was committed before PR creation and the first hosted run succeeded; there was no failure-driven baseline commit.",
        "anchors": {"commit": "2143f914", "run": 30679129346},
    },
    1796: {
        "category": "deliberate",
        "reason": "The count-affecting baseline commit preceded the first successful run and the later baseline edit was count-preserving and preceded another successful run; no hosted drift prompted either edit.",
        "anchors": {"commits": ["3549660c", "f5c18689"], "runs": [30681711598, 30682703833]},
    },
    1811: {
        "category": "deliberate",
        "reason": "The 103-to-102 baseline mutation was present before PR creation and the first hosted corpus run succeeded without an intervening failure or amendment.",
        "anchors": {"commit": "5ec428d2", "run": 30689126497},
    },
    1834: {
        "category": "unproven",
        "reason": "The initial baseline edit preceded a run that never reached measurement because corpus fetches failed; a later main merge also changed baseline lines. The retained evidence cannot prove pre-failure measurement of the complete merge delta.",
        "anchors": {"initialCommit": "7ad6b239", "setupFailureRun": 30952282200, "mergeCommit": "3d15e13c", "successRun": 30956721223},
    },
    1948: {
        "category": "gate-discovered",
        "reason": "The first run that reached corpus measurement reported the full M5/M8 drift population; the sole baseline commit followed that failure and the next hosted run succeeded.",
        "anchors": {"failureRun": 32345629796, "repairCommit": "cc0d5e25", "successRun": 32348449535},
    },
    1954: {
        "category": "deliberate",
        "reason": "The retained sweep event records the measured Ghostfolio 23/36-to-24/35 selection before the first hosted run containing the baseline commits. Subsequent corpus failures were unrelated transport/setup failures, not baseline drift.",
        "anchors": {
            "commits": ["d563465c", "fa258554"],
            "measurementEvent": "full-resume-event-922",
            "measurementEventDigest": "sha256:f31b23f91911cd39255ca5c0973eb69d61e5d959c90cc46507582cfd901f681d",
            "firstContainingRun": 32549070919,
            "successRun": 32600362946,
        },
    },
}


def canonical(value: Any, *, sorted_keys: bool = True, newline: bool = False) -> bytes:
    body = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=sorted_keys,
    )
    return (body + ("\n" if newline else "")).encode()


def digest(value: Any, *, sorted_keys: bool = True, newline: bool = False) -> str:
    return "sha256:" + hashlib.sha256(
        canonical(value, sorted_keys=sorted_keys, newline=newline)
    ).hexdigest()


def compact_pull(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": raw["number"],
        "createdAt": raw["created_at"],
        "mergedAt": raw["merged_at"],
        "merge": raw["merge_commit_sha"],
        "base": raw["base"]["sha"],
        "head": raw["head"]["sha"],
    }


def compact_run(wrapper: dict[str, Any]) -> dict[str, Any]:
    run = wrapper["raw_run"]
    jobs = []
    for attempt in wrapper.get("attempt_jobs", []):
        for job in attempt.get("jobs", []):
            steps = [
                {
                    "name": step["name"],
                    "conclusion": step.get("conclusion"),
                    "startedAt": step.get("started_at"),
                    "completedAt": step.get("completed_at"),
                }
                for step in job.get("steps", [])
                if step.get("conclusion") not in ("skipped", None)
            ]
            jobs.append(
                {
                    "attempt": attempt.get("attempt"),
                    "id": job.get("id"),
                    "name": job.get("name"),
                    "conclusion": job.get("conclusion"),
                    "startedAt": job.get("started_at"),
                    "completedAt": job.get("completed_at"),
                    "steps": steps,
                }
            )
    return {
        "id": run.get("id"),
        "head": run.get("head_sha"),
        "event": run.get("event"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "createdAt": run.get("created_at"),
        "updatedAt": run.get("updated_at"),
        "attempt": run.get("run_attempt"),
        "jobs": jobs,
        "failedLogExcerpts": wrapper.get("failed_log_excerpt", []),
    }


def compact_baseline_row(row: dict[str, Any]) -> dict[str, Any]:
    pull = row["raw_pull"]
    commits = []
    details_by_sha = row.get("raw_commit_details", {})
    for raw in row.get("raw_commits", []):
        sha = raw["sha"]
        commit = raw["commit"]
        detail = details_by_sha.get(sha, {})
        files = [
            {
                "filename": file.get("filename"),
                "status": file.get("status"),
                "additions": file.get("additions"),
                "deletions": file.get("deletions"),
                "patch": file.get("patch"),
            }
            for file in detail.get("files", [])
            if file.get("filename") == "src/scan/external-corpus.ts"
        ]
        commits.append(
            {
                "sha": sha,
                "authoredAt": commit["author"]["date"],
                "committedAt": commit["committer"]["date"],
                "message": commit["message"],
                "externalCorpusDiff": files,
            }
        )
    return {
        "number": row["number"],
        "classification": CLASSIFICATIONS[row["number"]],
        "pull": compact_pull(pull),
        "commits": commits,
        "runs": [compact_run(run) for run in row.get("corpus_runs", [])],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    envelope = json.loads(args.input.read_text())
    payload = envelope["payload"]
    baseline_population = payload["baseline_population"]
    recent_population = payload["recent_pr_population"]

    recent_manifest = [
        {
            "number": row["raw_pull"]["number"],
            "mergedAt": row["raw_pull"]["merged_at"],
            "merge": row["raw_pull"]["merge_commit_sha"],
            "base": row["raw_pull"]["base"]["sha"],
            "head": row["raw_pull"]["head"]["sha"],
        }
        for row in recent_population["rows"]
    ]
    baseline_merges = [
        row["raw_pull"]["merge_commit_sha"] for row in baseline_population["rows"]
    ]
    candidate_digests = {
        "recent": {
            "canonicalSorted": digest(recent_manifest),
            "canonicalInsertion": digest(recent_manifest, sorted_keys=False),
            "canonicalSortedNewline": digest(recent_manifest, newline=True),
            "canonicalInsertionNewline": digest(
                recent_manifest, sorted_keys=False, newline=True
            ),
            "expected": recent_population["manifest_digest_expected"],
        },
        "baseline": {
            "canonicalList": digest(baseline_merges),
            "canonicalListNewline": digest(baseline_merges, newline=True),
            "joined": "sha256:"
            + hashlib.sha256("\n".join(baseline_merges).encode()).hexdigest(),
            "joinedNewline": "sha256:"
            + hashlib.sha256(("\n".join(baseline_merges) + "\n").encode()).hexdigest(),
            "expected": baseline_population["ordered_merge_digest_expected"],
        },
    }

    categories = {category: 0 for category in ("deliberate", "gate-discovered", "mixed", "unproven")}
    for classification in CLASSIFICATIONS.values():
        categories[classification["category"]] += 1
    proven_denominator = (
        categories["deliberate"]
        + categories["gate-discovered"]
        + categories["mixed"]
    )
    metrics = {
        "counts": categories,
        "provenDenominator": proven_denominator,
        "strictGatePrompted": {
            "numerator": categories["gate-discovered"],
            "denominator": proven_denominator,
            "rate": categories["gate-discovered"] / proven_denominator,
        },
        "gateInvolved": {
            "numerator": categories["gate-discovered"] + categories["mixed"],
            "denominator": proven_denominator,
            "rate": (categories["gate-discovered"] + categories["mixed"])
            / proven_denominator,
        },
        "negativeControl": {
            "pull": 1712,
            "required": "gate-discovered",
            "observed": CLASSIFICATIONS[1712]["category"],
            "passes": CLASSIFICATIONS[1712]["category"] == "gate-discovered",
        },
    }

    reduced = {
        "schema": 1,
        "source": {
            "path": str(args.input),
            "payloadSha256": envelope["payload_sha256"],
        },
        "candidateDigests": candidate_digests,
        "commands": payload["commands"],
        "metrics": metrics,
        "baselinePopulation": [
            compact_baseline_row(row) for row in baseline_population["rows"]
        ],
        "recentPopulation": recent_manifest,
    }
    reduced["digest"] = digest(reduced)

    if args.out:
        args.out.write_bytes(canonical(reduced, newline=True))
    else:
        print(json.dumps(candidate_digests, indent=2))


if __name__ == "__main__":
    main()
