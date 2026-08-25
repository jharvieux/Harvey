#!/usr/bin/env python3
"""Replay the shipping corpus relevance classifier over the frozen 35-PR frame."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any


SCORING_STEPS = {
    "Score the corpus against its baselines": "hosted-producer",
    "Execute the independent exact-head replay": "independent-replay",
}


def run(args: list[str], *, cwd: Path | None = None, capture: bool = True) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return completed.stdout if capture else ""


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def seconds(start: str | None, end: str | None) -> float:
    if not start or not end:
        return 0.0
    return max(0.0, (instant(end) - instant(start)).total_seconds())


def scoring_jobs(attempt: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for job in attempt.get("jobs", []):
        executed = []
        for step in job.get("steps", []):
            kind = SCORING_STEPS.get(step.get("name"))
            if kind and step.get("conclusion") not in (None, "skipped"):
                executed.append({
                    "kind": kind,
                    "name": step["name"],
                    "conclusion": step.get("conclusion"),
                    "seconds": seconds(step.get("started_at"), step.get("completed_at")),
                })
        if executed:
            rows.append({
                "jobId": job.get("id"),
                "name": job.get("name"),
                "conclusion": job.get("conclusion"),
                "startedAt": job.get("started_at"),
                "completedAt": job.get("completed_at"),
                "runnerSeconds": seconds(job.get("started_at"), job.get("completed_at")),
                "executedScoringSteps": executed,
            })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--cli-root", type=Path, required=True)
    parser.add_argument("--ownership", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    envelope = json.loads(args.raw.read_text())
    recent = envelope["payload"]["recent_pr_population"]
    rows = recent["rows"]
    if len(rows) != 35 or recent["has_next_page"] is not False:
        raise RuntimeError("recent PR population is not the frozen complete 35-row frame")

    cli = args.cli_root / "src/cli/corpus-drift-relevance.ts"
    worktree_parent = Path(tempfile.mkdtemp(prefix="harvey-d16-replay-", dir="/private/tmp"))
    checkout = worktree_parent / "checkout"
    receipts_dir = worktree_parent / "receipts"
    receipts_dir.mkdir()
    classified: dict[tuple[str, str], dict[str, Any]] = {}
    classifications: list[dict[str, Any]] = []
    final_rows: list[dict[str, Any]] = []
    attempt_rows: list[dict[str, Any]] = []
    worktree_added = False
    started = time.monotonic()
    try:
        first = rows[0]["raw_pull"]["head"]["sha"]
        run(["git", "-C", str(args.repo), "worktree", "add", "--detach", str(checkout), first])
        worktree_added = True

        def classify(pr: int, head: str, requested_base: str) -> dict[str, Any]:
            resolved_base = run(["git", "-C", str(args.repo), "merge-base", requested_base, head]).strip()
            key = (head, resolved_base)
            if key in classified:
                return classified[key]
            run(["git", "-C", str(checkout), "checkout", "--detach", "--force", head])
            status = run(["git", "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=all"])
            if status:
                raise RuntimeError(f"historical replay worktree dirty at {head}: {status.splitlines()[0]}")
            receipt_path = receipts_dir / f"pr{pr}-{head}.json"
            tick = time.monotonic()
            completed = subprocess.run(
                [
                    "node", "--import", "tsx", str(cli), "classify",
                    "--root", str(checkout),
                    "--base", resolved_base,
                    "--head", head,
                    "--ownership", str(args.ownership),
                    "--out", str(receipt_path),
                ],
                cwd=args.cli_root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            elapsed = time.monotonic() - tick
            if completed.returncode != 0:
                raise RuntimeError(f"classifier exited {completed.returncode} for PR {pr} {head}: {completed.stderr}")
            receipt = json.loads(receipt_path.read_text())
            record = {
                "pull": pr,
                "head": head,
                "requestedBase": requested_base,
                "base": resolved_base,
                "elapsedSeconds": elapsed,
                "stderr": completed.stderr.strip(),
                "receipt": receipt,
            }
            classified[key] = record
            classifications.append(record)
            return record

        for pr_row in rows:
            pull = pr_row["raw_pull"]
            number = pull["number"]
            requested_base = pull["base"]["sha"]
            run_records = []
            for wrapped in pr_row.get("corpus_runs", []):
                raw_run = wrapped["raw_run"]
                record = classify(number, raw_run["head_sha"], requested_base)
                attempts = []
                for attempt in wrapped.get("attempt_jobs", []):
                    jobs = scoring_jobs(attempt)
                    gross = sum(job["runnerSeconds"] for job in jobs)
                    critical = max((job["runnerSeconds"] for job in jobs), default=0.0)
                    avoided = record["receipt"]["decision"] == "declared-no-op" and bool(jobs)
                    attempt_record = {
                        "pull": number,
                        "runId": raw_run["id"],
                        "runHead": raw_run["head_sha"],
                        "attempt": attempt.get("attempt"),
                        "runConclusion": raw_run.get("conclusion"),
                        "classifierDecision": record["receipt"]["decision"],
                        "scoringJobs": jobs,
                        "actuallyScored": bool(jobs),
                        "grossRunnerSecondsAvoided": gross if avoided else 0.0,
                        "criticalPathSecondsAvoided": critical if avoided else 0.0,
                    }
                    attempts.append(attempt_record)
                    attempt_rows.append(attempt_record)
                run_records.append({
                    "id": raw_run["id"],
                    "head": raw_run["head_sha"],
                    "attemptCount": raw_run.get("run_attempt", 1),
                    "conclusion": raw_run.get("conclusion"),
                    "classifierDecision": record["receipt"]["decision"],
                    "attempts": attempts,
                })
            final = classify(number, pull["head"]["sha"], requested_base)
            final_row = {
                "number": number,
                "mergedAt": pull["merged_at"],
                "base": requested_base,
                "head": pull["head"]["sha"],
                "merge": pull["merge_commit_sha"],
                "decision": final["receipt"]["decision"],
                "closureDigest": final["receipt"]["closureDigest"],
                "reasons": final["receipt"]["reasons"],
                "targetSelections": final["receipt"]["targetSelections"],
                "runs": run_records,
            }
            final_rows.append(final_row)

        noop_final = sum(row["decision"] == "declared-no-op" for row in final_rows)
        full_final = len(final_rows) - noop_final
        gross = sum(row["grossRunnerSecondsAvoided"] for row in attempt_rows)
        critical = sum(row["criticalPathSecondsAvoided"] for row in attempt_rows)
        assessed_attempts = sum(row["actuallyScored"] for row in attempt_rows)
        avoided_attempts = sum(row["grossRunnerSecondsAvoided"] > 0 for row in attempt_rows)
        elapsed_values = [row["elapsedSeconds"] for row in classifications]
        payload = {
            "schema": 1,
            "kind": "corpus-drift-relevance-recent-replay",
            "source": {
                "rawPayloadSha256": envelope["payload_sha256"],
                "populationQuery": recent["query"],
                "interval": recent["exact_utc_interval"],
                "populationCount": len(rows),
                "populationManifestDigest": recent["manifest_digest_expected"],
            },
            "method": {
                "classifier": str(cli.relative_to(args.cli_root)),
                "ownershipSha256": sha256(args.ownership.read_bytes()),
                "attemptAware": True,
                "allUniqueRunHeadsRetained": True,
                "baseRule": "git merge-base between each run/final head and the pull request's retained base SHA",
                "savingsRule": "count full runner duration only for jobs whose corpus producer or independent replay step actually executed and whose current classifier receipt is declared-no-op; sum the longest such job per attempt for critical path",
                "excludedFromSavings": "prepare/classifier overhead, skipped jobs, jobs that never reached corpus execution, and every full-scan decision",
            },
            "metrics": {
                "finalPullRequests": len(final_rows),
                "finalDeclaredNoOp": noop_final,
                "finalFullScan": full_final,
                "historicalWorkflowRuns": sum(len(row["corpus_runs"]) for row in rows),
                "uniqueClassifications": len(classifications),
                "attemptsRetained": len(attempt_rows),
                "attemptsThatActuallyScored": assessed_attempts,
                "scoredAttemptsAvoided": avoided_attempts,
                "grossRunnerMinutesAvoided": gross / 60,
                "criticalPathMinutesAvoided": critical / 60,
                "localClassifierSecondsTotal": sum(elapsed_values),
                "localClassifierSecondsMedian": sorted(elapsed_values)[len(elapsed_values) // 2],
                "localReplayWallSeconds": time.monotonic() - started,
                "hostedNetSavingsEstimated": False,
            },
            "finalPullRequests": final_rows,
            "attempts": attempt_rows,
            "classifications": classifications,
        }
        body = canonical(payload)
        wrapper = {"payloadSha256": sha256(body), "payload": payload}
        args.out.write_bytes(canonical(wrapper))
        print(json.dumps({"out": str(args.out), "bytes": args.out.stat().st_size, "payloadSha256": wrapper["payloadSha256"], "metrics": payload["metrics"]}, indent=2))
    finally:
        if worktree_added:
            subprocess.run(["git", "-C", str(args.repo), "worktree", "remove", "--force", str(checkout)], check=False)
        shutil.rmtree(worktree_parent)


if __name__ == "__main__":
    main()
