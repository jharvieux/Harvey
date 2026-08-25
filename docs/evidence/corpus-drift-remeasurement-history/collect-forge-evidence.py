#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO = "jharvieux/Harvey"
BASELINE_PRS = [1593, 1629, 1654, 1651, 1667, 1683, 1712, 1744, 1782, 1796, 1811, 1834, 1948, 1954]
RECENT_PRS = [
    1862, 1861, 1860, 1865, 1866, 1877, 1882, 1884, 1885, 1921, 1922,
    1932, 1938, 1939, 1942, 1943, 1949, 1944, 1948, 1945, 1950, 1951,
    1953, 1952, 1955, 1956, 1958, 1959, 1954, 1960, 1961, 1962, 1966,
    1963, 1937,
]
RETRIEVED_AT = "2026-08-25T20:20:00Z"
FRAME_START = "2026-08-11T19:06:13Z"
FRAME_END = "2026-08-25T19:06:13Z"


def command(args: list[str]) -> str:
    proc = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.stdout


def api(endpoint: str) -> object:
    return json.loads(command(["gh", "api", endpoint]))


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def corpus_runs(branch: str, created_at: str, merged_at: str) -> list[dict]:
    body = api(
        f"repos/{REPO}/actions/workflows/corpus-drift.yml/runs"
        f"?branch={branch}&event=pull_request&per_page=100"
    )
    start = parse_time(created_at) - timedelta(minutes=2)
    end = parse_time(merged_at) + timedelta(minutes=10)
    rows = [
        row for row in body.get("workflow_runs", [])
        if start <= parse_time(row["created_at"]) <= end
    ]
    rows.sort(key=lambda row: (row["created_at"], row["id"], row.get("run_attempt", 1)))
    return rows


def run_jobs(run: dict) -> list[dict]:
    attempts = []
    for attempt in range(1, int(run.get("run_attempt", 1)) + 1):
        body = api(f"repos/{REPO}/actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100")
        jobs = body.get("jobs", [])
        jobs.sort(key=lambda row: (row.get("started_at") or "", row.get("id", 0)))
        attempts.append({"attempt": attempt, "jobs": jobs})
    return attempts


LOG_PATTERN = re.compile(
    r"(✗ DRIFT|DRIFT [+-]\d+|SEMANTIC DRIFT|Process completed with exit code|"
    r"Error: Command failed|transport payload .* exceeds|not assessed|NEVER REACHED)",
    re.IGNORECASE,
)


def failed_log_excerpt(run: dict) -> list[str]:
    if run.get("conclusion") == "success":
        return []
    args = ["gh", "run", "view", str(run["id"]), "--repo", REPO, "--log-failed"]
    if int(run.get("run_attempt", 1)) > 1:
        args.extend(["--attempt", str(run["run_attempt"])])
    try:
        text = command(args)
    except subprocess.CalledProcessError as exc:
        text = exc.stdout or ""
    selected = []
    for raw in text.splitlines():
        fields = raw.split("\t", 2)
        content = fields[2] if len(fields) == 3 else raw
        if LOG_PATTERN.search(content):
            selected.append(content)
    return selected


def collect_pr(number: int, with_commits: bool, with_failed_logs: bool) -> dict:
    pull = api(f"repos/{REPO}/pulls/{number}")
    runs = corpus_runs(pull["head"]["ref"], pull["created_at"], pull["merged_at"])
    run_rows = []
    for run in runs:
        row = {
            "raw_run": run,
            "attempt_jobs": run_jobs(run),
        }
        if with_failed_logs:
            row["failed_log_excerpt"] = failed_log_excerpt(run)
        run_rows.append(row)
    result = {
        "number": number,
        "raw_pull": pull,
        "corpus_runs": run_rows,
    }
    if with_commits:
        commits = api(f"repos/{REPO}/pulls/{number}/commits?per_page=100")
        result["raw_commits"] = commits
        result["raw_files"] = api(f"repos/{REPO}/pulls/{number}/files?per_page=100")
        head_shas = {row["sha"] for row in commits}
        head_shas.update(row["raw_run"]["head_sha"] for row in run_rows)
        result["raw_commit_details"] = {
            sha: api(f"repos/{REPO}/commits/{sha}") for sha in sorted(head_shas)
        }
    return result


def main() -> None:
    output = Path(sys.argv[1])
    all_numbers = sorted(set(BASELINE_PRS + RECENT_PRS))
    baseline = set(BASELINE_PRS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(collect_pr, number, number in baseline, number in baseline): number
            for number in all_numbers
        }
        rows = {}
        for future in concurrent.futures.as_completed(futures):
            number = futures[future]
            rows[number] = future.result()

    recent_rows = [rows[number] for number in RECENT_PRS]
    for row in recent_rows:
        merged = row["raw_pull"]["merged_at"]
        if not (parse_time(FRAME_START) <= parse_time(merged) <= parse_time(FRAME_END)):
            raise RuntimeError(f"PR {row['number']} escaped exact recent frame: {merged}")

    payload = {
        "schema": 1,
        "repository": REPO,
        "retrieved_at": RETRIEVED_AT,
        "baseline_population": {
            "numbers": BASELINE_PRS,
            "ordered_merge_digest_expected": "sha256:fbf1c851063542319308bf44bf51038992692e3a07aa2752ac476dbce702c997",
            "rows": [rows[number] for number in BASELINE_PRS],
        },
        "recent_pr_population": {
            "query": "repo:jharvieux/Harvey is:pr is:merged base:main merged:2026-08-11..2026-08-25",
            "exact_utc_interval": {"start_inclusive": FRAME_START, "end_inclusive": FRAME_END},
            "issue_count": 35,
            "has_next_page": False,
            "numbers": RECENT_PRS,
            "manifest_digest_expected": "sha256:aa5db4c0c4ece092f943b5614ca00bb75c8a1282aa98751998a062176318135a",
            "rows": recent_rows,
        },
        "commands": {
            "pull": f"gh api repos/{REPO}/pulls/<number>",
            "commits": f"gh api repos/{REPO}/pulls/<number>/commits?per_page=100",
            "files": f"gh api repos/{REPO}/pulls/<number>/files?per_page=100",
            "runs": f"gh api repos/{REPO}/actions/workflows/corpus-drift.yml/runs?branch=<head-ref>&event=pull_request&per_page=100",
            "attempt_jobs": f"gh api repos/{REPO}/actions/runs/<id>/attempts/<attempt>/jobs?per_page=100",
            "failed_logs": f"gh run view <id> --repo {REPO} --log-failed [--attempt N]",
        },
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    wrapper = {
        "payload_sha256": f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        "payload": payload,
    }
    output.write_text(json.dumps(wrapper, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({
        "path": str(output),
        "bytes": output.stat().st_size,
        "payload_sha256": wrapper["payload_sha256"],
        "baseline_rows": len(payload["baseline_population"]["rows"]),
        "recent_rows": len(payload["recent_pr_population"]["rows"]),
        "corpus_runs": sum(len(row["corpus_runs"]) for row in rows.values()),
    }))


if __name__ == "__main__":
    main()
