#!/usr/bin/env python3
"""Build the deterministic corpus-drift remeasurement evidence bundle."""

from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import argparse
from pathlib import Path
from typing import Any


INPUTS = {
    "raw-forge-receipts.json.gz": Path("/tmp/d16-c4-raw-evidence.enriched.json"),
    "baseline-chronology.json.gz": Path("/tmp/d16-c4-chronology.json"),
    "recent-relevance-replay.json.gz": Path("/tmp/d16-c4-recent-replay.json"),
}
SCRIPTS = {
    "collect-forge-evidence.py": Path("/tmp/collect_d16_c4_evidence.py"),
    "reduce-chronology.py": Path("/tmp/analyze_d16_c4.py"),
    "replay-relevance.py": Path("/tmp/replay_d16_recent.py"),
    "build-package.py": Path("/tmp/package_d16_evidence.py"),
}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def deterministic_gzip(source: Path, target: Path) -> None:
    with source.open("rb") as reader, target.open("wb") as raw_writer:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw_writer, mtime=0) as writer:
            shutil.copyfileobj(reader, writer)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/tmp/corpus-drift-remeasurement-history"))
    args = parser.parse_args()
    root = args.root
    if root.exists():
        raise RuntimeError(f"refusing to replace existing package directory {root}")
    root.mkdir(parents=True)
    for name, source in INPUTS.items():
        deterministic_gzip(source, root / name)
    for name, source in SCRIPTS.items():
        shutil.copyfile(source, root / name)
    shutil.copyfile("/tmp/d16-evidence-README.md", root / "README.md")
    shutil.copyfile("/tmp/d16-current-ownership.json", root / "current-ownership.json")

    chronology = json.loads(Path("/tmp/d16-c4-chronology.json").read_text())
    replay = json.loads(Path("/tmp/d16-c4-recent-replay.json").read_text())["payload"]
    summary = {
        "schema": 1,
        "baselinePopulation": {
            "count": len(chronology["baselinePopulation"]),
            "digest": chronology["candidateDigests"]["baseline"]["expected"],
            "classificationCounts": chronology["metrics"]["counts"],
            "provenDenominator": chronology["metrics"]["provenDenominator"],
            "strictGatePrompted": chronology["metrics"]["strictGatePrompted"],
            "gateInvolved": chronology["metrics"]["gateInvolved"],
            "negativeControl": chronology["metrics"]["negativeControl"],
        },
        "recentReplay": {
            "populationCount": replay["metrics"]["finalPullRequests"],
            "populationDigest": replay["source"]["populationManifestDigest"],
            "finalDeclaredNoOp": replay["metrics"]["finalDeclaredNoOp"],
            "finalFullScan": replay["metrics"]["finalFullScan"],
            "historicalWorkflowRuns": replay["metrics"]["historicalWorkflowRuns"],
            "uniqueClassifications": replay["metrics"]["uniqueClassifications"],
            "attemptsRetained": replay["metrics"]["attemptsRetained"],
            "attemptsThatActuallyScored": replay["metrics"]["attemptsThatActuallyScored"],
            "scoredAttemptsAvoided": replay["metrics"]["scoredAttemptsAvoided"],
            "grossRunnerMinutesAvoided": replay["metrics"]["grossRunnerMinutesAvoided"],
            "criticalPathMinutesAvoided": replay["metrics"]["criticalPathMinutesAvoided"],
            "hostedNetSavingsEstimated": replay["metrics"]["hostedNetSavingsEstimated"],
            "finalNoOpPulls": [row["number"] for row in replay["finalPullRequests"] if row["decision"] == "declared-no-op"],
            "attemptAwareNote": "All 117 unique run heads and 129 attempts are retained. Savings count only jobs whose corpus producer/replay step actually executed and whose replayed receipt is declared-no-op; skipped/setup-only jobs and classifier overhead are excluded.",
        },
    }
    (root / "summary.json").write_bytes(canonical(summary))

    manifest_files = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.encode()):
        if path.name == "manifest.json":
            continue
        manifest_files.append({
            "path": path.name,
            "bytes": path.stat().st_size,
            "sha256": digest(path),
        })
    manifest = {
        "schema": 1,
        "kind": "corpus-drift-remeasurement-history",
        "repository": "jharvieux/Harvey",
        "frozenAt": "2026-08-25T20:20:00Z",
        "files": manifest_files,
    }
    manifest_bytes = canonical(manifest)
    (root / "manifest.json").write_bytes(manifest_bytes)
    print(json.dumps({
        "root": str(root),
        "manifestSha256": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
        "files": len(list(root.iterdir())),
        "bytes": sum(path.stat().st_size for path in root.iterdir()),
    }, indent=2))


if __name__ == "__main__":
    main()
