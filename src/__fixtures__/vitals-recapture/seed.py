#!/usr/bin/env python3
"""
Seed a throwaway git repo + `.vitals` provenance DB whose REAL
`vitals 0.2.0 report --json` output reproduces every planted M3 calibration entry,
then capture that output to `src/__fixtures__/vitals-report.json` (issue #1146, row 6 of #1130).

WHY this exists: the fixture doubles as the M3 calibration-corpus plant
(`src/scan/calibration/m3.entries.ts`, scored via `buildCoverageMatrix` in
`src/hotspot-scan.test.ts`). A faithful capture cannot be a single ad-hoc run pasted in — the plant
encodes specific hotspot / truck-factor / coupling / AI-provenance RELATIONSHIPS. This script builds
a repo whose git history + provenance DB make vitals emit those relationships, so every number in the
fixture comes from the tool, not from a keyboard. See the sibling PROVENANCE.md.

Records may be TRIMMED/DROPPED from the capture but never hand-EDITED. This script edits INPUTS
(repo history), never the tool's OUTPUT.

Usage:
    python3 src/__fixtures__/vitals-recapture/seed.py [--out <path>] [--keep-repo]

Requires vitals 0.2.0 installed at the pinned plugin path (EXPECTED_VITALS_VERSION in
src/cli/hotspot-scan.ts). Verified 2026-07-26: `vitals_cli.py version` -> `Vitals v0.2.0`.
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DEFAULT_OUT = os.path.join(REPO_ROOT, "src", "__fixtures__", "vitals-report.json")
_PLUGIN_CLI = os.path.expanduser(
    "~/.claude/plugins/cache/vitals/vitals/0.2.0/scripts/vitals_cli.py"
)
# The pinned plugin path when present (local plugin install); else vitals_cli.py on PATH — how CI
# installs it (conservation.yml adds the cloned vitals scripts dir to PATH). run_vitals asserts the
# version either way, so a wrong version on PATH still fails loud.
VITALS_CLI = _PLUGIN_CLI if os.path.exists(_PLUGIN_CLI) else (shutil.which("vitals_cli.py") or _PLUGIN_CLI)
EXPECTED_VERSION = "Vitals v0.2.0"

DAY = 86400
NOW = int(time.time())

ALICE = ("alice", "alice@example.com")
BOB = ("bob", "bob@example.com")
CAROL = ("carol", "carol@example.com")


# --- File-content generators -------------------------------------------------
# vitals' complexity score (complexity.py) for non-Python files is driven by INDENTATION nesting
# depth and file length; branch keywords are NOT counted for non-.py files. So "high complexity"
# means deep, long nesting. Bodies below are chosen to land each file in the intended health bucket;
# the exact score is READ BACK from the tool, never asserted here.

def deep_body(fn_name, levels, inner_lines):
    """A deeply-nested, optionally-long function — drives a LOW health score (high complexity)."""
    kw = ["if (a) {", "for (const x of xs) {", "while (a) {", "if (b) {", "if (c) {", "if (d) {", "if (e) {"]
    out = [f"export function {fn_name}(a, b, c, d, e, xs) {{", "  let acc = 0;"]
    for i in range(levels):
        out.append("  " * (i + 1) + kw[i % len(kw)])
    for j in range(inner_lines):
        out.append("  " * (levels + 1) + f"acc += x{j % 7} + {j};")
    for i in range(levels, 0, -1):
        out.append("  " * i + "}")
    out.append("  return acc;")
    out.append("}")
    return "\n".join(out)


def mid_body(fn_name, levels):
    """A moderately-nested short function — mid health; still gated in (nesting >= 3)."""
    out = [f"export function {fn_name}(a, b, xs) {{", "  let acc = 0;"]
    for i in range(levels):
        out.append("  " * (i + 1) + ("for (const x of xs) {" if i == 1 else "if (a) {"))
    out.append("  " * (levels + 1) + "acc += 1;")
    for i in range(levels, 0, -1):
        out.append("  " * i + "}")
    out.append("  return acc;")
    out.append("}")
    return "\n".join(out)


def low_body(fn_name):
    """Nesting depth EXACTLY 3 with lots of flat filler — the smallest complexity score a file can
    carry while still clearing vitals' nesting>2 gate (so it appears in the hotspot table but scores
    HEALTHY). This is the M3-N-CHURN-TRIVIAL / M3-N-AIPROV-HUMAN file: highest raw churn, lowest risk."""
    out = [f"export function {fn_name}(a, b, xs) {{", "  let acc = 0;"]
    # flat filler dilutes the deep-nesting ratio so the score sits in the HEALTHY band
    for i in range(14):
        out.append(f"  const c{i} = {i};")
    out += ["  if (a) {", "    for (const x of xs) {", "      acc += 1;", "    }", "  }",
            "  return acc;", "}"]
    return "\n".join(out)


# file -> (body, churn_count, author_pool). Each churn commit is authored by pool[i % len(pool)] and
# lands on its OWN calendar day (except the a<>b joint commits). Multi-author files rotate 3 authors
# so no single author holds >50% of a file's commits -> truck_factor >= 2. billing is sole-authored
# -> truck_factor 1. There is NO shared initial commit: a single-author creation commit would tip
# every file toward that author and collapse truck_factor to 1 (observed). Files are created on first
# touch inside their own churn loop.
TRIO = [ALICE, BOB, CAROL]
FILES = {
    "core/checkout.ts":       (deep_body("checkout", 6, 210),  17, TRIO),   # high churn + high complexity -> #1 hotspot
    "generated/schema.gen.ts":(low_body("schema"),             18, TRIO),   # highest RAW churn, lowest risk -> NOT top-K
    "core/billing.ts":        (deep_body("billing", 6, 120),   14, [ALICE]),# sole author -> truck_factor 1
    "core/reporting.ts":      (deep_body("reporting", 6, 200), 16, TRIO),   # multi-author (must NOT be truck_factor 1)
    "core/a.ts":              (mid_body("a", 4),                0,  []),     # churned only WITH core/b.ts (coupling)
    "core/b.ts":              (mid_body("b", 4),                0,  []),
    "lib/stable.ts":          (mid_body("stable", 3),           2,  TRIO),   # LOW churn; AI-authored but not high-churn
}
AB_CHURN = 5  # core/a.ts <> core/b.ts always co-committed -> exactly one coupling edge


def git(repo, *args, author=None, when=None):
    env = dict(os.environ)
    if author:
        name, email = author
        env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = name
        env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = email
    if when is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"@{when} +0000"
    subprocess.run(["git", "-C", repo, *args], check=True, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_file(repo, path, body, rev):
    full = os.path.join(repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    # The REV line is top-level (indent 0), so bumping it changes NOTHING about nesting depth or
    # length — complexity stays constant across churn commits, only the churn COUNT grows.
    with open(full, "w") as f:
        f.write(body + f"\nexport const REV = {rev};\n")


def build_repo(repo):
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "seed")
    git(repo, "config", "user.email", "seed@example.com")

    # Distinct calendar days for every churn commit so no two unrelated files ever share a day (which
    # would manufacture a spurious coupling pair). Days 3..~74 ago -> all inside the 90-day churn
    # window. Files are created on first touch — no shared initial commit (see the FILES note).
    day = 3
    rev = 1

    for path, (body, churn, authors) in FILES.items():
        for i in range(churn):
            write_file(repo, path, body, rev)
            git(repo, "add", path)
            git(repo, "commit", "-q", "-m", f"churn {path} {i}", author=authors[i % len(authors)],
                when=NOW - day * DAY)
            day += 1
            rev += 1

    # core/a.ts <> core/b.ts: always committed TOGETHER, each on its own day -> one coupling edge.
    for i in range(AB_CHURN):
        write_file(repo, "core/a.ts", FILES["core/a.ts"][0], rev)
        write_file(repo, "core/b.ts", FILES["core/b.ts"][0], rev)
        git(repo, "add", "core/a.ts", "core/b.ts")
        git(repo, "commit", "-q", "-m", f"churn a+b {i}", author=TRIO[i % len(TRIO)],
            when=NOW - day * DAY)
        day += 1
        rev += 1


def seed_provenance(repo):
    """Seed `.vitals/store.db` so provenance.has_data is true with a specific ai_files list:
    core/checkout.ts (AI-authored + high churn -> M3-P-AIPROV) and lib/stable.ts (AI-authored but
    LOW churn -> M3-N-AIPROV-STABLE). generated/schema.gen.ts is deliberately ABSENT (high churn but
    human -> M3-N-AIPROV-HUMAN). Matches db.py's schema exactly (get_ai_file_stats groups Edit/Write
    over a 30-day window, ordered by total_events DESC)."""
    vdir = os.path.join(repo, ".vitals")
    os.makedirs(vdir, exist_ok=True)
    db_path = os.path.join(vdir, "store.db")
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE provenance_events (
            event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, timestamp REAL NOT NULL,
            file_path TEXT NOT NULL, tool_name TEXT NOT NULL, lines_changed INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT);
        INSERT INTO schema_meta (key, value) VALUES ('version', '2');
        """
    )
    # (file, edits, writes) -> checkout 34 events, stable 12 events, all within the 30-day window.
    # Three distinct sessions so provenance.summary.total_sessions == 3.
    plan = [("core/checkout.ts", 30, 4), ("lib/stable.ts", 10, 2)]
    sessions = [str(uuid.uuid4()) for _ in range(3)]
    for file_path, edits, writes in plan:
        n = 0
        for kind, count in (("Edit", edits), ("Write", writes)):
            for _ in range(count):
                # spread across the last 25 days (inside the 30-day get_ai_file_stats window)
                ts = NOW - (1 + (n % 25)) * DAY
                conn.execute(
                    "INSERT INTO provenance_events (event_id, session_id, timestamp, file_path, tool_name) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), sessions[n % 3], ts, file_path, kind),
                )
                n += 1
    conn.commit()
    conn.close()


def run_vitals(repo):
    ver = subprocess.run([sys.executable, VITALS_CLI, "version"], capture_output=True, text=True)
    if ver.stdout.strip() != EXPECTED_VERSION:
        sys.exit(f"vitals version mismatch: expected {EXPECTED_VERSION!r}, got {ver.stdout.strip()!r}")
    out = subprocess.run([sys.executable, VITALS_CLI, "report", "--json", repo],
                         capture_output=True, text=True, cwd=repo)
    if out.returncode != 0:
        sys.exit(f"vitals report failed:\n{out.stderr}")
    return json.loads(out.stdout)


NOTE = (
    "CAPTURED, not hand-written. Real `vitals 0.2.0 report --json` output, produced by "
    "src/__fixtures__/vitals-recapture/seed.py against a purpose-seeded throwaway git repo + "
    ".vitals provenance DB (see src/__fixtures__/vitals-recapture/PROVENANCE.md). "
    "The seed reproduces every planted M3 calibration entry (m3.entries.ts) from the tool's own "
    "output: core/checkout.ts is the #1 churn x complexity hotspot (M3-P-HOTSPOT / M3-P-AIPROV); "
    "generated/schema.gen.ts has the highest RAW churn but ranks outside top-3 by risk "
    "(M3-N-CHURN-TRIVIAL / M3-N-AIPROV-HUMAN); core/billing.ts is sole-authored -> truck_factor 1 "
    "(M3-P-TRUCK1); core/reporting.ts is multi-author (M3-N-MULTIAUTHOR); core/a.ts<>core/b.ts are "
    "always co-committed -> one coupling edge (M3-P-COUPLING); lib/stable.ts is AI-authored but LOW "
    "churn (M3-N-AIPROV-STABLE). Records may be dropped from this capture, never edited. "
    "To re-capture: python3 src/__fixtures__/vitals-recapture/seed.py"
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--keep-repo", action="store_true")
    args = ap.parse_args()

    # realpath: on macOS $TMPDIR is a /var -> /private/var symlink, and vitals derives the repo root
    # via `git rev-parse --show-toplevel` (which resolves symlinks) while scoping against the path it
    # was handed — a mismatch empties the file scope. Hand it the resolved path from the start.
    repo = os.path.realpath(tempfile.mkdtemp(prefix="vitals-seed-"))
    try:
        build_repo(repo)
        seed_provenance(repo)
        report = run_vitals(repo)

        # Prepend a provenance _note (metadata, not a tool field) — mirrors the lighthouse fixtures.
        # Absolute capture-machine path leaks nothing useful; normalize `scope`/path-ish fields.
        out = {"_note": NOTE}
        out.update(report)
        with open(args.out, "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")

        # Inspection summary to stderr — never trusted as the source of truth, just for tuning.
        ranked = sorted(report["hotspots"], key=lambda h: -h["risk_score"])
        print("=== hotspot ranking (risk desc) ===", file=sys.stderr)
        for h in ranked:
            print(f"  {h['risk_score']:7.1f}  churn={h['changes']:2d} {h['churn_label']:4s} "
                  f"comp={h['complexity_score']:3d} health={h['health']}  {h['file_path']}", file=sys.stderr)
        print("=== knowledge_risk ===", file=sys.stderr)
        for k in report["knowledge_risk"]:
            print(f"  tf={k['truck_factor']} authors={k['author_count']}  {k['file_path']}", file=sys.stderr)
        print("=== coupling ===", file=sys.stderr)
        for c in report["coupling"]:
            print(f"  {c['file_a']} <> {c['file_b']}  co={c['co_changes']} strength={c['coupling_strength']}", file=sys.stderr)
        print("=== provenance.ai_files ===", file=sys.stderr)
        for a in (report.get("provenance", {}) or {}).get("ai_files", []):
            print(f"  {a['file_path']}  total_events={a['total_events']} edit={a['edit_count']} write={a['write_count']}", file=sys.stderr)
        print(f"\nwrote {args.out}", file=sys.stderr)
    finally:
        if args.keep_repo:
            print(f"kept repo at {repo}", file=sys.stderr)
        else:
            shutil.rmtree(repo, ignore_errors=True)


if __name__ == "__main__":
    main()
