// A source file containing a literal NUL byte is classified as BINARY, and plain `grep` then
// returns nothing for it and exits 1 — indistinguishable from "the symbol does not exist".
//
// That matters here more than it would in most repos. CLAUDE.md's doctrine for re-testing a recorded
// blocker is "grep the current tree for the thing the acceptance criteria promised", and #1377 records
// that as "the check that actually found defects". A silently unreadable file turns that check into a
// false NEGATIVE: it manufactures exactly the false decline the doctrine exists to catch.
//
// MEASURED 2026-07-30 (#1377): `src/fix/verify-harness.ts` and `report-template/rollup.mjs` each
// carried one literal NUL as a composite-key separator in a template literal. `grep -rn "cmdKey" src/`
// found ZERO hits while the symbol had five, and an audit of this repo read that zero as "no caller"
// before catching itself. Both now use a unicode escape sequence — same runtime string, greppable file.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { describe, expect, it } from "vitest";

const REPO_ROOT = new URL("..", import.meta.url).pathname;

// Extensions whose content is meant to be read as text by a human or a grep. Anything else
// (.png/.pdf/.gz) is legitimately binary and is not this check's business.
const TEXT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".md", ".sql", ".css", ".html", ".txt", ".sh"]);

function trackedTextFiles(): string[] {
  const out = execFileSync("git", ["ls-files", "-z"], { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return out.split("\0").filter((p) => p !== "" && TEXT_EXTENSIONS.has(extname(p)));
}

describe("tracked source files stay greppable", () => {
  it("no text source carries a literal NUL, which makes grep silently skip the whole file", () => {
    const files = trackedTextFiles();
    // A zero-file walk would pass vacuously, and this repo's own doctrine says an unstated
    // limitation reads as a clean bill of health.
    expect(files.length).toBeGreaterThan(100);

    const offenders = files.filter((p) => readFileSync(`${REPO_ROOT}${p}`).includes(0));
    expect(offenders, "use the \\u0000 escape instead of a literal NUL byte — same string, and grep can still read the file").toEqual([]);
  });
});
