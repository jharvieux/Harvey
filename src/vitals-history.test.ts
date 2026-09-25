import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { VitalsReport } from "./hotspot-scan.js";
import { prepareVitalsRun, vitalsAvailability } from "./vitals-history.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const digest = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");

describe("prepareVitalsRun source boundary", () => {
  it.each(["unstaged", "staged", "rename", "directory", "spaced", "cached", "recreated"])("preserves the live checkout after %s deletion without refreshing the client index", mode => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-vitals-source-"));
    const cache = mkdtempSync(join(tmpdir(), "harvey-vitals-cache-"));
    roots.push(repo, cache);
    execFileSync("git", ["init", "-q"], { cwd: repo });
    execFileSync("git", ["config", "user.email", "fixture@example.test"], { cwd: repo });
    execFileSync("git", ["config", "user.name", "Fixture"], { cwd: repo });
    mkdirSync(join(repo, "src"));
    const deletedPath = mode === "spaced" ? " deleted.ts" : mode === "directory" ? "src/deleted/file.ts" : "src/deleted.ts";
    if (mode === "directory") mkdirSync(join(repo, "src/deleted"));
    writeFileSync(join(repo, deletedPath), "export const deleted = true;\n");
    writeFileSync(join(repo, "src", "modified.ts"), "export const modified = 1;\n");
    writeFileSync(join(repo, "src", "unchanged.ts"), "export const unchanged = true;\n");
    execFileSync("git", ["add", "."], { cwd: repo });
    execFileSync("git", ["commit", "-qm", "fixture"], { cwd: repo });
    if (mode === "rename") execFileSync("git", ["mv", deletedPath, "src/moved.ts"], { cwd: repo });
    else if (mode === "cached") execFileSync("git", ["rm", "--cached", "--", deletedPath], { cwd: repo });
    else if (mode === "recreated") {
      execFileSync("git", ["rm", "--", deletedPath], { cwd: repo });
      writeFileSync(join(repo, deletedPath), "export const recreated = true;\n");
    }
    else if (mode === "staged" || mode === "spaced") execFileSync("git", ["rm", "--", deletedPath], { cwd: repo });
    else if (mode === "directory") execFileSync("git", ["rm", "-r", "--", "src/deleted"], { cwd: repo });
    else rmSync(join(repo, deletedPath));
    writeFileSync(join(repo, "src", "modified.ts"), "export const modified = 2;\n");
    writeFileSync(join(repo, "src", "added.ts"), "export const added = true;\n");
    // A copied checkout retains index stat data from another filesystem instance.
    // Keep bytes unchanged while forcing Git to reconsider its cached timestamps.
    utimesSync(join(repo, "src", "unchanged.ts"), new Date(0), new Date(0));
    const before = digest(join(repo, ".git", "index"));

    const prepared = prepareVitalsRun({ targetDir: repo, cacheRoot: cache, toolVersion: "0.2.0" });
    try {
      if (mode === "cached" || mode === "recreated") expect(readFileSync(join(prepared.targetDir, deletedPath), "utf8")).toBe(readFileSync(join(repo, deletedPath), "utf8"));
      else expect(() => readFileSync(join(prepared.targetDir, deletedPath))).toThrow();
      if (mode === "rename") expect(readFileSync(join(prepared.targetDir, "src/moved.ts"), "utf8")).toContain("deleted");
      expect(readFileSync(join(prepared.targetDir, "src", "modified.ts"), "utf8")).toContain("= 2");
      expect(readFileSync(join(prepared.targetDir, "src", "added.ts"), "utf8")).toContain("added");
      expect(digest(join(repo, ".git", "index"))).toBe(before);
    } finally {
      prepared.cleanup();
    }
  });
});

describe("vitalsAvailability measured populations", () => {
  const report: VitalsReport = {
    hotspots: [], coupling: [], knowledge_risk: [], mode: "full", files_analyzed: 7,
    file_health: Object.fromEntries(Array.from({ length: 7 }, (_, i) => [`src/${i}.ts`, 7])),
    trends: { previous_overall: 7, previous_timestamp: 1, days_since: 1, overall_delta: 0, degrading: [], improving: [] },
    provenance: { has_data: true, summary: { total_events: 4, unique_files: 2, total_sessions: 1, first_event: 1, last_event: 2 }, ai_files: [] },
  };

  it("reports only comparable history and current-window signal populations", () => {
    const availability = vitalsAvailability(report, undefined, false, {
      historyComparableFiles: 1,
      knowledgeCandidateFiles: 7,
      knowledgeFilesWithAuthorship: 0,
      aiFilesInWindow: 0,
    });
    expect(availability.historyTrend).toEqual({ status: "examined", unitsExamined: 1 });
    expect(availability.knowledgeRisk).toMatchObject({ status: "not-assessed", unitsExamined: 0 });
    expect(availability.aiProvenance).toMatchObject({ status: "not-assessed", unitsExamined: 0 });
  });

  it("does not label a trend examined when prior and current files do not overlap", () => {
    const availability = vitalsAvailability(report, undefined, false, {
      historyComparableFiles: 0,
      knowledgeCandidateFiles: 7,
      knowledgeFilesWithAuthorship: 7,
      aiFilesInWindow: 2,
    });
    expect(availability.historyTrend).toMatchObject({ status: "not-assessed", unitsExamined: 0 });
    expect(availability.knowledgeRisk).toEqual({ status: "examined", unitsExamined: 7 });
    expect(availability.aiProvenance).toEqual({ status: "examined", unitsExamined: 2 });
  });
});
