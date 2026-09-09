// #2002 — GitHub can delay or drop scheduled workflows that start at the top of the hour. This
// reads the workflow directory directly; no separate cron list is maintained.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { readNamesSafe } from "./fs-walk.js";

interface WorkflowFile {
  name: string;
  text: string;
}

interface CronRow {
  workflow: string;
  index: number;
  cron: string;
}

const WORKFLOWS = join(process.cwd(), ".github", "workflows");

function activeWorkflowFiles(): WorkflowFile[] {
  return readNamesSafe(WORKFLOWS)
    .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
    .sort()
    .map((name) => ({ name, text: readFileSync(join(WORKFLOWS, name), "utf8") }));
}

function cronRows(files: WorkflowFile[]): { rows: CronRow[]; errors: string[] } {
  const rows: CronRow[] = [];
  const errors: string[] = [];
  for (const { name, text } of files) {
    const document = parse(text) as { on?: { schedule?: unknown } };
    if (document.on?.schedule === undefined) continue;
    if (!Array.isArray(document.on.schedule)) {
      errors.push(`${name}: on.schedule must be a list`);
      continue;
    }
    document.on.schedule.forEach((entry, index) => {
      const cron = entry && typeof entry === "object" ? (entry as { cron?: unknown }).cron : undefined;
      if (typeof cron !== "string") {
        errors.push(`${name}: schedule row ${index + 1} must have a string cron`);
        return;
      }
      rows.push({ workflow: name, index: index + 1, cron });
    });
  }
  return { rows, errors };
}

function minuteError(row: CronRow): string | undefined {
  const fields = row.cron.trim().split(/\s+/);
  if (fields.length !== 5) return `${row.workflow}: schedule row ${row.index} has ${fields.length} cron fields, expected 5`;
  const minute = fields[0]!;
  if (/^\d+$/.test(minute)) {
    const value = Number(minute);
    if (value >= 1 && value <= 59) return undefined;
    return `${row.workflow}: schedule row ${row.index} uses minute zero or an invalid minute (${minute})`;
  }
  // Compound cron syntax remains unsupported until a parser gives each form a bounded meaning.
  const reachesZero = minute === "*" || /(^|[,/])0(?:$|[,/-])/.test(minute) || /^\*\//.test(minute);
  return reachesZero
    ? `${row.workflow}: schedule row ${row.index} uses a minute syntax that includes zero (${minute})`
    : `${row.workflow}: schedule row ${row.index} uses unsupported minute syntax (${minute})`;
}

function scheduleErrors(files: WorkflowFile[]): string[] {
  const census = cronRows(files);
  return [...census.errors, ...census.rows.flatMap((row) => minuteError(row) ?? [])];
}

function workflow(name: string, cron: string): WorkflowFile {
  return { name, text: `name: ${name}\non:\n  schedule:\n    - cron: "${cron}"\n` };
}

function withMinuteZero(files: WorkflowFile[], row: CronRow): WorkflowFile[] {
  const zeroCron = `0 ${row.cron.trim().split(/\s+/).slice(1).join(" ")}`;
  return files.map((file) => {
    if (file.name !== row.workflow) return file;
    const old = `cron: "${row.cron}"`;
    expect(file.text.match(new RegExp(old.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"))).toHaveLength(1);
    return { ...file, text: file.text.replace(old, `cron: "${zeroCron}"`) };
  });
}

describe("active GitHub Actions schedules stay off minute zero (#2002)", () => {
  it("discovers the complete live workflow population and accepts its nonzero minute fields", () => {
    const files = activeWorkflowFiles();
    const census = cronRows(files);
    expect(files.length).toBeGreaterThan(0);
    expect(census.errors).toEqual([]);
    expect(census.rows).toHaveLength(15);
    expect(scheduleErrors(files)).toEqual([]);
  });

  it("finds a new workflow with a minute-zero schedule without adding it to a fixture list", () => {
    const files = [...activeWorkflowFiles(), workflow("new-scheduled-workflow.yml", "0 14 * * *")];
    expect(scheduleErrors(files)).toContain("new-scheduled-workflow.yml: schedule row 1 uses minute zero or an invalid minute (0)");
  });

  it("fails for every production schedule when its discovered minute is reverted to zero", () => {
    const files = activeWorkflowFiles();
    const rows = cronRows(files).rows;
    expect(rows).toHaveLength(15);
    for (const row of rows) {
      const errors = scheduleErrors(withMinuteZero(files, row));
      expect(errors, `${row.workflow} row ${row.index}`).toHaveLength(1);
      expect(errors[0], `${row.workflow} row ${row.index}`).toContain("minute zero");
    }
  });

  it("rejects every zero-capable cron minute grammar that GitHub accepts", () => {
    for (const minute of ["0", "0,17", "*/5", "0/5", "0-10", "0-59/5"]) {
      const errors = scheduleErrors([workflow(`minute-${minute.replaceAll(/[^a-z0-9]/gi, "-")}.yml`, `${minute} 14 * * *`)]);
      expect(errors, minute).toHaveLength(1);
      expect(errors[0], minute).toContain("zero");
    }
  });

  it("fails closed on an unproved compound minute expression", () => {
    expect(scheduleErrors([workflow("compound.yml", "7-15 14 * * *")]))
      .toEqual(["compound.yml: schedule row 1 uses unsupported minute syntax (7-15)"]);
  });
});
