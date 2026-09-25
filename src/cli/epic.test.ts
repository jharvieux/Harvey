import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { ScaffoldModelClient } from "../epic-builder/model-scaffold.js";
import { runClarify } from "../epic-builder/session.js";
import type { ModelClient } from "../epic-builder/types.js";
import { createWorkspace, loadSession, readDraft, readFileRaw } from "../epic-builder/workspace.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "epic.ts");
const TSX = join(REPO_ROOT, "node_modules", ".bin", "tsx");
let cleanup: string[] = [];

afterEach(() => {
  for (const dir of cleanup) rmSync(dir, { recursive: true, force: true });
  cleanup = [];
});

describe("epic CLI session recovery (#2081)", () => {
  it("resumes a durable clarify checkpoint after a model exception", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "epic-cli-resume-"));
    cleanup.push(cwd);
    const templateDir = join(cwd, "docs", "templates");
    mkdirSync(templateDir, { recursive: true });
    for (const file of ["epic.md", "user-story.md", "implementation-brief.md"]) {
      copyFileSync(join(REPO_ROOT, "docs", "templates", file), join(templateDir, file));
    }

    const created = createWorkspace(cwd, "Resume a failed clarification model call");
    const throwing = Object.assign(Object.create(new ScaffoldModelClient()) as ModelClient, {
      async clarify() { throw new Error("model unavailable"); },
    });
    await expect(runClarify(created.dir, created.session, throwing, async () => "defaults"))
      .rejects.toThrow("model unavailable");
    expect(loadSession(created.dir).state).toBe("clarify");

    const child = spawnSync(TSX, [CLI, "resume", created.slug], {
      cwd,
      input: "defaults\nq\n",
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" },
    });
    expect(child.status, child.stderr).toBe(0);
    expect(child.stdout).toContain("Session saved.");
    expect(loadSession(created.dir).state).toBe("epic-review");
    expect(readFileRaw(created.dir, "intake.md")).toContain("**Answers:** defaults");
    expect(readDraft(created.dir, "epic.md").data.status).toBe("in-review");
  });
});
