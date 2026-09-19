import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { copyFilteredSourceTree } from "./source-copy.js";

const dirs: string[] = [];
const temp = () => { const dir = mkdtempSync(join(tmpdir(), "harvey-source-copy-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

describe("filtered source copies", () => {
  it.each([false, true])("rebases internal directory and file aliases without exposing excluded files (absolute %s)", (absolute) => {
    const root = temp(), dest = temp();
    mkdirSync(join(root, "src"));
    writeFileSync(join(root, "src/live.ts"), "original");
    writeFileSync(join(root, "src/generated.js"), "generated");
    symlinkSync(absolute ? join(root, "src") : "src", join(root, "alias"));
    symlinkSync(absolute ? join(root, "src/live.ts") : "src/live.ts", join(root, "file.ts"));
    copyFilteredSourceTree(root, dest, (path) => path !== "src/generated.js");
    expect(existsSync(join(dest, "alias/generated.js"))).toBe(false);
    expect(realpathSync(join(dest, "alias/live.ts"))).toBe(realpathSync(join(dest, "src/live.ts")));
    expect(realpathSync(join(dest, "file.ts"))).toBe(realpathSync(join(dest, "src/live.ts")));
    writeFileSync(join(dest, "alias/live.ts"), "mutated");
    expect(readFileSync(join(dest, "file.ts"), "utf8")).toBe("mutated");
    expect(readFileSync(join(root, "src/live.ts"), "utf8")).toBe("original");
  });

  it("materializes an alias when its own exact exclusions differ from its target", () => {
    const root = temp(), dest = temp();
    mkdirSync(join(root, "src"));
    writeFileSync(join(root, "src/live.ts"), "live");
    writeFileSync(join(root, "src/other.ts"), "other");
    symlinkSync("src", join(root, "alias"));
    copyFilteredSourceTree(root, dest, (path) => path !== "alias/other.ts");
    expect(lstatSync(join(dest, "alias")).isDirectory()).toBe(true);
    expect(existsSync(join(dest, "alias/other.ts"))).toBe(false);
    expect(readFileSync(join(dest, "alias/live.ts"), "utf8")).toBe("live");
    expect(readFileSync(join(dest, "src/other.ts"), "utf8")).toBe("other");
  });

  it("rejects external source aliases while leaving excluded dependency links to their separate mirror", () => {
    const root = temp(), dest = temp(), external = temp();
    writeFileSync(join(external, "live.ts"), "external");
    symlinkSync(external, join(root, "external"));
    symlinkSync(external, join(root, "node_modules"));
    expect(() => copyFilteredSourceTree(root, dest, (path) => path !== "node_modules")).toThrow(/source alias external.*outside/);
    expect(existsSync(join(dest, "external"))).toBe(false);
    expect(readFileSync(join(external, "live.ts"), "utf8")).toBe("external");
  });

  it("omits dangling and file-cycle aliases and rejects directory cycles before linking", () => {
    const root = temp(), dest = temp();
    writeFileSync(join(root, "live.ts"), "live");
    symlinkSync("missing.ts", join(root, "dangling.ts"));
    symlinkSync("cycle-b", join(root, "cycle-a"));
    symlinkSync("cycle-a", join(root, "cycle-b"));
    copyFilteredSourceTree(root, dest, () => true);
    expect(readFileSync(join(dest, "live.ts"), "utf8")).toBe("live");
    expect(existsSync(join(dest, "dangling.ts"))).toBe(false);
    expect(existsSync(join(dest, "cycle-a"))).toBe(false);
    symlinkSync(".", join(root, "cycle-dir"));
    expect(() => copyFilteredSourceTree(root, temp(), () => true)).toThrow(/cyclic source directory alias/);
  });

  it("keeps tracked selection when a tracked alias points at an untracked target", () => {
    const root = temp(), dest = temp();
    writeFileSync(join(root, "live.ts"), "tracked");
    writeFileSync(join(root, "untracked.ts"), "untracked");
    symlinkSync(join(root, "untracked.ts"), join(root, "alias.ts"));
    copyFilteredSourceTree(root, dest, () => true, ["live.ts", "alias.ts"]);
    expect(readFileSync(join(dest, "live.ts"), "utf8")).toBe("tracked");
    expect(existsSync(join(dest, "alias.ts"))).toBe(false);
  });
});
