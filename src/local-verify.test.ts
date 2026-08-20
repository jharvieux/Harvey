import { describe, expect, it } from "vitest";
import { isFocusedLocalVerificationPath, localVerificationTier } from "./local-verify.js";

describe("path-sensitive local verification", () => {
  it("uses the focused gate for operating docs, Markdown docs, and Codex agent TOML", () => {
    for (const path of [
      "AGENTS.md",
      "CLAUDE.md",
      "MODULES.md",
      "README.md",
      "SESSION.md",
      "docs/design/recorded-reasons.md",
      ".codex/agents/acceptance-verifier.toml",
    ]) {
      expect(isFocusedLocalVerificationPath(path), path).toBe(true);
    }
    expect(localVerificationTier(["AGENTS.md", "SESSION.md", ".codex/agents/acceptance-verifier.toml"])).toBe("focused");
  });

  it("fails safe to the full gate for source, executable inputs, manifests, workflows, and unknown paths", () => {
    for (const path of [
      "src/findings.ts",
      "briefs/anti-patterns.md",
      "targets/calibration/README.md",
      "package.json",
      "pnpm-lock.yaml",
      ".github/workflows/ci.yml",
      ".github/actions/alert-issue/action.yml",
      "dry-run/findings.json",
      ".codex/config.toml",
      ".codex/agents/unclassified.txt",
      ".codex/agents/team/nested.toml",
      "docs/data.json",
      "notes.txt",
    ]) {
      expect(isFocusedLocalVerificationPath(path), path).toBe(false);
      expect(localVerificationTier([path]), path).toBe("full");
    }
  });

  it("takes the widest tier for mixed changes and treats an empty diff as full", () => {
    expect(localVerificationTier(["SESSION.md", "src/findings.ts"])).toBe("full");
    expect(localVerificationTier([])).toBe("full");
  });
});
