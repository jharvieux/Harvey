import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // ".claude" holds agent worktrees (.claude/worktrees/<agent>/ — full repo copies while a
  // parallel agent runs). Top-level ignores don't apply to those nested copies, so without
  // this entry `pnpm verify` fails locally whenever an agent worktree exists.
  { ignores: ["node_modules", "report-template/out", "coverage", "targets", "epic-builder-web", ".claude"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.mjs"],
    languageOptions: { globals: { console: "readonly", process: "readonly", fetch: "readonly" } },
  },
);
