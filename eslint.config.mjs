import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // ".claude" holds agent worktrees (.claude/worktrees/<agent>/ — full repo copies while a
  // parallel agent runs). Top-level ignores don't apply to those nested copies, so without
  // this entry `pnpm verify` fails locally whenever an agent worktree exists.
  // "site" is the harvey-qa.com marketing site — a self-contained Next.js app with its own
  // package.json/tsconfig/build, deployed as its own Vercel project. Excluded from the root
  // toolchain the same way epic-builder-web is (knip/tsconfig are already src-scoped).
  { ignores: ["node_modules", "report-template/out", "coverage", "targets", "epic-builder-web", "site", ".claude"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.mjs"],
    languageOptions: { globals: { console: "readonly", process: "readonly", fetch: "readonly" } },
  },
);
