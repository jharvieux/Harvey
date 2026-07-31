import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // ".claude" holds agent worktrees (.claude/worktrees/<agent>/ — full repo copies while a
  // parallel agent runs). Top-level ignores don't apply to those nested copies, so without
  // this entry `pnpm verify` fails locally whenever an agent worktree exists.
  // "site" is the harvey-qa.com marketing site. Since #1597 it is a pnpm WORKSPACE MEMBER rather
  // than a separate npm project, but it still has its own Next toolchain and its own eslint
  // (site/eslint.config.mjs, run by `next lint` in the site-ci job), so the root pass keeps out of
  // it — the same split epic-builder-web has. knip DOES cover it now (knip.json `workspaces`).
  // ".vercel" is the Vercel CLI's link + `vercel build` output, which #1597 moved to the REPO ROOT
  // when the deploy started uploading from here. Without this entry, `pnpm verify` fails with ~33
  // errors in generated launcher/chunk files the moment anyone runs `vercel build` locally
  // (MEASURED 2026-07-30 — that is exactly how this line was found).
  { ignores: ["node_modules", "report-template/out", "coverage", "targets", "epic-builder-web", "site", ".claude", ".vercel"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.mjs"],
    languageOptions: { globals: { console: "readonly", process: "readonly", fetch: "readonly" } },
  },
);
