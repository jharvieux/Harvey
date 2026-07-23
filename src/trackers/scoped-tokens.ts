// Scoped-token auth intake (#747, least-privilege). The filing CLI reads a tracker credential from
// the environment. This module documents, per tracker, the MINIMUM scope that credential needs —
// so an engagement provisions an issues-create-only token, never a broad repo/admin PAT. It is
// intake documentation + the env-var contract, not a scope verifier: a tracker won't tell us a
// token's granted scopes without spending the token, so we document the least-privilege setup and
// keep the credential itself confined to the Authorization header (never a flag, log, or error —
// see http.ts and credentials.test.ts).

export type TrackerKind = "github" | "jira" | "azure";

interface TrackerIntake {
  // The env vars the CLI reads for this tracker. NAMES only — values never appear here or in logs.
  envVars: string[];
  // The least-privilege grant to request when minting the token.
  minimumScope: string;
  // How to provision it, one line, for the per-engagement intake.
  setup: string;
}

export const TRACKER_INTAKE: Record<TrackerKind, TrackerIntake> = {
  github: {
    envVars: ["GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO"],
    minimumScope: "fine-grained PAT with Issues: Read and write on the target repo only (classic: public_repo, or repo for a private repo — no admin/workflow)",
    setup: "Create a fine-grained PAT scoped to the single client repo, Issues → Read and write; nothing else.",
  },
  jira: {
    envVars: ["JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"],
    minimumScope: "API token for a user whose project role can Create Issues in the target project only",
    setup: "Mint an Atlassian API token for a service user granted the Create-Issues permission on the one audit project.",
  },
  azure: {
    envVars: ["AZURE_ORG_URL", "AZURE_PROJECT", "AZURE_PAT"],
    minimumScope: "PAT with Work Items: Read & Write, scoped to the target project (no code/build/release scopes)",
    setup: "Create a project-scoped PAT with only Work Items → Read & Write.",
  },
};

// One-tracker intake sheet for the CLI's --auth-intake. References env-var NAMES; never reads or
// echoes a token value.
export function intakeDoc(kind: TrackerKind): string {
  const it = TRACKER_INTAKE[kind];
  return [
    `Auth intake — ${kind} (least-privilege)`,
    `  Minimum scope: ${it.minimumScope}`,
    `  Provision:     ${it.setup}`,
    `  Env vars:      ${it.envVars.join(", ")}`,
    `  The token is read from the environment only — never passed as a flag, logged, or serialized.`,
  ].join("\n");
}
