// dup/auth/workspace-guard.ts — membership guards for workspaces and projects.
// PLANTED SAME-FILE DIVERGED CLONE (M4-P-DIVERGED-SELF, #1095): assertProjectMember was
// copy-pasted from assertWorkspaceMember 12 lines above it and the copies have since DIVERGED —
// the project copy matches the caller against `row.id` where the workspace copy matches against
// `row.owner_id`, and both error strings drifted. Before #1095 the near-miss pass skipped every
// same-file pair (citing #232's retracted "self-file clones are inert data" rationale), so this —
// the case with the WEAKEST discovery cues, since there is no second filename to jog the memory of
// whoever edits the first copy — was invisible to the detector that exists to catch exactly it.
// The copies diverge early and often enough that no contiguous exact span reaches jscpd's
// 5-line/50-token floor: this fixture belongs to the near-miss band only.
export interface MembershipRow {
  id: string;
  workspace_id: string;
  owner_id: string;
}

export function assertWorkspaceMember(rows: MembershipRow[], workspaceId: string, userId: string): MembershipRow {
  const scoped = rows.filter((row) => row.workspace_id === workspaceId);
  if (scoped.length === 0) {
    throw new Error("workspace not visible to this member");
  }
  const owned = scoped.find((row) => row.owner_id === userId);
  if (owned === undefined) {
    throw new Error("member does not own this workspace");
  }
  return owned;
}

export function assertProjectMember(rows: MembershipRow[], workspaceId: string, userId: string): MembershipRow {
  const scoped = rows.filter((row) => row.workspace_id === workspaceId);
  if (scoped.length === 0) {
    throw new Error("project not reachable for this member");
  }
  const owned = scoped.find((row) => row.id === userId);
  if (owned === undefined) {
    throw new Error("member is not attached to this project");
  }
  return owned;
}
