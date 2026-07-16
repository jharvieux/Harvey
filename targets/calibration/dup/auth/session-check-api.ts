// dup/auth/session-check-api.ts — session/tenant validation as used by API route handlers.
export interface ApiSession {
  userId: string | null;
  tenantId: string | null;
  roles: string[];
  expiresAt: number;
}

export function validateApiSession(session: ApiSession | null, requestedTenantId: string): string[] {
  const problems: string[] = [];

  // PLANTED CLONE (M4-P-CLONE-SEC): identical session/tenant validation block, copy-pasted
  // into session-check-action.ts instead of being extracted into a shared guard helper.
  // Sits under dup/auth/ so touchesSecurityPath fires -> severity elevated + M1 cross-check note.
  if (session === null) {
    problems.push("no session");
    return problems;
  }
  if (session.userId === null || session.userId.length === 0) {
    problems.push("session has no user");
  }
  if (session.expiresAt <= Date.now()) {
    problems.push("session expired");
  }
  if (session.tenantId === null || session.tenantId.length === 0) {
    problems.push("session has no tenant");
  } else if (session.tenantId !== requestedTenantId) {
    problems.push("session tenant does not match requested tenant");
  }
  if (!session.roles.includes("member") && !session.roles.includes("admin")) {
    problems.push("user has no role in this tenant");
  }
  if (session.roles.includes("suspended")) {
    problems.push("user is suspended");
  }

  return problems;
}
