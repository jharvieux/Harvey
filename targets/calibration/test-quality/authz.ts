// M8 calibration fixture (#72 §M8) — the STRONG-test-covered source. See
// authz.strong.test.ts for the planted strong test (M8-N-STRONG).
export type Role = "admin" | "member";
export type Action = "read" | "delete";

export function canAccess(role: Role, action: Action): boolean {
  if (role === "admin") return true;
  return action === "read";
}
