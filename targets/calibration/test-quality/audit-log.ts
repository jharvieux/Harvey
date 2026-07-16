// M8 stub-check calibration fixture (#373) — the DELETION-SURVIVING pair's source. Covered
// only by audit-log.deletion-surviving.test.ts, which calls this but asserts nothing, so the
// covering suite still passes when this body is stubbed to `return undefined` (verified by an
// executed transpile-and-run in src/stub-check.test.ts). Contrast: discount.ts's weak test IS
// assertion-backed, so it does NOT survive deletion — weak-but-killable vs structurally dead.
export function logAuditEvent(event: string, userId: string): string {
  const entry = `${event}:${userId}`;
  auditTrail.push(entry);
  return entry;
}

export const auditTrail: string[] = [];
