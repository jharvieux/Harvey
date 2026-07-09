// simplify/id.ts — PLANTED (M6-P-UUID): a hand-rolled random-id string builder.
// The rubric expects /simplify to name `crypto.randomUUID()` (Node 14.17+/all evergreen
// browsers) instead of this Math.random()-based id generator (quality-extras.txt M6
// "HAND-ROLLED PRIMITIVES"). Note: this is also a *weaker* id — Math.random() isn't
// cryptographically secure — but the M6 rubric flags it for the reinvention, not as a security
// finding (that's M1's lane if the id is used as a security token).
export function generateId(length = 16): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < length; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}
