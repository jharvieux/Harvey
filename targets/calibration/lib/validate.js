// N-REDOS-SAFE (NEGATIVE — must NOT be flagged): a linear-time email regex using negated
// character classes ([^\s@]). Sonar S5852 raises a ReDoS hotspot on any regex with multiple
// quantifiers, but this one cannot backtrack catastrophically. ReDoS stays out of the
// mechanical count (needs real backtracking analysis, not a quantifier count).
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isEmail(value) {
  return EMAIL.test(value);
}
