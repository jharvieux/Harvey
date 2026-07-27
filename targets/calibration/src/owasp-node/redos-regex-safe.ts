// N-REDOS-SAFE (negative for P-OWASP-NODE-REDOS): a single quantified group with no NESTED
// quantifier inside it is linear-time — catastrophic backtracking needs a repeated repetition,
// not one level. Included alongside an ordinary anchored regex with a top-level quantifier and
// no groups at all.
const REPEATED_WORD = /^(ab)+$/;

export function isRepeatedAb(input: string): boolean {
  return REPEATED_WORD.test(input);
}

const SIMPLE_EMAIL = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

export function isSimpleEmail(input: string): boolean {
  return SIMPLE_EMAIL.test(input);
}
