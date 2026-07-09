// N-RANDOM-NONSEC (NEGATIVE — must NOT be flagged): Math.random() used for a UI stagger delay,
// not a security-sensitive value. harvey-insecure-random-token only fires inside a function
// whose name signals token/secret/session/otp/password/reset — this function's name doesn't
// match, so it stays silent.
export function jitterDelay() {
  return Math.random() * 100;
}
