// PLANTED BUG (P-INSECURE-RANDOM): Math.random() (a non-cryptographic PRNG — predictable and
// seedable from observed outputs) generates a password-reset token. An attacker who can predict
// or brute-force Math.random()'s internal state can forge valid reset tokens and take over any
// account. harvey-insecure-random-token gates on the function name (contains "reset"/"token")
// to separate this from a non-security use like UI jitter (N-RANDOM-NONSEC).
export function generateResetToken() {
  return Math.random().toString(36).slice(2);
}
