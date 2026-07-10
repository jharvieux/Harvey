import crypto from "crypto";

// N-HMAC-KEY-ENV (NEGATIVE — must NOT be flagged): the HMAC key is read from the environment, not a
// committed literal. harvey-hmac-hardcoded-key fires only when the key argument is a string literal.
export function sign(payload) {
  return crypto.createHmac("sha256", process.env.HMAC_SIGNING_KEY).update(payload).digest("hex");
}
