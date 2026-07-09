import https from "https";

// N-TLS-VERIFY-ON (NEGATIVE — must NOT be flagged): the default HTTPS agent, no override — TLS
// certificate verification stays on (rejectUnauthorized defaults to true). harvey-tls-verify-
// disabled only matches an explicit `rejectUnauthorized: false` (or NODE_TLS_REJECT_UNAUTHORIZED
// =0). (Named http-safe.js, not the spec's lib/http.js, to avoid a location collision with
// P-TLS-VERIFY-DISABLED's fixture already in lib/http.js.)
export const defaultAgent = new https.Agent();
