import https from "https";

// PLANTED BUG (P-TLS-VERIFY-DISABLED): rejectUnauthorized:false disables TLS certificate
// verification for this HTTPS agent — a man-in-the-middle can present ANY certificate
// (including a self-signed one) and every request through this agent trusts it silently.
export const insecureAgent = new https.Agent({ rejectUnauthorized: false });
