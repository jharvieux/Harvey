// PLANTED BUG (P-URI-CREDS-NONPG): an SMTP connection URI with an inline password committed to
// source. Complements P-DB-URL-PASSWORD (a postgres:// URI) — the harvey-uri-credentials rule
// covers the non-database schemes (smtp/ftp/http). Value is FAKE. gitleaks → high.
const SMTP_URL = "smtp://mailer:S3ndM4ilPwZ9Qm2v@smtp.mailprovider.example.com:587";

// NEGATIVE (N-URI-CREDS-ENV): the same URI with the password sourced from an environment
// variable — no literal credential, so the rule's char class (which excludes ${ }) does not
// match. Cleared.
const SMTP_URL_SAFE = "smtp://mailer:${SMTP_PASSWORD}@smtp.mailprovider.example.com:587";

export function mailTransport() {
  return { url: SMTP_URL, safe: SMTP_URL_SAFE };
}
