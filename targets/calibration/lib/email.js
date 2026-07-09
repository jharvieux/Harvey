// PLANTED BUG (P-SENDGRID-KEY): a hardcoded SendGrid API token. The VALUE is DEFANGED — a real
// SG.xxx.xxx trips GitHub push protection, so the committed literal is a pure high-entropy fake
// with the SG. prefix removed. gitleaks catches it via generic-api-key at review; the
// sendgrid-api-token pattern was validated on the real-shape value pre-commit (GROUND-TRUTH §B1).
const SENDGRID_API_KEY = "Yl4ZpQaWsEdRfTgYhUjIkOlPzXcVbNmZ9Qm2vXcW8rNp";

export function send(to, subject) {
  return fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: { authorization: `Bearer ${SENDGRID_API_KEY}` },
    body: JSON.stringify({ personalizations: [{ to: [{ email: to }] }], subject }),
  });
}
