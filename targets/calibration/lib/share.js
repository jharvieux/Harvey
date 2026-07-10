// PLANTED BUG (P-SIGNED-URL-TOKEN-SRC): a Supabase Storage signed-URL committed to source with
// its live `?token=` JWT still attached. The token grants time-boxed object access to anyone who
// reads the source/doc — it should never be committed. Value is FAKE. gitleaks jwt → review.
const SHARE_URL =
  "https://calibrationref01.supabase.co/storage/v1/object/sign/reports/q3.pdf?token=eyJhbGciOiJIUzI1NiJ9.eyJ1cmwiOiJyZXBvcnRzL3EzLnBkZiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.Kf3Zp7wV0nRtY8sLbUmEdHjGqAoIcPwZ1kYqXq3fFaK";

// NEGATIVE (N-SIGNED-URL-PLACEHOLDER): the same URL shape with the token angle-bracketed — a
// documentation placeholder, not a real JWT. The jwt rule does not match `<SIGNED_URL_TOKEN>`.
const SHARE_URL_TEMPLATE =
  "https://calibrationref01.supabase.co/storage/v1/object/sign/reports/q3.pdf?token=<SIGNED_URL_TOKEN>";

export function shareLinks() {
  return { live: SHARE_URL, template: SHARE_URL_TEMPLATE };
}
