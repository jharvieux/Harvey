// TRUE NEGATIVE (N-WEBSTORAGE-CSRF): a CSRF token is JS-readable by design — the client has to
// echo it back in a request header — so keeping it in localStorage is expected, not a leak. The
// key name starts with "csrf", which harvey-token-in-webstorage's name regex deliberately excludes.
export function persistCsrf(csrfToken) {
  localStorage.setItem("csrfToken", csrfToken);
}
