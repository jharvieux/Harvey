// TRUE NEGATIVE (N-HOST-HEADER-FIXED-ORIGIN, #135): the reset link is built from a fixed,
// allowlisted origin read from an env var set at deploy time — never from the request's Host
// header, so a spoofed Host can't redirect the token anywhere.
export function buildResetLink(token) {
  return `${process.env.NEXT_PUBLIC_SITE_URL}/reset?token=${token}`;
}
