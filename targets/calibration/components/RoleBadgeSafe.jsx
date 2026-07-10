"use client";

// N-JWTDECODE-SERVER (NEGATIVE — must NOT be flagged): the role comes from a signature-verified
// server session passed in as a prop, not a client-side unverified decode. There is no jwtDecode()
// call, so harvey-jwt-decode-render has nothing to match.
export function RoleBadge({ session }) {
  return session.role === "admin" ? <AdminTools /> : <span>member</span>;
}
