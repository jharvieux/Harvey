"use client";
import { jwtDecode } from "jwt-decode";

// PLANTED BUG (P-JWT-DECODE-RENDER): jwtDecode() reads the token's claims WITHOUT verifying the
// signature, and the `role` claim drives what the client renders (an admin control). Anyone can
// forge a token with `role: "admin"` (no signing key needed) and unlock the UI — authz must come
// from a signature-verified server session, never a client-side decode. harvey-jwt-decode-render
// matches a jwtDecode()/jwt_decode() call (adjacent to harvey-jwt-decode-noverify, which covers the
// server-side jwt.decode()).
export function RoleBadge({ token }) {
  const { role } = jwtDecode(token);
  return role === "admin" ? <AdminTools /> : <span>member</span>;
}
