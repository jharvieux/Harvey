import "server-only";

// The HS256 verify secret, read from the environment in a server-only module (#586 fixture support).
// Guarded by import "server-only" so harvey-missing-server-only stays cleared — the custom-JWT admin
// routes import this constant instead of reading process.env directly, keeping their findings scoped
// to the authz shape under test.
export const JWT_SECRET = process.env.JWT_SECRET ?? "";
