import "server-only";

// TRUE NEGATIVE (N-SERVER-ONLY-PRESENT): reads the same kind of server secret, but guards the
// module with "import 'server-only'" first — harvey-missing-server-only's pattern-not-inside
// excludes any file with that import (a build-time error if it's ever pulled into a Client
// Component's bundle).
export function getApiSecret() {
  return process.env.INTERNAL_API_SECRET;
}
