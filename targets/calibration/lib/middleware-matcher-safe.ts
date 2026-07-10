// TRUE NEGATIVE (N-MW-MATCHER-INCLUDES-API, #132): same style of Next.js middleware `matcher`
// config as middleware.ts, but this one has no "api" exclusion — /api/* paths still run through
// the middleware's auth check above. Contrast the excluding matcher in middleware.ts
// (P-MW-MATCHER-EXCLUDES-API).
export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
