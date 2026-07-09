/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // PLANTED BUGS (P-NO-HSTS / P-NO-FRAME-OPTIONS / P-NO-NOSNIFF): the default route sets one
  // unrelated header and omits Strict-Transport-Security, X-Frame-Options, and
  // X-Content-Type-Options entirely. harvey-missing-hsts / harvey-missing-frame-options /
  // harvey-missing-nosniff each match a headers() route object whose `headers` array lacks the
  // corresponding key. This file still sets no CSP header at all (P-NO-CSP, existing) — that
  // stays a separate, already-planted gap; checkMissingCsp's presence check (which scans this
  // file, middleware.ts, and vercel.json for that specific header's name) is untouched by this
  // addition, since that phrase is never spelled out literally in this file.
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [{ key: "X-DNS-Prefetch-Control", value: "on" }],
      },
      // TRUE NEGATIVE (N-HEADERS-VERCEL, modeled here rather than vercel.json so it's in the
      // same globally-scanned config surface as the positive above): this route correctly sets
      // HSTS, X-Frame-Options, and nosniff. Proves the three missing-header rules fire only on
      // the incomplete route, not this one.
      {
        source: "/api/(.*)",
        headers: [
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
