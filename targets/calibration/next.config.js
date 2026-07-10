/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The `env` block inlines each value into the CLIENT bundle at build time.
  env: {
    // TRUE NEGATIVE (N-NEXTCONFIG-ENV-BENIGN): a non-secret build constant is safe to inline.
    APP_VERSION: process.env.APP_VERSION,
    // PLANTED BUG (P-NEXTCONFIG-ENV-SECRET): a service-role secret mapped through `env` is
    // inlined into browser-shipped JS — a full RLS-bypass key handed to every visitor. Semgrep
    // harvey-nextconfig-env-secret matches a secret-named key in the env block → high.
    SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
  },
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
