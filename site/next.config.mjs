/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  webpack(config) {
    // Root scanner modules use Node ESM's emitted `.js` specifiers while their checked-in
    // sources are TypeScript. Keep the real JavaScript extension as the fallback so the same
    // imports work both before and after TypeScript emission.
    config.resolve.extensionAlias = {
      ...config.resolve.extensionAlias,
      ".js": [".ts", ".js"],
      ".jsx": [".tsx", ".jsx"],
      ".mjs": [".mts", ".mjs"],
      ".cjs": [".cts", ".cjs"],
    };
    return config;
  },
  async redirects() {
    return [
      // /intake served the #32 client-intake questionnaire out of intake-site/, which was orphaned
      // when this Vercel project's rootDirectory was repointed on 2026-07-22 — the path has 404ed
      // ever since (#1308). Whether that questionnaire is re-hosted, folded in here, or dropped is
      // an open product decision on #1308, so this is a STOPGAP, not the answer: 307 (temporary) so
      // nothing caches it and any of the three outcomes can replace it without fighting a
      // browser-pinned 308. Until then a visitor lands on the one live way to reach the venture
      // rather than a dead end.
      { source: "/intake", destination: "/#scan", permanent: false },
    ];
  },
};

export default nextConfig;
