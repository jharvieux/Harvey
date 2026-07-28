/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
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
