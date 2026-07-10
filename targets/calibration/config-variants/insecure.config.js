// A second, standalone next-config-shaped fixture (B12, #71). Named off the `next.config.*`
// pattern on purpose so checkMissingCsp's presence check (which keys off the exact filenames
// next.config.js/.mjs/.ts) never picks it up — it exists only as a Semgrep scan surface for the
// three config-misconfig classes, whose safe counterparts live in hardened.config.js.
//
// PLANTED BUGS:
//   P-IMG-REMOTEPATTERNS-WILD — images.remotePatterns hostname '**' turns next/image into an
//     open image proxy / SSRF fetcher for any host. Semgrep harvey-img-remotepatterns-wild → high.
//   P-PROD-SOURCEMAPS — productionBrowserSourceMaps:true ships readable original source to every
//     browser. Semgrep harvey-prod-sourcemaps → high.
//   P-SERVERACTIONS-ORIGIN-WILD — experimental.serverActions.allowedOrigins ['*'] disables the
//     Server Actions origin allowlist (CSRF). Semgrep harvey-serveractions-origin-wild → high.
module.exports = {
  productionBrowserSourceMaps: true,
  images: {
    remotePatterns: [{ protocol: "https", hostname: "**" }],
  },
  experimental: {
    serverActions: {
      allowedOrigins: ["*"],
    },
  },
};
