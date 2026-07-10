// The safe counterpart to insecure.config.js (B12, #71) — same three config keys, hardened:
//   N-IMG-REMOTEPATTERNS-OK  — an explicit hostname allowlist (not a '**'/'*' wildcard).
//   N-PROD-SOURCEMAPS-OFF    — productionBrowserSourceMaps:false (also the absent-key default).
//   N-SERVERACTIONS-ORIGIN-OK— allowedOrigins pinned to an explicit host, no bare '*'.
// None of the three B12 config rules match these shapes.
module.exports = {
  productionBrowserSourceMaps: false,
  images: {
    remotePatterns: [{ protocol: "https", hostname: "images.example.com" }],
  },
  experimental: {
    serverActions: {
      allowedOrigins: ["app.example.com", "admin.example.com"],
    },
  },
};
