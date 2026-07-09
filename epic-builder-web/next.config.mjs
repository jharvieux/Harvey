// The wrap layer imports the src/epic-builder + src/trackers core, which is NodeNext ESM authored
// with explicit ".js" specifiers that point at ".ts" sources. Teach webpack to resolve ".js" -> ".ts"
// so those imports (and the core's own internal ones) resolve into the real, unmodified source.
// ESLint during build is off — the root toolkit owns lint; this app is typechecked via `tsc`.

/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: { ignoreDuringBuilds: true },
  webpack: (config) => {
    config.resolve.extensionAlias = {
      ".js": [".ts", ".tsx", ".js", ".jsx"],
      ".jsx": [".tsx", ".jsx"],
    };
    return config;
  },
};

export default nextConfig;
