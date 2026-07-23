/** @type {import('next').NextConfig} */
const nextConfig = {
  // The fixture must build hermetically for the live stand-up (`dynamic-validate --execute`):
  // a lint/type error in a deliberately-sloppy vuln route must not fail `next build`.
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: true },
};

module.exports = nextConfig;
