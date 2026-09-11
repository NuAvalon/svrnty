import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    // Blocker-E: the production build now type-checks honestly (no more "green that lies").
    // Uses the build-only tsconfig, which excludes tests/e2e (checked separately) so the build
    // type-checks shipping code only.
    ignoreBuildErrors: false,
    tsconfigPath: 'tsconfig.build.json',
  },
};

export default nextConfig;
