// next.config.ts
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Ensure crypto APIs are available in the browser
  webpack: (config, { isServer }) => {
    if (!isServer) {
      // Ensure crypto polyfills are available for browser
      config.resolve.fallback = {
        ...config.resolve.fallback,
        crypto: false, // Use the browser's built-in crypto
        stream: false,
        util: false,
        fs: false,
        path: false,
      };
    }

    // Optimize chunk splitting for dynamic imports
    config.optimization = {
      ...config.optimization,
      splitChunks: {
        ...config.optimization.splitChunks,
        chunks: 'all',
        cacheGroups: {
          ...config.optimization.splitChunks?.cacheGroups,
          openpgp: {
            test: /[\\/]node_modules[\\/]openpgp[\\/]/,
            name: 'openpgp',
            chunks: 'all',
            priority: 20,
          },
        },
      },
    };

    return config;
  },
  
  // Enable experimental features for better client-side handling
  experimental: {
    esmExternals: 'loose',
  },
  
  // Ensure proper module resolution
  transpilePackages: ['openpgp'],
  
  // Disable SSR for pages that use crypto
  env: {
    DISABLE_SSR_CRYPTO: 'true',
  },
};

export default nextConfig;