import fs from 'node:fs';
import path from 'node:path';
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  // Fleet crypto (contact-message / mailbox-envelope) uses Node ESM `.js` specifiers
  // that map to `.ts` files. Webpack must rewrite those so the Encrypt/Decrypt tab
  // can CALL the hooks without forking crypto.
  webpack: (config, { webpack }) => {
    config.plugins.push(
      new webpack.NormalModuleReplacementPlugin(/\.js$/, (resource: { context?: string; request?: string }) => {
        const request = resource.request || '';
        const context = resource.context || '';
        if (!request.startsWith('.') || !request.endsWith('.js')) return;
        if (!context.includes(`${path.sep}src${path.sep}`)) return;
        const absJs = path.resolve(context, request);
        const absTs = absJs.replace(/\.js$/, '.ts');
        if (fs.existsSync(absTs)) {
          resource.request = request.replace(/\.js$/, '.ts');
        }
      }),
    );
    return config;
  },
};

export default nextConfig;
