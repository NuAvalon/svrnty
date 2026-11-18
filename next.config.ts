import fs from 'node:fs';
import path from 'node:path';
import type { NextConfig } from 'next';
import { beaconDevArtifactsFlag } from './src/lib/beacon-dev-flag';

const nextConfig: NextConfig = {
  // #822 (a)-Z: ALWAYS defined ('true' only in a dev build that opted in to the beacon wire), so the bundler can drop the dev-only proving-key pin from every other build.
  // See src/lib/beacon-dev-flag.ts for why an unset NEXT_PUBLIC_ variable is not enough.
  env: {
    NEXT_PUBLIC_BEACON_DEV_ARTIFACTS: beaconDevArtifactsFlag(process.env),
  },
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
