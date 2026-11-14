// app/beacon-dev/[file]/route.ts: #822 (a)-Z2. Serves the dev-only rehearsal proving files from a dir the dev deploy mounts. See src/lib/beacon-dev-artifact-route.ts.
// In every build whose flag is not 'true' this answers 404 for every name; the flag reference below is the static one next.config.ts always defines.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { serveBeaconDevArtifact } from '@/lib/beacon-dev-artifact-route';

export const dynamic = 'force-dynamic';

export async function GET(_req: Request, ctx: { params: Promise<{ file: string }> }): Promise<Response> {
  const { file } = await ctx.params;
  const r = await serveBeaconDevArtifact({
    flag: process.env.NEXT_PUBLIC_BEACON_DEV_ARTIFACTS,
    dir: process.env.BEACON_DEV_ARTIFACT_DIR,
    file,
    read: async (p) => new Uint8Array(await readFile(p)),
    join: path.join,
  });
  if (r.status !== 200) return new Response(null, { status: 404 });
  return new Response(r.body, { status: 200, headers: r.headers });
}
