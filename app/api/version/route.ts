// app/api/version/route.ts
// Build provenance: reports the git commit / branch / build time baked into the image at
// build time (Dockerfile ARG -> ENV; the deploy pipeline passes --build-arg GIT_SHA /
// GIT_BRANCH / BUILD_TIME). Lets us tell exactly what's deployed on any instance.
// NuAvalon/svrnty is a PUBLIC repo, so the SHA/branch are non-secret and safe to expose.

import { NextResponse } from 'next/server';

// Read env at REQUEST time, not build time — the values must reflect the running image,
// not whatever was in scope when Next compiled. force-dynamic disables static rendering.
export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json({
    commit: process.env.BUILD_GIT_SHA ?? 'unknown',
    branch: process.env.BUILD_GIT_BRANCH ?? 'unknown',
    builtAt: process.env.BUILD_TIME ?? 'unknown',
    service: 'svrnty-frontend',
  });
}
