// middleware.ts — Route param-bearing profile/connect URLs to their PARAM-FREE shells.
//
// Node Zero G-D requires every served shell to be byte-stable so it can be content-addressed
// (one hash covers infinite URLs) and covered by the hash-CSP. A Next dynamic segment ([name],
// [code]) echoes its param into the RSC flight-data inline script, so /u/alice ≠ /u/bob in prod
// (KB#3220) — uncoverable. Fix: the profile and connect pages are STATIC /u and /c shells; this
// middleware rewrites the param-bearing URL to the param-free shell WITHOUT changing the browser
// URL (NextResponse.rewrite ≠ redirect), and the shell reads the slug/code client-side from
// window.location post-hydration. Every existing link keeps working; the served bytes are uniform.
//
// Keep this rewrite in lockstep with the signer-walk + SW-walk path-canon (Archie #142135): the
// SW verifies a navigation to /u/<name> by content-membership (SHA256(served) ∈ shell-set), which
// holds iff /u/<name> serves the byte-identical /u shell — which this rewrite guarantees.
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Single-segment paths that are NOT bare-name profiles (real routes / static files).
const RESERVED = new Set([
  '_next', 'api', 'c', 'u', 'msg', 'dev', 'favicon.ico', 'icon-192.svg',
  'manifest.json', 'sw.js', 'health', 'register', 'slug',
]);

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const segments = pathname.split('/').filter(Boolean);
  const url = request.nextUrl.clone();

  // /u/<name>[/...] → the param-free /u shell. Slug read client-side from window.location.
  if (segments.length >= 2 && segments[0] === 'u') {
    url.pathname = '/u';
    return NextResponse.rewrite(url);
  }

  // /c/<code>[/...] → the param-free /c shell. Code + #key read client-side (key never hits server).
  if (segments.length >= 2 && segments[0] === 'c') {
    url.pathname = '/c';
    return NextResponse.rewrite(url);
  }

  // Bare single-segment /<name> (friendly profile alias) → the same param-free /u shell.
  if (segments.length === 1) {
    const slug = segments[0];
    // Skip reserved routes and any path with a dot (file extensions).
    if (RESERVED.has(slug) || slug.includes('.')) return NextResponse.next();
    url.pathname = '/u';
    return NextResponse.rewrite(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
