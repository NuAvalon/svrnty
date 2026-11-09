// middleware.ts — Rewrite /:name → /u/:name.
// There is no public directory; the page says so. Reserved names stay put.
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { buildCsp, makeScriptNonce } from './src/lib/csp';

// Routes that should NOT be rewritten to profile pages
const RESERVED = new Set([
  '_next', 'api', 'c', 'u', 'msg', 'favicon.ico', 'icon-192.svg',
  'manifest.json', 'sw.js', 'health', 'register', 'slug',
]);

function route(request: NextRequest, headers: Headers): NextResponse {
  const { pathname } = request.nextUrl;

  // Only handle single-segment paths like /alice (not /api/foo or /c/abc)
  const segments = pathname.split('/').filter(Boolean);
  if (segments.length !== 1) return NextResponse.next({ request: { headers } });

  const slug = segments[0];

  // Skip reserved routes, static files, and paths with dots (file extensions)
  if (RESERVED.has(slug) || slug.includes('.')) return NextResponse.next({ request: { headers } });

  // Rewrite to the profile page
  const url = request.nextUrl.clone();
  url.pathname = `/u/${slug}`;
  return NextResponse.rewrite(url, { request: { headers } });
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  // API routes and Next's internals are not pages, so they need no policy and no nonce.
  if (pathname === '/api' || pathname.startsWith('/api/') || pathname.startsWith('/_next/')) {
    return NextResponse.next();
  }

  // A new nonce for every response. set() replaces anything the client sent under these names.
  // Next reads the nonce for its own scripts from the policy on the request; app/layout.tsx reads x-nonce.
  const nonce = makeScriptNonce();
  const csp = buildCsp(nonce, { dev: process.env.NODE_ENV === 'development' });
  const headers = new Headers(request.headers);
  headers.set('x-nonce', nonce);
  // The layout can't see the path otherwise. set() replaces anything the client sent.
  headers.set('x-svrnty-path', pathname);
  headers.set('content-security-policy', csp);

  const response = route(request, headers);
  response.headers.set('content-security-policy', csp);
  return response;
}

export const config = {
  // api/relay is excluded because Next reads a matched request's whole body before the route runs, which would defeat the deposit route's own byte cap.
  matcher: ['/((?!_next/static|_next/image|favicon.ico|api/relay).*)'],
};
