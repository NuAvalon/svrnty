// middleware.ts — Rewrite /username → /u/username for public profiles
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Routes that should NOT be rewritten to profile pages
const RESERVED = new Set([
  '_next', 'api', 'c', 'u', 'msg', 'favicon.ico', 'icon-192.svg',
  'manifest.json', 'sw.js', 'health', 'register', 'slug',
]);

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Only handle single-segment paths like /peter (not /api/foo or /c/abc)
  const segments = pathname.split('/').filter(Boolean);
  if (segments.length !== 1) return NextResponse.next();

  const slug = segments[0];

  // Skip reserved routes, static files, and paths with dots (file extensions)
  if (RESERVED.has(slug) || slug.includes('.')) return NextResponse.next();

  // Rewrite to the profile page
  const url = request.nextUrl.clone();
  url.pathname = `/u/${slug}`;
  return NextResponse.rewrite(url);
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
