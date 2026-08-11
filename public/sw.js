// svrnty Service Worker — offline-first, local-first
//
// v2 (2026-08-11, Athena): fixes the "stuck on RESOLVING…" trap.
// The old v1 served the HTML document and build chunks CACHE-FIRST, so after a
// redeploy (new /_next chunk hashes) a returning browser kept serving the old
// cached shell, which then requested chunk hashes that no longer exist → the
// client bundle never loaded → React never hydrated → the page froze on the
// server-rendered "RESOLVING…" placeholder. Because sw.js itself never changed,
// the browser never saw a new worker, so the stale cache was frozen forever.
//
// Fix: the app shell (navigations) and versioned build assets are NETWORK-FIRST
// (always current when online; cached copy is only a last-known-good offline
// fallback). Truly-static assets (icons, manifest) stay cache-first. Bumping
// CACHE_NAME forces every existing browser to install this worker, and the
// activate handler then deletes the poisoned v1 cache.
const CACHE_NAME = 'svrnty-v2';

// Only genuinely-static, rarely-changing assets are pre-cached. The HTML
// document is deliberately NOT pre-cached — it must always come from the network
// so it references the current build's chunk hashes.
const STATIC_ASSETS = [
  '/manifest.json',
  '/icon-192.svg',
  '/icon-512.svg',
];

// Install: pre-cache the static shell and activate immediately.
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

// Activate: delete every cache that isn't the current version (purges poisoned
// v1), then take control of open clients so the fix applies without a full close.
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
      )
      .then(() => self.clients.claim())
  );
});

// network-first with cache write-through + offline fallback.
function networkFirst(request, fallbackToRoot) {
  return fetch(request)
    .then((response) => {
      if (response && response.ok) {
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
      }
      return response;
    })
    .catch(() =>
      caches.match(request).then((cached) => {
        if (cached) return cached;
        if (fallbackToRoot) return caches.match('/');
        return Response.error();
      })
    );
}

// cache-first with network fallback (for immutable, rarely-changing assets).
function cacheFirst(request) {
  return caches.match(request).then((cached) => {
    if (cached) return cached;
    return fetch(request).then((response) => {
      if (response && response.ok) {
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
      }
      return response;
    });
  });
}

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Only handle GETs; let the browser deal with everything else.
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  const accept = request.headers.get('accept') || '';
  const isNavigation = request.mode === 'navigate' || accept.includes('text/html');

  // App shell (HTML documents): NEVER serve a stale shell. This is the fix.
  if (isNavigation) {
    event.respondWith(networkFirst(request, /* fallbackToRoot */ true));
    return;
  }

  // Versioned build assets + API: network-first so a redeploy can never strand
  // a browser on dead chunk hashes; cached copy is an offline fallback only.
  if (url.pathname.startsWith('/_next/') || url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(request, /* fallbackToRoot */ false));
    return;
  }

  // Everything else (icons, manifest, misc static): cache-first.
  event.respondWith(cacheFirst(request));
});
