// src/sw/sw-source.ts
// Node Zero G-D service worker — the fetch-handler assembly. esbuild bundles THIS + its imports (incl @noble
// crypto) into public/sw.js. It EXTENDS the existing network-first/anti-stale/offline sw.js (whose RESOLVING-trap
// fix is load-bearing — preserved verbatim in spirit: navigations + /_next/ + /api stay network-first, static
// stays cache-first, activate purges old caches, skipWaiting + clients.claim) and adds publisher VERIFICATION:
//
//   • VERIFY-BEFORE-SERVE (Archie precondition): a response's bytes are hashed and checked BEFORE respondWith
//     hands them to the browser — never verify-after-execute (that loses the inline-script race).
//   • STATIC assets → exact-path SRI (verifyAsset over the accepted manifest).
//   • NAVIGATIONS → shell content-hash MEMBERSHIP (verifyShell — one hash covers infinite /u/<name> paths).
//   • ADOPT-UPDATE on a signed release (epoch-0 sig + manifest⇄bundle_hash + counter>HWM) — on activate + lazily
//     when a served asset/shell isn't in the current accepted set (could be a legit new release).
//   • §3 WARN-NEVER-BRICK: on mismatch, WARN + markDiverged + serve last-known-good; one-time proceed is
//     session-scoped. EXPORT paths bypass the gate entirely (anti-hostage).
//   • F2 (Flint): a size cap on buffered bytes before SHA256 (memory-blowup defense).
//
// TCB: this file is itself a signed manifest entry (Q8 self-inclusion) — a swapped sw.js fails its own SRI.

import { verifyAsset, verifyShell, shellHashSet, adoptUpdate, loadAcceptedManifest, type AssetVerdict } from './gd-verify-flow.js';
import { classifyRequest, manifestPath } from './gd-pathname.js';
import { parseDeliveredRelease } from './gd-delivery.js';
import { bootstrapPin } from './gd-bootstrap.js';
import { readPin, markDiverged } from './gd-pin-store.js';
import { broadcastWarn, proceedGrantedThisSession, grantOneTimeProceed, configureExportPaths, isExportPath } from './gd-warn.js';

// SW globals typed locally (the repo tsconfig is DOM-lib; avoid a webworker-lib conflict). caches/fetch/Response/
// Request/URL/TextDecoder/JSON come from the DOM lib and are available.
interface ExtendableEventLike { waitUntil(p: Promise<unknown>): void }
interface FetchEventLike { request: Request; respondWith(r: Response | Promise<Response>): void }
interface MessageEventLike { data: unknown }
interface SWGlobal {
  location: { origin: string };
  skipWaiting(): void;
  clients: { claim(): Promise<void> };
  addEventListener(type: 'install' | 'activate', listener: (event: ExtendableEventLike) => void): void;
  addEventListener(type: 'fetch', listener: (event: FetchEventLike) => void): void;
  addEventListener(type: 'message', listener: (event: MessageEventLike) => void): void;
}
declare const self: unknown;
const sw = self as SWGlobal;

const CACHE_NAME = 'svrnty-v3-nodezero'; // bump from v2 → forces install of this worker + purges the v2 cache
const RELEASE_URL = '/.well-known/svrnty/release.json';
const MAX_VERIFY_BYTES = 8 * 1024 * 1024; // F2 cap for buffered bytes before SHA256
const ORIGIN = sw.location.origin;

// Genuinely-static, rarely-changing assets pre-cached (existing set). The HTML shell is deliberately NOT
// pre-cached (it must come from network to reference the current build's chunk hashes — the RESOLVING-trap fix).
const STATIC_ASSETS = ['/manifest.json', '/icon-192.svg', '/icon-512.svg'];

// EXPORT paths (anti-hostage): the user's own data export must serve regardless of verify/diverged state.
// Supplied explicitly (never guessed) so the bypass can't silently miss a route or over-broadly skip verify.
configureExportPaths(['/api/contacts/export', '/api/contacts/secure-export', '/api/keys/export']);

// ── in-SW memoized verify state (ephemeral: reloaded after a SW restart / on adopt) ────────────────────────
let _accepted: Map<string, string> | null = null;
let _shells: Set<string> | null = null;
async function getAccepted(force = false): Promise<Map<string, string> | null> {
  if (force || _accepted === null) {
    _accepted = await loadAcceptedManifest();
    _shells = _accepted ? shellHashSet(_accepted) : null;
  }
  return _accepted;
}
async function getShells(force = false): Promise<Set<string>> {
  await getAccepted(force);
  return _shells ?? new Set<string>();
}

// ── size-capped buffering (F2) ─────────────────────────────────────────────────────────────────────────────
async function cappedBytes(resp: Response): Promise<Uint8Array | null> {
  const declared = Number(resp.headers.get('content-length') || '0');
  if (declared && declared > MAX_VERIFY_BYTES) return null; // declared too big → refuse to buffer/verify
  const buf = new Uint8Array(await resp.arrayBuffer());
  return buf.length > MAX_VERIFY_BYTES ? null : buf;
}

function cachePut(request: Request, resp: Response): void {
  caches.open(CACHE_NAME).then((c) => c.put(request, resp)).catch(() => {});
}

// ── ADOPT-UPDATE: fetch the signed release + inline manifest, verify, advance the accepted set ──────────────
let _adoptInFlight: Promise<boolean> | null = null;
function tryAdopt(): Promise<boolean> {
  if (_adoptInFlight) return _adoptInFlight;
  _adoptInFlight = (async () => {
    try {
      const resp = await fetch(RELEASE_URL, { cache: 'no-store' });
      if (!resp.ok) return false;
      const bytes = await cappedBytes(resp);
      if (!bytes) return false;
      let json: unknown;
      try {
        json = JSON.parse(new TextDecoder().decode(bytes));
      } catch {
        return false;
      }
      const parsed = parseDeliveredRelease(json);
      if (!parsed.ok) {
        await broadcastWarn({ kind: 'verify-fail', reason: `invalid release delivery: ${parsed.error}` });
        return false;
      }
      // first-install TOFU bootstrap from the genesis block, if no pin exists yet.
      if (!(await readPin()) && parsed.genesis) await bootstrapPin(parsed.genesis);
      const res = await adoptUpdate(parsed.release, parsed.releasePublisherFp, parsed.manifestBytes);
      if (res.adopted) {
        await getAccepted(true); // refresh the in-SW accepted/shell state
        return true;
      }
      return false;
    } catch {
      return false;
    } finally {
      _adoptInFlight = null;
    }
  })();
  return _adoptInFlight;
}

// ── §3 WARN-never-brick disposition ────────────────────────────────────────────────────────────────────────
async function warnAndDiverge(reason: string, path: string): Promise<void> {
  await broadcastWarn({ kind: 'asset-mismatch', reason, path });
  await markDiverged();
}
/**
 * Never-brick disposition after a WARN. Prefer the last VERIFIED cached copy; if the user granted a one-time
 * proceed this session, serve the fresh (unverified) bytes; if there is no cached good copy AND no proceed, still
 * serve fresh-unverified rather than a blank brick (the WARN has fired). SEAM: the first-load-already-tampered
 * ceremony (serve a WARN interstitial instead of the bad shell) is Flint's §3 spec — wired via broadcastWarn to
 * any existing client; a from-scratch interstitial page belongs to that spec.
 */
async function servePreferCached(request: Request, freshUnverified: Response): Promise<Response> {
  if (proceedGrantedThisSession()) return freshUnverified;
  const cached = await caches.match(request);
  return cached || freshUnverified;
}

// §3 WARN INTERSTITIAL — a SW-SYNTHETIC navigation Response served when a shell can't be verified and there is no
// verified last-good copy (offline, or first-load-already-tampered). It NEVER passes through Caddy, so it carries
// its OWN tight CSP set on the Response (Flint #142097): the inline proceed-script's sha256 is computed here and
// placed in THIS response's script-src — the Caddy edge union never sees it. The button posts NODEZERO_PROCEED
// (session-scoped one-time) + reloads → the next fetch serves the fresh (now proceed-granted) bytes.
const PROCEED_SCRIPT =
  "document.getElementById('nz-p').addEventListener('click',function(){navigator.serviceWorker.controller&&navigator.serviceWorker.controller.postMessage({type:'NODEZERO_PROCEED'});setTimeout(function(){location.reload()},150)});";

async function sha256Base64(s: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
  let bin = '';
  for (let i = 0; i < digest.length; i++) bin += String.fromCharCode(digest[i]);
  return btoa(bin);
}

async function warnInterstitial(): Promise<Response> {
  const csp = `default-src 'self'; script-src 'sha256-${await sha256Base64(PROCEED_SCRIPT)}'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`;
  const html =
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>Could not verify — svrnty</title></head>' +
    '<body style="font-family:system-ui,sans-serif;max-width:38rem;margin:10vh auto;padding:0 1.25rem;line-height:1.55;color:#e8e8e8;background:#111">' +
    '<h1 style="font-size:1.35rem">⚠ This page could not be verified</h1>' +
    '<p>The code served for this page does not match what the publisher signed. This can mean the network or the server is compromised. ' +
    '<strong>Proceeding runs unverified code — it does not make it safe.</strong></p>' +
    '<p style="opacity:.8">Your saved data is not exposed by staying here. If you did not expect this, close the tab.</p>' +
    '<button id="nz-p" style="margin-top:1rem;padding:.6rem 1rem;font:inherit;cursor:pointer">Proceed anyway (this session only)</button>' +
    '<script>' + PROCEED_SCRIPT + '</script></body></html>';
  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': csp,
    },
  });
}

/**
 * A cached shell, returned ONLY if its bytes still verify against the pin-bound shell-set (a poisoned Cache-API
 * entry is rejected — Flint #142077 offline-shell close). Tries the exact request, then the root shell, as the
 * offline last-known-good.
 */
async function verifiedCachedShell(request: Request): Promise<Response | null> {
  const shells = await getShells();
  for (const key of [request, '/'] as const) {
    const cached = await caches.match(key);
    if (!cached) continue;
    const cb = await cappedBytes(cached.clone());
    if (cb && verifyShell(shells, cb) === 'ok') return cached;
  }
  return null;
}

// ── verify-before-serve: STATIC (exact-path SRI) ───────────────────────────────────────────────────────────
async function verifyStaticOnce(path: string, bytes: Uint8Array): Promise<AssetVerdict | 'no-manifest'> {
  const accepted = await getAccepted();
  if (!accepted) return 'no-manifest';
  return verifyAsset(accepted, path, bytes);
}
async function handleStatic(request: Request, url: URL): Promise<Response> {
  let resp: Response;
  try {
    resp = await fetch(request);
  } catch {
    // OFFLINE: re-verify the cached asset vs the pin-bound accepted-map; serve if ok, else WARN + serve-anyway
    // (defense-in-depth behind the shell-closure — never brick a legit stale chunk after the accepted-map advanced).
    const cached = await caches.match(request);
    if (!cached) return Response.error();
    const p = manifestPath(request.url, ORIGIN);
    const cb = await cappedBytes(cached.clone());
    if (p && cb && (await verifyStaticOnce(p, cb)) !== 'ok') await warnAndDiverge('offline: cached asset failed re-verify', p);
    return cached;
  }
  if (!resp.ok) return resp; // 404 etc — not a verify target
  const bytes = await cappedBytes(resp.clone());
  const path = manifestPath(request.url, ORIGIN);
  if (bytes === null || path === null) {
    await warnAndDiverge('static asset unverifiable (too large / cross-origin)', url.pathname);
    return servePreferCached(request, resp);
  }
  let verdict = await verifyStaticOnce(path, bytes);
  if (verdict !== 'ok' && (await tryAdopt())) verdict = await verifyStaticOnce(path, bytes); // maybe a new release
  if (verdict === 'ok') {
    cachePut(request, resp.clone());
    return resp;
  }
  await warnAndDiverge(verdict === 'mismatch' ? 'static asset hash mismatch' : 'static asset not in signed manifest', path);
  return servePreferCached(request, resp);
}

// ── verify-before-serve: NAVIGATION (shell content-hash membership) ────────────────────────────────────────
async function handleShell(request: Request): Promise<Response> {
  let resp: Response;
  try {
    resp = await fetch(request);
  } catch {
    // OFFLINE: serve a RE-VERIFIED cached shell, else the §3 WARN interstitial (never a poisoned or blank shell).
    return (await verifiedCachedShell(request)) ?? warnInterstitial();
  }
  if (!resp.ok) return resp;
  const bytes = await cappedBytes(resp.clone());
  const path = new URL(request.url).pathname;
  if (bytes !== null) {
    let ok = verifyShell(await getShells(), bytes) === 'ok';
    if (!ok && (await tryAdopt())) ok = verifyShell(await getShells(true), bytes) === 'ok';
    if (ok) {
      cachePut(request, resp.clone());
      return resp;
    }
  }
  // Served shell is unverified (mismatch, or too large to buffer). §3 CLOSE-the-shell-window: WARN, then honour a
  // one-time proceed (serve fresh) else a RE-VERIFIED cached shell else the WARN interstitial — never run
  // whole-app unverified code by default, never blank-brick.
  await warnAndDiverge('served shell is not in the signed publisher set', path);
  if (proceedGrantedThisSession()) return resp;
  return (await verifiedCachedShell(request)) ?? warnInterstitial();
}

// ── dynamic / export passthrough (no verify; preserves network-first + offline) ────────────────────────────
async function passthrough(request: Request, navFallback = false): Promise<Response> {
  try {
    const r = await fetch(request);
    if (r.ok) cachePut(request, r.clone());
    return r;
  } catch {
    const c = await caches.match(request);
    if (c) return c;
    return navFallback ? (await caches.match('/')) || Response.error() : Response.error();
  }
}

// ── lifecycle (preserves the existing install/activate contract) ───────────────────────────────────────────
sw.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((c) => c.addAll(STATIC_ASSETS)).catch(() => undefined));
  sw.skipWaiting();
});
sw.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)));
      await sw.clients.claim();
      await getAccepted(true); // warm the verify state
      void tryAdopt(); // opportunistically pick up the latest signed release
    })(),
  );
});
sw.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return; // let the browser handle non-GET
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return;
  }
  if (url.origin !== ORIGIN) return; // cross-origin → not ours
  if (isExportPath(url)) {
    event.respondWith(passthrough(request)); // anti-hostage: never gated
    return;
  }
  const isNav = request.mode === 'navigate' || (request.headers.get('accept') || '').includes('text/html');
  const cls = classifyRequest(request.url, ORIGIN, isNav);
  if (cls === 'dynamic') {
    event.respondWith(passthrough(request, isNav));
    return;
  }
  event.respondWith(cls === 'shell' ? handleShell(request) : handleStatic(request, url));
});

// One-time "proceed anyway" from the WARN UI (session-scoped; never persisted; the pin stays diverged + re-warns).
sw.addEventListener('message', (event) => {
  const d = event.data as { type?: string } | null;
  if (d && d.type === 'NODEZERO_PROCEED') grantOneTimeProceed();
});
