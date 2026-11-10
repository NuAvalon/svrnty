// The script lock. middleware.ts sets this policy on every page response and hands the nonce
// to the render through a request header, so the header and the HTML always come from the same
// process: there is no list of hashes to keep in step with a build.
//
// It stops injected script, and keeps a script that does run from loading from or sending to
// any other origin through fetch, images, fonts, styles, media or frames. What it does not stop:
// - a compromised server or a malicious build: the header comes from the server too;
// - data leaving through this origin: 'self' includes our public relay, which takes a deposit
//   from anyone, so a script written for this app can leave data there for its author;
// - navigation, WebRTC and DNS prefetch, which no directive here governs;
// - a same-origin response with no policy (the JSON routes): a script can open one in a new
//   window and send from there;
// - anything the edge adds to the page with its nonce, which runs and can report to this origin;
// - script gadgets in our own trusted code.
// Never describe this policy as keeping data from leaving.
//
// connect-src is exactly 'self'. Cloud backup and moving to another relay will each need more,
// and each is its own decision when it is wired: an allow-listed storage API can be used with
// an attacker's token, and an arbitrary relay host is a place to send anything.
//
// The PSI prover uses WebAssembly, so wiring it will need 'wasm-unsafe-eval'. Add it then.

/** 128 bits from the platform CSPRNG. Runs in the Edge runtime, so no Node APIs. */
export function makeScriptNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * `dev` is for `next dev` only, whose client code needs eval. Never true in a production build.
 * No 'strict-dynamic': Next's chunks are same-origin, and it would let a trusted script load
 * more script from anywhere.
 */
export function buildCsp(nonce: string, opts: { dev: boolean }): string {
  const script = ["'self'", `'nonce-${nonce}'`];
  if (opts.dev) script.push("'unsafe-eval'");
  return [
    "default-src 'self'",
    `script-src ${script.join(' ')}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "media-src 'self' blob:",
    "connect-src 'self'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; ');
}
