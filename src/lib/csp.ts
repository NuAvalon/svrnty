// The script lock. middleware.ts sets this policy on every page response and hands the nonce
// to the render through a request header, so the header and the HTML always come from the same
// process: there is no list of hashes to keep in step with a build.
//
// It stops injected script. It does not stop a compromised server or a malicious build (the
// header comes from the server too), it does not limit where data can be sent (connect-src is
// left open on purpose for now), and script gadgets in our own trusted code can still run.
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
    `script-src ${script.join(' ')}`,
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; ');
}
