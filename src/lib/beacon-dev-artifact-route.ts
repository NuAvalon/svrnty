// src/lib/beacon-dev-artifact-route.ts: #822 (a)-Z2. The decision for the dev-only proving-file route, pure so it is unit-tested with an injected reader. DARK.
//
// The dev deploy serves the two rehearsal proving files from its own app, not from public/ (a production build copies public/) and not from the shared edge. This
// function says what to answer; app/beacon-dev/[file]/route.ts adapts it to Next and passes the STATIC flag, so a production build, whose flag is the empty string, compiles
// to a handler that always answers 404.
//
// Only the two exact names below are ever read. The name is looked up as an OWN property of a fixed table (never used as a path on its own), so '..', encoded
// traversal, a trailing slash, another case, '__proto__' or 'constructor' are all a plain 404 and the reader is never called.

export interface ArtifactServeInput {
  /** NEXT_PUBLIC_BEACON_DEV_ARTIFACTS as inlined at build time: 'true' only in a dev build that opted in (see beacon-dev-flag.ts). */
  flag: string | undefined;
  /** BEACON_DEV_ARTIFACT_DIR: a server-side dir mounted by the dev deploy. Unset = nothing to serve. */
  dir: string | undefined;
  /** The raw name from the URL. */
  file: string;
  /** Reads a file by absolute path. Injected so the tests need no disk. */
  read: (absPath: string) => Promise<Uint8Array>;
  join: (dir: string, name: string) => string;
}

export type ArtifactServeResult =
  | { status: 404 }
  | { status: 200; body: Uint8Array; headers: Record<string, string> };

const TYPES: Readonly<Record<string, string>> = Object.freeze({
  'slotbind.wasm': 'application/wasm',
  'final.zkey': 'application/octet-stream',
});

const NOT_FOUND: ArtifactServeResult = { status: 404 };

export async function serveBeaconDevArtifact(i: ArtifactServeInput): Promise<ArtifactServeResult> {
  if (i.flag !== 'true') return NOT_FOUND;
  if (typeof i.dir !== 'string' || i.dir.length === 0) return NOT_FOUND;
  if (typeof i.file !== 'string' || !Object.prototype.hasOwnProperty.call(TYPES, i.file)) return NOT_FOUND;
  try {
    const body = await i.read(i.join(i.dir, i.file));
    if (!(body instanceof Uint8Array)) return NOT_FOUND;
    return {
      status: 200,
      body,
      headers: { 'content-type': TYPES[i.file], 'content-length': String(body.length), 'cache-control': 'no-store' },
    };
  } catch {
    return NOT_FOUND; // never echo a path or an error
  }
}
