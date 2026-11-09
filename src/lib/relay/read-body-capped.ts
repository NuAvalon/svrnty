// src/lib/relay/read-body-capped.ts
// Read a request body, stopping as soon as it passes the cap. A chunked body has no Content-Length, so checking that header can't bound it.

/** The body bytes, or null if it went over `cap`. The stream is cancelled at that point, so the rest is never read. */
export async function readBodyCapped(request: Request, cap: number): Promise<Uint8Array | null> {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.byteLength; }
  return out;
}
