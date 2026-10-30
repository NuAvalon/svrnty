/**
 * Inbound distress / VivreBurn paint gate.
 *
 * FALSE: the distress emit-path is not wired. Painting a mark now would be a
 * false life-safety claim (Flint). Re-enable is Flint-reviewed — flip WITH a
 * real received signal, never a placeholder.
 *
 * Do not gut VivreBurn / StarEmber / the galaxy. Gate the PAINT only.
 */
export function isInboundDistressPaintLive(): boolean {
  return false;
}

/** Visual distress only. Call sites still read contactHasDistress; paint no-ops until the flip. */
export function paintInboundDistress(hasMark: boolean): boolean {
  return isInboundDistressPaintLive() && hasMark;
}
