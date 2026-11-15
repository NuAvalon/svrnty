// e2e/helpers/relay-precheck.ts
// A spec that deposits through the app's own relay fails with a misleading "not delivered" when the relay refuses for a reason outside the
// spec: the deposit route answers 429 "Relay storage full." for EVERY deposit while the data filesystem is above RELAY_DISK_WATERMARK_PCT
// (default 80), and it answers BEFORE it reads the body. So an empty POST tells us, without depositing anything, whether this box will
// refuse. Call it first in any spec that needs a deposit to land, so the failure names the cause instead of a missing contact or message.

const ROUTE = '/api/relay/envelope';

export async function assertRelayAcceptsDeposits(baseURL: string | undefined): Promise<void> {
  if (!baseURL) throw new Error('relay pre-check needs the Playwright baseURL (use the `baseURL` test fixture)');
  const res = await fetch(new URL(ROUTE, baseURL), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  const text = await res.text();
  if (res.status === 429 && /relay storage full/i.test(text)) {
    throw new Error(
      'relay over watermark: the relay refuses every deposit while the disk is above RELAY_DISK_WATERMARK_PCT (default 80). ' +
        'Set RELAY_DISK_WATERMARK_PCT=100 on the relay server for local runs, then run again.',
    );
  }
}
