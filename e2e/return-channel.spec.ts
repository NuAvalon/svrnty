import { test, expect, type APIRequestContext } from '@playwright/test';

// Return-channel custody gate — I-1/I-4 timing + functional (Flint · s919 · Peter #116192 §1, joint §8).
// Drop-in for `e2e/return-channel.spec.ts`. Gates Athena's mailbox/poll/ack build: the relay may gain a
// mailbox + poll + ack WITHOUT becoming smart about the social graph. Grounded in
// shared/outbox/archie/svrnty_return_channel_joint_design.md §2/§4/§5/§8 + criteria doc + KB #86227.
//
// TEST-FIRST: it self-skips LOUDLY until the endpoints exist (a not-yet-run gate is NOT a passing one).
// The NON-owner anti-oracle half (B/C/E) activates as soon as the endpoints land — it needs no owner key,
// and it is the load-bearing I-4 property. The owner-dependent functional half (A) activates once the
// owner-auth seam (§4.1) is wired. The statistical latency test (B2) is on-demand (RC_TIMING=1), never a
// flaky always-on CI gate (ci.yml: "a flaky gate is worse than a narrow one"). Nothing here authorizes deploy.

// ── SEAM CONSTANTS (joint §7) — confirm exact shapes with Athena; the gate asserts PROPERTIES, only these bind to wire ──
const DEPOSIT = '/api/relay/envelope';        // POST {mailbox_id, blob} → uniform ack
const QUEUE = '/api/relay/queue';             // GET ?mailbox_id=… → owner-only, non-destructive list
const ACK = '/api/relay/ack';                 // POST {mailbox_id, envelope_ids[], owner_ack} → owner-only delete
const OPAQUE_BLOB = 'AAAA';                    // opaque base64-ish payload; the relay must never read it

// Deterministic distinct mailbox ids for probing. TODO(seam §4.2): demo = hash(fingerprint).
function mailboxIdFor(seed: string): string {
  return `mbx_${seed}_${'x'.repeat(24)}`.slice(0, 40);
}

// Owner-ownership proof for a mailbox. TODO(seam §4.1): signed poll request vs short-lived bearer.
// Until wired, returns null → the owner-dependent tests self-skip loudly (seam pending), the anti-oracle
// tests (which assert the NON-owner path) still run.
async function ownerAuthHeaders(_mailboxId: string): Promise<Record<string, string> | null> {
  return null;
}

async function deposit(request: APIRequestContext, mailboxId: string, blob = OPAQUE_BLOB) {
  return request.post(DEPOSIT, { data: { mailbox_id: mailboxId, blob } });
}
async function pollAsNonOwner(request: APIRequestContext, mailboxId: string) {
  return request.get(`${QUEUE}?mailbox_id=${encodeURIComponent(mailboxId)}`);
}

// A response's observable "shape" from a non-owner's vantage: status + body bytes. If two states share a
// shape, a prober cannot distinguish them. (Header side-channels — Content-Length, error strings — are
// caught because the body bytes are compared verbatim.)
async function shapeOf(r: Awaited<ReturnType<typeof pollAsNonOwner>>) {
  return { status: r.status(), body: await r.text() };
}

async function endpointsLive(request: APIRequestContext): Promise<boolean> {
  const r = await deposit(request, mailboxIdFor('probe'));
  return r.status() !== 404; // an existing deposit endpoint answers with something other than "route not found"
}

test.describe('return-channel custody gate (I-1/I-4 + functional)', () => {
  test.beforeAll(async ({ request }) => {
    const live = await endpointsLive(request);
    test.skip(
      !live,
      `⏸ RETURN-CHANNEL GATE PENDING — mailbox endpoints not built (POST ${DEPOSIT} 404s). This is a ` +
        `NOT-YET-RUN gate, not a passing one; it auto-activates when Athena's build lands. (Flint, joint §8)`,
    );
  });

  // ── B. I-4 anti-existence-oracle — the load-bearing gate. Runs on non-owner path; no owner key needed. ──
  test('B1: non-owner poll is byte+status-identical across {never-existed, has-mail} (no occupancy oracle)', async ({
    request,
  }) => {
    const neverExisted = mailboxIdFor('b1-absent');
    const hasMail = mailboxIdFor('b1-hasmail');
    await deposit(request, hasMail); // lazily creates + fills hasMail; neverExisted is never touched

    const absent = await shapeOf(await pollAsNonOwner(request, neverExisted));
    const full = await shapeOf(await pollAsNonOwner(request, hasMail));

    // A prober must not tell "mailbox absent" from "mailbox present with mail". Same status, same bytes.
    expect(full.status, 'status must not leak mailbox existence to a non-owner').toBe(absent.status);
    expect(full.body, 'body bytes must not leak mailbox existence/occupancy to a non-owner').toBe(absent.body);
    // And it must NOT be the mail itself (E1: a bare GET with no owner-auth is the occupancy oracle).
    expect(full.body, 'non-owner poll must never return the stored blob').not.toContain(OPAQUE_BLOB);
  });

  // ── C. I-4 deposit-side uniform ack — a depositor cannot probe R's state via deposit. ──
  test('C1: deposit ack is shape-identical across {never-existed, has-mail} mailboxes', async ({ request }) => {
    const fresh = mailboxIdFor('c1-fresh');
    const warm = mailboxIdFor('c1-warm');
    await deposit(request, warm); // warm now has mail

    const toFresh = await shapeOf(await deposit(request, fresh));
    const toWarm = await shapeOf(await deposit(request, warm));

    expect(toWarm.status, 'deposit status must not reveal R mailbox state').toBe(toFresh.status);
    expect(toWarm.body, 'deposit body must not reveal R mailbox state (exists/empty/full)').toBe(toFresh.body);
    // NOTE: the at-CAP (429) state is deliberately EXCLUDED here — see criteria §3 (cap-429 ↔ I-4 seam),
    // pending Peter/Archie/Athena's option (i/ii/iii). Add the at-cap assertion once that's decided.
  });

  // ── E. Owner-only enforcement (non-owner half; owner half under A). ──
  test('E1: non-owner poll of a filled mailbox returns the uniform non-owner response, never the mail', async ({
    request,
  }) => {
    const mbx = mailboxIdFor('e1');
    await deposit(request, mbx);
    const asNonOwner = await shapeOf(await pollAsNonOwner(request, mbx));
    const asAbsent = await shapeOf(await pollAsNonOwner(request, mailboxIdFor('e1-absent')));
    expect(asNonOwner.body, 'non-owner must get the uniform response, not the blob').toBe(asAbsent.body);
    expect(asNonOwner.body).not.toContain(OPAQUE_BLOB);
  });

  // ── A. Functional return-channel — owner-dependent; self-skips loudly until the owner-auth seam is wired. ──
  test('A1–A4: deposit→owner-poll→ack-delete, non-destructive, at-least-once redelivery', async ({ request }) => {
    const mbx = mailboxIdFor('a');
    const auth = await ownerAuthHeaders(mbx);
    test.skip(
      auth === null,
      '⏸ owner-auth seam (§4.1) not wired — functional poll/ack half pending. Anti-oracle half (B/C/E) still gates.',
    );
    // Deposit two envelopes.
    await deposit(request, mbx, 'AAAA');
    await deposit(request, mbx, 'BBBB');

    // A1 deposit→poll (owner sees them); A2 non-destructive (poll twice, same set, no ack between).
    const poll1 = await request.get(`${QUEUE}?mailbox_id=${encodeURIComponent(mbx)}`, { headers: auth! });
    expect(poll1.ok()).toBeTruthy();
    const list1 = (await poll1.json()) as Array<{ envelope_id: string; blob: string }>;
    expect(list1.length).toBe(2);
    const poll2 = await request.get(`${QUEUE}?mailbox_id=${encodeURIComponent(mbx)}`, { headers: auth! });
    const list2 = (await poll2.json()) as Array<{ envelope_id: string; blob: string }>;
    expect(list2.map((e) => e.envelope_id).sort(), 'poll is non-destructive').toEqual(
      list1.map((e) => e.envelope_id).sort(),
    );

    // A3 ack-delete one → next poll omits exactly it.
    const drop = list1[0].envelope_id;
    const ack = await request.post(ACK, { headers: auth!, data: { mailbox_id: mbx, envelope_ids: [drop], owner_ack: 'seam' } });
    expect(ack.ok()).toBeTruthy();
    const poll3 = await request.get(`${QUEUE}?mailbox_id=${encodeURIComponent(mbx)}`, { headers: auth! });
    const ids3 = ((await poll3.json()) as Array<{ envelope_id: string }>).map((e) => e.envelope_id);
    expect(ids3, 'acked id is gone').not.toContain(drop);
    expect(ids3, 'unacked ids remain (at-least-once)').toContain(list1[1].envelope_id);
  });

  // A5 (TTL GC) needs a shortened-TTL hook (seam §4.4) — assert once Athena exposes it.
});

// ── B2. Statistical latency-distribution uniformity — ON-DEMAND ONLY (RC_TIMING=1). Not an always-on CI gate. ──
test.describe('return-channel timing distribution (I-4, on-demand)', () => {
  test.skip(!process.env.RC_TIMING, 'statistical timing gate — set RC_TIMING=1 to run (noise-sensitive; see criteria §0). Rigorous KS lives in the on-demand harness.');

  test('B2: non-owner poll latency does not distinguish {never-existed} from {has-mail}', async ({ request }) => {
    const N = 300;
    const absentId = mailboxIdFor('b2-absent');
    const fullId = mailboxIdFor('b2-full');
    await deposit(request, fullId);

    const sample = async (id: string): Promise<number[]> => {
      const xs: number[] = [];
      for (let i = 0; i < N; i++) {
        const t0 = performance.now();
        await pollAsNonOwner(request, id);
        xs.push(performance.now() - t0);
      }
      return xs.sort((a, b) => a - b);
    };
    const median = (xs: number[]) => xs[Math.floor(xs.length / 2)];

    const a = await sample(absentId);
    const f = await sample(fullId);
    const delta = Math.abs(median(a) - median(f));
    // Coarse guard: median delta within a few ms. The RIGOROUS two-sample KS test lives in the on-demand
    // harness (criteria §0/§2-B2); if this coarse guard trips, the relay is branching on mailbox state.
    expect(delta, `median latency delta ${delta.toFixed(2)}ms suggests a state-dependent code path (I-4 leak)`).toBeLessThan(3);
  });
});
