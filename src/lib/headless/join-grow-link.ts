// src/lib/headless/join-grow-link.ts
// `devin-comm join <grow link>`, made safe and testable. Spec: Flint join_expect_fp_spec_v1.md (sha256 b79db0ef, J1-J6) plus his review note
// "admit only after deposit:ok, or roll back" (task:698 #1236). Dependencies are INJECTED so every rule has a test that can fail.
//
// WHY: stock `join` resolved a link and upserted WHATEVER card came back as trust_level 'known' under the card's own display_name, with no fingerprint
// check, and its joiner-response target omitted giverPqKemPublicKey, so the deposit failed closed (encrypt-failed) AFTER the giver was already admitted:
// a trusted contact whose response never went out. A line-wrapped link (fragment cut short) was only discovered by the GET that already spent a use.
//
// ORDER (each step can refuse; nothing before the deposit changes the store):
//   J1 --expect-fp required, 64 hex            (no network)
//   J3 --name required, [a-z0-9-]{1,24}         (no network)
//   J4 URL shape: /c/<code> + a 43-char fragment (no network: the wrap case is caught here)
//   J5 backup the store                         (local)
//   resolve the link                            (one GET)
//   J2 resolved fp == expect-fp AND the fp DERIVES from the keys the card presents
//   J6 deposit our signed joiner-response WITH the giver's verified KEM key
//   ONLY IF the deposit is ok: admit the giver (name = --name, never the card's display_name)

export const GROW_FRAGMENT_CHARS = 43; // base64url of a 32-byte key, no padding
const FP64 = /^[0-9a-f]{64}$/;
const NAME = /^[a-z0-9-]{1,24}$/;
const CODE = /^[A-Za-z0-9_-]{4,32}$/;
const FRAGMENT = new RegExp(`^[A-Za-z0-9_-]{${GROW_FRAGMENT_CHARS}}$`);

export type JoinRefusal =
  | 'missing-expect-fp' | 'bad-expect-fp' | 'missing-name' | 'bad-name' | 'bad-url' | 'bad-fragment'
  | 'resolve-failed' | 'bad-card' | 'fp-mismatch' | 'fp-not-derived' | 'no-kem-key' | 'backup-failed' | 'deposit-failed';

export interface JoinGiverCard {
  fingerprint: string;
  public_key: string;
  pq_kem_public_key?: string;
  pq_sig_public_key?: string;
}

export interface JoinDeps {
  /** J5: copy the store to a dated backup BEFORE anything can change; throws on failure. Called after validation, before any network. */
  backup(): void;
  /** One GET of the link (resolveRelay). Returns the card JSON text. */
  resolve(code: string, fragment: string): Promise<string>;
  /** fingerprintMatchesKey: does `fp` derive from the keys the card presents? */
  derives(fp: string, publicKey: string, pq: { kem_public_key?: string; sig_public_key?: string }): Promise<boolean>;
  /** sendJoinerResponse: the target MUST carry the giver's verified KEM key. Returns the relay outcome. */
  deposit(target: { fingerprint: string; publicKeyArmored: string; giverPqKemPublicKey: string; inviteNonce: string }): Promise<{ ok: boolean; status?: number | string }>;
  /** Write the contact. Called ONLY after a successful deposit. */
  admit(contact: {
    id: string; fingerprint: string; name: string; public_key: string; pq_sig_public_key?: string; pq_kem_public_key?: string; trust_level: 'known';
  }): void;
}

export type JoinResult =
  | { ok: true; admitted: string; fp8: string; name: string; joinerResponse: { ok: boolean; status?: number | string } }
  | { ok: false; refusal: JoinRefusal; detail?: string };

const refuse = (refusal: JoinRefusal, detail?: string): JoinResult => ({ ok: false, refusal, ...(detail ? { detail } : {}) });

export async function runJoin(args: { url?: string; expectFp?: string; name?: string }, deps: JoinDeps): Promise<JoinResult> {
  // J1
  if (args.expectFp === undefined || args.expectFp === '') return refuse('missing-expect-fp');
  const expect = String(args.expectFp).toLowerCase();
  if (!FP64.test(expect)) return refuse('bad-expect-fp');
  // J3
  if (args.name === undefined || args.name === '') return refuse('missing-name');
  if (!NAME.test(args.name)) return refuse('bad-name');
  // J4
  let u: URL;
  try { u = new URL(String(args.url)); } catch { return refuse('bad-url'); }
  const code = u.pathname.startsWith('/c/') ? u.pathname.slice(3) : '';
  if (!CODE.test(code)) return refuse('bad-url');
  const fragment = u.hash.startsWith('#') ? u.hash.slice(1) : '';
  if (!FRAGMENT.test(fragment)) return refuse('bad-fragment', `expected ${GROW_FRAGMENT_CHARS} base64url chars, got ${fragment.length}`);

  // J5
  try { deps.backup(); } catch (e) { return refuse('backup-failed', String((e as Error)?.message ?? e).slice(0, 120)); }

  let raw: string;
  try { raw = await deps.resolve(code, fragment); } catch (e) { return refuse('resolve-failed', String((e as Error)?.message ?? e).slice(0, 120)); }
  let card: { identity?: Record<string, unknown>; durable_id?: unknown } & Record<string, unknown>;
  try { card = JSON.parse(raw); } catch { return refuse('bad-card'); }
  const id = (card.identity ?? card) as Record<string, unknown>;
  const fpRaw = id.fingerprint ?? card.durable_id;
  if (typeof fpRaw !== 'string' || typeof id.public_key !== 'string' || !id.public_key) return refuse('bad-card');
  const fp = fpRaw.toLowerCase();

  // J2
  if (fp !== expect) return refuse('fp-mismatch');
  const kem = typeof id.pq_kem_public_key === 'string' ? id.pq_kem_public_key : undefined;
  const sig = typeof id.pq_sig_public_key === 'string' ? id.pq_sig_public_key : undefined;
  if (!(await deps.derives(fp, id.public_key, { kem_public_key: kem, sig_public_key: sig }))) return refuse('fp-not-derived');
  if (!kem) return refuse('no-kem-key'); // unreachable when derives() is honest (it needs the KEM key); kept so the deposit target can never lack it

  // J6, then admit ONLY if it worked
  let sent: { ok: boolean; status?: number | string };
  try {
    sent = await deps.deposit({ fingerprint: fp, publicKeyArmored: id.public_key, giverPqKemPublicKey: kem, inviteNonce: code });
  } catch (e) { return refuse('deposit-failed', String((e as Error)?.message ?? e).slice(0, 120)); }
  if (!sent || sent.ok !== true) return refuse('deposit-failed', String(sent?.status ?? 'unknown'));

  deps.admit({ id: fp, fingerprint: fp, name: args.name, public_key: id.public_key, pq_sig_public_key: sig, pq_kem_public_key: kem, trust_level: 'known' });
  return { ok: true, admitted: fp, fp8: fp.slice(0, 8), name: args.name, joinerResponse: { ok: true, status: sent.status } };
}

/** Pull `--expect-fp <v>` and `--name <v>` out of the CLI args (value = the next token; a flag as the last token has no value). */
export function parseJoinFlags(rest: readonly string[]): { url?: string; expectFp?: string; name?: string } {
  const val = (flag: string): string | undefined => {
    const i = rest.indexOf(flag);
    return i >= 0 && i + 1 < rest.length && !rest[i + 1].startsWith('--') ? rest[i + 1] : undefined;
  };
  const url = rest.find((a) => !a.startsWith('--') && a !== val('--expect-fp') && a !== val('--name'));
  return { url, expectFp: val('--expect-fp'), name: val('--name') };
}
