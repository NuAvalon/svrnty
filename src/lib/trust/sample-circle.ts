// Demo sample circle for Trust Map / Contacts — keyless peers (no MITM risk).
// UI-only seed; not production identity data.

import { addContact, getAllContacts } from '@/lib/identity/client-store';

/** Deterministic fake fingerprints (40 hex) — no matching keys; gray/keyless OK. */
const SAMPLE = [
  { name: 'Ada Lovelace', email: 'ada@analytical.engine', fingerprint: 'a11a10e1ace00000000000000000000000000001', trust_level: 'verified' as const },
  { name: 'Alan Turing', email: 'alan@bletchley.uk', fingerprint: 'a1a2011216000000000000000000000000000002', trust_level: 'verified' as const },
  { name: 'Grace Hopper', email: 'grace@cobol.dev', fingerprint: '61ace00000000000000000000000000000000003', trust_level: 'verified' as const },
  { name: 'Claude Shannon', email: 'claude@bell.labs', fingerprint: 'c1a00e0000000000000000000000000000000004', trust_level: 'unverified' as const },
  { name: 'Hedy Lamarr', email: 'hedy@fhss.radio', fingerprint: '4ed1000000000000000000000000000000000005', trust_level: 'unverified' as const },
  { name: 'Katherine Johnson', email: 'katherine@nasa.gov', fingerprint: 'ca1e000000000000000000000000000000000006', trust_level: 'unverified' as const },
  { name: 'Nikola Tesla', email: '', fingerprint: '', trust_level: 'unverified' as const },
  { name: 'Hypatia', email: '', fingerprint: '', trust_level: 'unverified' as const },
];

/** Seed sample known + trusted contacts if the owner has none yet. Returns count added. */
export async function seedSampleCircle(ownerFingerprint: string): Promise<number> {
  const existing = await getAllContacts(ownerFingerprint);
  if (existing.length > 0) return 0;
  let n = 0;
  for (const c of SAMPLE) {
    await addContact(ownerFingerprint, {
      name: c.name,
      email: c.email,
      fingerprint: c.fingerprint,
      public_key: '',
      trust_level: c.trust_level,
      metadata: { sample: true },
    });
    n++;
  }
  return n;
}
