/**
 * Local demo threads for the sample circle.
 * Calls fleet putThread / putNote only — no wire, no keys, no send.
 * Bodies are on-device glass fixtures so Notes has something to open.
 */

import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import {
  initNotesStore,
  isNotesStoreUnlocked,
  putNote,
  putThread,
} from '@/lib/messaging/store';
import type { NoteRecord, NoteThread } from '@/lib/messaging/types';

const ADA = 'a11a10e1ace00000000000000000000000000001';
const GRACE = '61ace00000000000000000000000000000000003';
const ALAN = 'a1a2011216000000000000000000000000000002';
const NIKOLA = '7e51a00000000000000000000000000000000008';

type Line = { from: 'me' | 'them'; body: string; minutesAgo: number };

const DEMO: { fp: string; name: string; lines: Line[] }[] = [
  {
    fp: ADA,
    name: 'Ada Lovelace',
    lines: [
      { from: 'them', body: 'The engine will compose as well as calculate — if we let it.', minutesAgo: 180 },
      { from: 'me', body: 'Then we write the score first. I trusted you for that.', minutesAgo: 150 },
      { from: 'them', body: 'Mutual, then. Bring the next table when you come.', minutesAgo: 40 },
    ],
  },
  {
    fp: GRACE,
    name: 'Grace Hopper',
    lines: [
      { from: 'me', body: 'Frank is waiting at the Gate. I have not accepted yet.', minutesAgo: 240 },
      { from: 'them', body: 'That is knowing, not trusting. Meet him first.', minutesAgo: 200 },
    ],
  },
  {
    fp: ALAN,
    name: 'Alan Turing',
    lines: [
      { from: 'me', body: 'I hold you as trusted. Waiting on your side.', minutesAgo: 90 },
      { from: 'them', body: 'Received. I will verify in person at Bletchley.', minutesAgo: 70 },
    ],
  },
  {
    fp: NIKOLA,
    name: 'Nikola Tesla',
    lines: [
      { from: 'them', body: 'The coil still sings. Come by if the night is clear.', minutesAgo: 30 },
      { from: 'me', body: 'I will. No location — just whether I can reach you.', minutesAgo: 12 },
    ],
  },
];

export async function seedDemoNotes(args: {
  ownerFingerprint: string;
  ownerName: string;
  passphrase?: string;
}): Promise<number> {
  if (!isNotesStoreUnlocked()) {
    if (!args.passphrase) return 0;
    await initNotesStore(args.passphrase);
  }

  const now = Date.now();
  let n = 0;
  for (const convo of DEMO) {
    const threadId = `demo-thr-${convo.fp}`;
    const last = convo.lines[convo.lines.length - 1];
    const thread: NoteThread = {
      thread_id: threadId,
      kind: 'direct',
      participants: [
        { fingerprint: args.ownerFingerprint, kind: 'human', display_name: args.ownerName || 'You' },
        { fingerprint: convo.fp, kind: 'human', display_name: convo.name },
      ],
      created_at: new Date(now - convo.lines[0].minutesAgo * 60_000).toISOString(),
      last_activity_at: new Date(now - last.minutesAgo * 60_000).toISOString(),
      retention: { expires_at: null },
    };
    await putThread(thread);

    for (let i = 0; i < convo.lines.length; i++) {
      const line = convo.lines[i];
      const fromMe = line.from === 'me';
      const note: NoteRecord = {
        note_id: `demo-note-${convo.fp}-${i}`,
        thread_id: threadId,
        direction: fromMe ? 'outbound' : 'inbound',
        from_fingerprint: fromMe ? args.ownerFingerprint : convo.fp,
        to_fingerprints: [fromMe ? convo.fp : args.ownerFingerprint],
        sent_at: new Date(now - line.minutesAgo * 60_000).toISOString(),
        body: line.body,
        participant_kind: 'human',
        retention: { expires_at: null },
        wire_type: NOTE_WIRE_TYPE,
      };
      await putNote(note);
      n++;
    }
  }
  return n;
}
