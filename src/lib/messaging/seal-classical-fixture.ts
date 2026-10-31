// src/lib/messaging/seal-classical-fixture.ts
//
// TEST FIXTURE ONLY. Builds a CLASSICAL OpenPGP note blob, the shape clients produced before the PQ-hybrid seal, so tests can prove the
// receive path still opens (or refuses) it. sealNoteTo no longer does this: a send never downgrades. No application code may import
// this file; src/lib/messaging/seal-no-downgrade.test.ts fails if any non-test file under src/ or app/ does.
import { createMessage, encrypt, readKey } from 'openpgp';
import type { NoteWireV0 } from './types';
import { NOTE_WIRE_TYPE } from './domains';

export async function sealNoteClassicalFixture(note: NoteWireV0, recipientPublicKeyArmored: string): Promise<string> {
  if (note.type !== NOTE_WIRE_TYPE) throw new Error('sealNoteClassicalFixture: refusing non-note wire type');
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(note) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

// #720 close-out: the same fixture treatment for the other two seal primitives. encryptContactUpdateTo / encryptJoinerResponseTo used to
// fall back to classical OpenPGP when no ML-KEM key was passed; they now THROW (like sealNoteTo), and tests that need a classical blob
// build it here. Same rule: no application code may import this file (seal-no-downgrade.test.ts walks the tree).
import type { SignedContactUpdate } from '@/lib/trust/contact-update';
import type { SignedJoinerResponse } from '@/lib/trust/joiner-response';

export async function encryptContactUpdateClassicalFixture(signed: SignedContactUpdate, recipientPublicKeyArmored: string): Promise<string> {
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(signed) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

export async function encryptJoinerResponseClassicalFixture(signed: SignedJoinerResponse, giverPublicKeyArmored: string): Promise<string> {
  const encryptionKeys = await readKey({ armoredKey: giverPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(signed) });
  return (await encrypt({ message, encryptionKeys })) as string;
}
