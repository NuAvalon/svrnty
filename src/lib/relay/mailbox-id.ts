// src/lib/relay/mailbox-id.ts
// The two shapes a mailbox id can have. Anything else was not produced by deriveMailboxId or deriveMailboxIdV2.
import { isMailboxIdV2 } from './mailbox-auth-v2';

const ID_V1 = /^mbx_[0-9a-f]{64}$/;

export function isValidMailboxId(id: unknown): id is string {
  return typeof id === 'string' && (ID_V1.test(id) || isMailboxIdV2(id));
}
