// src/lib/messaging/thread-alias-store.ts: the real alias port (thread-alias.ts) over the notes DB's encrypted 'settings' rows (adopt-floor-store.ts pattern; no schema bump).
// Both calls THROW while the store is locked, so a locked store makes the accept retryable (the note waits in the mailbox); an alias that cannot be read is never taken for "no alias
// and join the claimed thread": acceptInboundNote decides that, and it never joins a thread the sender is not in.
import { getEncryptedSetting, putEncryptedSetting } from './store';
import { aliasFor, parseThreadAliasRow, threadAliasKey, withAlias, type ThreadAliasPort } from './thread-alias';
import { normalizeResetFp } from './reset-flag';

async function readRow(senderFp: string) {
  const key = threadAliasKey(senderFp);
  if (!key) return { key: null, row: null };
  return { key, row: parseThreadAliasRow(await getEncryptedSetting<unknown>(key)) };
}

export const threadAliasPort: ThreadAliasPort = {
  async resolve(senderFp, claimed) {
    const { row } = await readRow(senderFp);
    return aliasFor(row, claimed);
  },
  async remember(senderFp, claimed, local) {
    const fp = normalizeResetFp(senderFp);
    const { key, row } = await readRow(senderFp);
    if (!key || !fp) return;
    const next = withAlias(row, fp, claimed, local);
    if (next) await putEncryptedSetting(key, next);
  },
};
