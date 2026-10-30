// Test-only: in-memory ratchet session storage with the SAME version semantics as store.ts (0 = no row, a legacy row = 1, a CAS write
// bumps by one and throws RatchetSessionConflictError on a mismatch). Every call is logged, so "nothing stateful happened" is an
// assertion about the log. Imported by the ratchet policy tests only.
import type { RatchetSnapshot } from '@/lib/crypto/message-ratchet';
import type { RatchetIO } from './direct-session';
import { ratchetRowVersion, RatchetSessionConflictError, type RatchetSessionRead } from './store';

export function memIO(opts: { failPuts?: number } = {}) {
  const rows = new Map<string, RatchetSessionRead>();
  const log: string[] = [];
  let failPuts = opts.failPuts ?? 0;
  const versionOf = (fp: string) => {
    const r = rows.get(fp);
    return ratchetRowVersion(r ? { version: r.state === 'ok' ? r.version : 1 } : undefined);
  };
  const io: RatchetIO = {
    read: async (fp) => { log.push(`read:${fp}`); return rows.get(fp) ?? { state: 'absent' }; },
    put: async (fp, snapshot: RatchetSnapshot, expectedVersion: number) => {
      if (failPuts > 0) { failPuts--; log.push(`put-FAILED:${fp}`); throw new Error('session store write failed'); }
      const have = versionOf(fp);
      if (have !== expectedVersion) { log.push(`put-CONFLICT:${fp}`); throw new RatchetSessionConflictError(); }
      log.push(`put:${fp}`);
      rows.set(fp, { state: 'ok', snapshot, version: have + 1 });
    },
  };
  return { rows, log, io, puts: () => log.filter((l) => l.startsWith('put:')).length };
}
