// src/lib/trust/psi-epoch-config.ts
/**
 * Where the three epoch switches are read from: three build-time environment variables, each ON only when it is exactly the string "true". Everything
 * else (unset, "1", "TRUE", " true") is off. If the switches that are on are out of order (see psi-epoch-flags), ALL are off: a flip mistake falls back
 * to the safe state instead of reaching a fleet that is not ready.
 *
 * The variables are named in full at the read, not looked up by name from process.env: Next.js replaces NEXT_PUBLIC_* only where it sees the full
 * name, so a computed lookup would silently read undefined in the browser and every switch would be off for the wrong reason.
 */
import { checkFlagOrder, PSI_EPOCH_FLAGS_OFF, type PsiEpochFlags } from './psi-epoch-flags';

export interface PsiEpochEnv {
  receive?: string;
  send?: string;
  use?: string;
}

export function readPsiEpochFlags(env: PsiEpochEnv = {
  receive: process.env.NEXT_PUBLIC_PSI_EPOCH_RECEIVE,
  send: process.env.NEXT_PUBLIC_PSI_EPOCH_SEND,
  use: process.env.NEXT_PUBLIC_PSI_EPOCH_USE,
}): PsiEpochFlags {
  const flags: PsiEpochFlags = { receive: env.receive === 'true', send: env.send === 'true', use: env.use === 'true' };
  return checkFlagOrder(flags).ok ? flags : { ...PSI_EPOCH_FLAGS_OFF };
}
