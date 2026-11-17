// src/lib/identity/device-password.ts: the one definition of the shortest password a device will be unlocked with. Pure, no dependencies, so the restore sentences
// (restore-errors.ts) and the check that enforces it (client-store.ts) read the SAME constant: no number is written out in any copy.

/** The shortest password a device will be unlocked with (the same floor the password exports ask for). */
export const DEVICE_PASSWORD_MIN = 12;
