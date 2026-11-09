// src/lib/identity/save-owner-email.ts
// The identity record is a single row, so saving one field rewrites all of it. A copy held in memory can lack fields written
// since it was read; card_version is the one that hurts, because losing it makes the next contact update repeat a version every
// recipient has already seen, and they drop it silently. So the base is what is stored, and the copy is used only if nothing is.

type Loaded = { identity: Record<string, unknown> } & Record<string, unknown>;

export async function saveOwnerEmail<T extends Loaded>(
  fingerprint: string,
  email: string,
  inMemory: T,
  deps: { load: (fp: string) => Promise<unknown>; store: (fp: string, identity: T) => Promise<void> },
): Promise<T> {
  const base = ((await deps.load(fingerprint)) ?? inMemory) as T;
  const next = { ...base, identity: { ...base.identity, email } };
  await deps.store(fingerprint, next);
  return next;
}
