/**
 * Thin glass seam for Switch → migrateRelay.
 * Cursor renders; Apollo registers the real deps (config override, card re-sign, migrateRelay).
 */

import { isRelayMigrateLive } from '@/lib/claim-gates';

export type RelayMigrateResult = {
  complete: boolean;
  failedFps: string[];
  overlapUntil: number | null;
};

export type RelayMigrateFn = (url: string) => Promise<RelayMigrateResult>;

export class RelayMigrateUnwiredError extends Error {
  constructor() {
    super('migrateRelay is built, not yet wired');
    this.name = 'RelayMigrateUnwiredError';
  }
}

let impl: RelayMigrateFn | null = null;

/** Fleet calls this once the three seams are live. */
export function registerRelayMigrate(fn: RelayMigrateFn): void {
  impl = fn;
}

export function isRelayMigrateRegistered(): boolean {
  return impl !== null;
}

export async function switchToRelay(url: string): Promise<RelayMigrateResult> {
  if (!isRelayMigrateLive() || !impl) {
    throw new RelayMigrateUnwiredError();
  }
  const result = await impl(url);
  return {
    complete: !!result.complete,
    failedFps: Array.isArray(result.failedFps) ? result.failedFps : [],
    overlapUntil: typeof result.overlapUntil === 'number' ? result.overlapUntil : null,
  };
}
