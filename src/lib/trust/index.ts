// src/lib/trust/index.ts
// Public API for the trust layer.

export { TrustGraphManager } from './trust-graph';
export type { TrustGraphManagerOptions } from './trust-graph';

export {
  createSignal,
  verifySignal,
  vouchSignal,
  concernSignal,
  breakSignal,
  syncSignal,
  introduceSignal,
  keyRotationSignal,
  shouldPropagate,
  maxIntroductionLevel,
} from './signals';

export { migrateContact, migrateContacts } from './migration';

export type {
  TrustEdge,
  TrustGraph,
  TrustLevel,
  TrustEvent,
  TrustSignal,
  SignedSignal,
  Tribe,
  IntroductionRecord,
  LegacyContact,
} from './types';

export { TRUST_LABELS, PRIVACY_FILTERS, LEGACY_TRUST_MAP } from './types';
