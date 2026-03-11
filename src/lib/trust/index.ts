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
  introductionCreatesTrust,
} from './signals';

export { migrateContact, migrateContacts } from './migration';

export {
  formatSignalMessage,
  parseSignalMessage,
  SignalTransport,
  ClipboardTransport,
  registerTransport,
  getAvailableTransports,
  getTransport,
} from './transport';
export type { TransportAdapter } from './transport';

export type {
  TrustEdge,
  TrustGraph,
  TrustEvent,
  TrustSignal,
  SignedSignal,
  Tribe,
  IntroductionRecord,
  LegacyContact,
  VerifiedClaim,
} from './types';

export {
  isDecayed,
  daysUntilDecay,
  migrateTrustLevel,
  PRIVACY_FILTERS,
} from './types';
