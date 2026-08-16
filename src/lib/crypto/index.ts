// src/lib/crypto/index.ts
// Soverentity cryptography — classical + post-quantum hybrid

export {
  // Hybrid operations (primary API)
  generateHybridKeys,
  hybridSign,
  hybridVerify,
  hybridEncapsulate,
  hybridDecapsulate,
  deriveHybridSecret,
  isQuantumReady,
  type HybridSignature,
  type HybridPublicKeys,
  type HybridPrivateKeys,
  type HybridKeypairResult,
} from './hybrid';

export {
  // Low-level PQ operations (for advanced use)
  generateSigningKeypair,
  generateKEMKeypair,
  generatePQKeypairBundle,
  sign as pqSign,
  verify as pqVerify,
  encapsulate as pqEncapsulate,
  decapsulate as pqDecapsulate,
  publicKeyToBase64,
  base64ToPublicKey,
  serializeKeypairBundle,
  deserializeKeypairBundle,
  type PQSigningKeypair,
  type PQKEMKeypair,
  type PQKeypairBundle,
} from './pq';

export {
  // Encrypted .svrnty file (Argon2id + AES-256-GCM)
  encryptBackup,
  decryptBackup,
  isEncryptedSvrntyFile,
  type EncryptedSvrntyFile,
} from './encrypted-backup';

export {
  // 0.1 canonical sign-envelope (domain separation + suite binding)
  lengthPrefix,
  buildSignedBytes,
  signWithEnvelope,
  verifyWithEnvelope,
  SUITE_CLASSICAL,
  SUITE_HYBRID,
  type EnvelopeSignature,
} from './sign-envelope';

export {
  // Key recovery (Shamir + seed phrase)
  createKeyVault,
  recoverFromShards,
  recoverFromSeedPhrase,
  generateMasterSecret,
  encryptVault,
  decryptVault,
  createShards,
  reconstructFromShards,
  masterSecretToSeedPhrase,
  seedPhraseToMasterSecret,
  type KeyVault,
  type Shard,
  type PrivateKeyBundle,
} from './recovery';
