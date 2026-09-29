/**
 * Download name for the legacy contacts-only encrypted export
 * (SecureImportExportDialogs — PBKDF2 JSON envelope, NOT fleet packVault).
 *
 * Claim-honesty: must NOT use the bare `.svrnty` extension. That extension is
 * reserved for the binary identity vault (`packVault` / `downloadVault`).
 * A contacts-only file named `*.svrnty` reads as a full vault and strands
 * restore UX (QUEUE CASE A vs Full Backup).
 *
 * Restore still accepts `.json` (and legacy misnamed `.svrnty` JSON) via
 * format-detect in SoverentityFrontend — this only changes the download name.
 */
export function contactsEncryptedExportFilename(now = new Date()): string {
  const day = now.toISOString().slice(0, 10);
  return `svrnty-contacts-${day}.json`;
}
