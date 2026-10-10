/**
 * Beta Unlock/redeem chrome mounts IFF the operator provisioned the issuer pin.
 *
 * Public flag only — never ships the issuer key. The claim route still fail-closes
 * without SVRNTY_BETA_ISSUER_FP / SVRNTY_BETA_ISSUER_PUBKEY.
 *
 * NEXT_PUBLIC_SVRNTY_BETA_GATE=1 (or true) → the redeem screen may render.
 * Unset / any other value → dogfood gap, no redeem UI.
 */
export function isBetaIssuerProvisioned(): boolean {
  const raw =
    typeof process !== 'undefined' ? process.env?.NEXT_PUBLIC_SVRNTY_BETA_GATE : undefined;
  return raw === '1' || raw === 'true';
}
