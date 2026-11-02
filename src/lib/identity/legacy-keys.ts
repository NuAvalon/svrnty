// The old chat page kept its identity keys in plaintext under one localStorage item. The app never reads or writes that item, so any copy
// left in a browser is only exposure. The root layout runs this script on every page load of the app origin, before the app code.
//
// Exactly one item is removed, by exact name. No other item is touched, and a storage that throws (blocked or private mode) is ignored.
//
// Run: npx tsx --test src/lib/identity/legacy-keys.test.ts

export const LEGACY_CHAT_KEYS_ITEM = 'svrnty_keys';

/** Remove the legacy item from `storage`. Returns true when the removal ran without error. */
export function clearLegacyChatKeys(storage: Pick<Storage, 'removeItem'> | null | undefined): boolean {
  try {
    if (!storage) return false;
    storage.removeItem(LEGACY_CHAT_KEYS_ITEM);
    return true;
  } catch {
    return false;
  }
}

/** The same removal as an inline script for the root layout (it runs before the app code and on pages that never mount the app shell). */
export const LEGACY_CHAT_KEYS_BOOT_SCRIPT = `
(function(){
  try { localStorage.removeItem(${JSON.stringify(LEGACY_CHAT_KEYS_ITEM)}); } catch (e) {}
})();
`;
