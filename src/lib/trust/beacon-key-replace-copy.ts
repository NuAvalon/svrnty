// src/lib/trust/beacon-key-replace-copy.ts
// The words shown when a contact's newer signed card replaces what is saved for them, copy ledger rows 345a, 344b and 345c. Reviewed copy: do not reword it here;
// a change needs the copy owner's new row and new hash. Plain ASCII, straight apostrophes. Each template is pinned by length and sha256 prefix in
// beacon-key-replace-copy.test.ts. Placeholders are written {like_this} and filled by fill() below. {name} is ALWAYS the BOOK's name for the contact, never the name
// on the card (the card may be the impersonator's).
//   - No line says "key", a generation, "withdrawn", safe, verified or compromised, and none points to a fix: until the in-person confirm exists there is
//     nothing to point to, and a pointer gets its own row when it does.
//   - The refused line says the saved details are UNCHANGED, not that nothing changed: when the key write aborts after the queue was committed, the old rows are
//     still withdrawn, so "nothing changed" would be false. Only the saved details are unchanged on both refusal paths.
// Run: npx tsx --test src/lib/trust/beacon-key-replace-copy.test.ts
import type { KeyReplaceOutcome } from './beacon-key-replace';

/** Row 345a (85 chars, sha256 prefix 0a863a7ac84b70a0): shown ONLY after the compare-and-set write of the new key succeeded. */
export const KEY_REPLACED = 'A newer signed card from {name} has changed the security details saved here for them.';
/** Row 344b (52, 9061fecf8e057145): appended ONLY IF the pair was confirmed BEFORE the replace. Nothing writes the confirmed set in production yet, so "again" would be false for every real pair today; when the pair was never confirmed, 345a stands alone. */
export const KEY_REPLACED_UNCONFIRMED = 'Because of this update, {name} is unconfirmed again.';
/** Row 345c (121, 4682ab5e73fd7a85): both refusal paths (the plan could not be made, and the key write did not happen). */
export const KEY_REPLACE_REFUSED = "{name}'s newer card couldn't be saved, so the security details saved for them are unchanged. Trying again later may work.";
/** Row 338d of the held-messages copy (11, af49636912aec2d2): the approved words for a contact with no name. Reused here, not new copy; the copy owner confirms the reuse. */
export const KEY_REPLACE_NO_NAME = 'this person';

/**
 * Put each value in once. A value that looks like a placeholder, or like a replacement pattern, is inserted as it is. A hole (no value for a placeholder)
 * THROWS (a sentence with a hole in it must never reach the screen), and so does a value nobody asked for (a typo in a key must fail loudly).
 */
export function fill(template: string, values: Record<string, string | number>): string {
  const wanted = new Set<string>();
  const out = template.replace(/\{([a-z_]+)\}/g, (_m, key: string) => {
    wanted.add(key);
    if (!(key in values)) throw new Error(`key replace copy: no value for {${key}}`);
    return String(values[key]);
  });
  for (const k of Object.keys(values)) if (!wanted.has(k)) throw new Error(`key replace copy: {${k}} is not in this sentence`);
  return out;
}

/** The line a screen shows for an outcome. `bookName` is the name in the person's own book for the contact. */
export function replaceNotice(outcome: KeyReplaceOutcome, bookName: string): string {
  const name = bookName.trim() === '' ? KEY_REPLACE_NO_NAME : bookName;
  if (outcome.kind === 'refused') return fill(KEY_REPLACE_REFUSED, { name });
  return outcome.wasConfirmed
    ? `${fill(KEY_REPLACED, { name })} ${fill(KEY_REPLACED_UNCONFIRMED, { name })}`
    : fill(KEY_REPLACED, { name });
}
