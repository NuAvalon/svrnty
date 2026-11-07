// src/lib/contacts/empty-book-copy.ts
// What the contact book says when it has nothing to list. Pure so the words can be tested.
//
// A book whose only contacts are blocked used to say "No contacts yet", which reads as if they were gone. They are kept out of the main book on purpose
// (the blocked list is one menu away), so say that they exist, how many, and where.
// Run: npx tsx --test src/lib/contacts/empty-book-copy.test.ts

export interface EmptyBookState {
  /** A search is typed in the box. */
  searching: boolean;
  /** The blocked list is the one being shown. */
  showBlocked: boolean;
  /** Every contact the book holds, blocked or not. */
  totalCount: number;
  /** How many of them are blocked. */
  blockedCount: number;
}

export function emptyBookCopy(s: EmptyBookState): { title: string; hint: string } {
  if (s.searching) return { title: 'No matching contacts', hint: 'Try a different search' };
  if (s.showBlocked) return { title: 'No blocked contacts', hint: 'Blocked stays out of the main book — exit via ⋯' };
  if (s.totalCount > 0 && s.blockedCount === s.totalCount) {
    const n = s.blockedCount;
    return {
      title: 'No contacts in your main book',
      hint: `${n} blocked ${n === 1 ? 'contact is' : 'contacts are'} kept out of it. Open ⋯ → View blocked contacts (${n}).`,
    };
  }
  return { title: 'No contacts yet', hint: 'Import a VCF or add someone to start your master book' };
}
