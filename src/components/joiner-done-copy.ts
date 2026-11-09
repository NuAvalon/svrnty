// src/components/joiner-done-copy.ts
// What the invite's last screen says when the giver is already in your book. For someone you blocked, "already connected" is false, and nothing was sent back.
// The line states what happened and stops: it must not suggest undoing the block, because a blocked person may be the one who got you to open this link.

export function alreadyKnownCopy(name: string | null | undefined, blocked: boolean): { heading: string; sub: string } {
  if (blocked) return { heading: 'You’ve blocked this person', sub: 'Nothing was sent to them.' };
  return { heading: 'You’re already connected', sub: `${name || 'They'} are already in your network.` };
}
