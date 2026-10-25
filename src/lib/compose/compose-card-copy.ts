// src/lib/compose/compose-card-copy.ts
// The words on the "Sign portal message" card and the hand-back screen. VERBATIM from Hypatia's portal_compose_copy_v0.md §3, §3-last-screen, §4 and §6b
// (sha1 prefix recorded in the commit message; a script compares every string below against the doc). Do not reword: this is the screen people sign on.
// Never on these screens: "sent", "delivered", "posted" before the receiver accepts; "end-to-end encrypted"; "secure"; "verified" alone; "auto-approve";
// any post-quantum wording (doc §5).

export const CARD_COPY = {
  post: {
    title: 'Sign a message for noosphere',
    intro: (origin: string) => `${origin} asks you to sign this message, as you, into:`,
    approve: 'Sign and post as me',
    decline: "Don't sign",
    footnote: 'Your signature makes this message yours. Only sign text you wrote and can see in full above.',
  },
  task: {
    title: 'Sign a task request for noosphere',
    intro: (origin: string) => `${origin} asks you to sign this request, as you:`,
    toAgent: (agent: string) => `To: ${agent}`,
    toOrchestrator: 'To: the orchestrator, to route',
    linked: (node: string) => `Linked to step: ${node}`,
    approve: 'Sign the request as me',
    decline: "Don't sign",
    footnote: 'This posts a signed request. Nothing is assigned until an agent accepts it and creates the task.',
  },
  words: (w: readonly string[]) => `Check these words match the portal: ${w.join(' ')}`,
  refused: {
    notice: "Can't sign this message: it contains hidden characters that can change how text looks (shown below as [U+202E] etc.). Write it again in the portal without them.",
    close: 'Close',
  },
  weftViewOnly: 'View only: replying into the Weft needs their side to accept signed posts (not built yet).',
  handBack: {
    title: 'Signed. Not posted yet.',
    body: 'Copy this and paste it into the portal\'s "Sign on your phone" box. Nothing is posted until the portal delivers it; the portal shows what happened.',
    copy: 'Copy',
    copied: 'Copied.',
  },
  /**
   * NOT IN HYPATIA'S DOC (pending her words, flagged in the PR): shown only when the card cannot compute the four check-words. The card then offers NO approve
   * button, so a missing word derivation fails closed. Plain and true; contains none of the forbidden words.
   */
  noWords: "Can't show the check words, so this request can't be signed.",
} as const;
