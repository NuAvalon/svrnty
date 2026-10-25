// src/lib/compose/compose-words-gate.ts
// The production switch for the check-words. OFF unless explicitly built in. Flint lane:portal #1474 (3): "the card stays no-Approve in production until
// [the portal's] test is green"; Hypatia: no Approve until the vectors are pinned and green in BOTH code bases. The flag name says what it means, so setting it
// is a decision someone makes on purpose, not a default that drifts on: NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED=1 at BUILD time, set only for the e2e server
// (playwright.config.ts) until the portal confirms, then by whoever Flint and Athena name. A NEXT_PUBLIC value is BAKED into the bundle, so an image built with
// it set must never be the deployable image (compose-words-gate.test.ts fails if a deploy file mentions it).
//
// Next inlines NEXT_PUBLIC_* ONLY where the source holds the LITERAL `process.env.NEXT_PUBLIC_…` expression (Flint #1478). Reading the property off a
// `process.env` OBJECT (a default parameter, a destructure) is empty in the browser bundle, so the switch would stay off even on the e2e build. Hence the
// module-scope literal below, which must stay exactly this expression.
const BUILT = process.env.NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED;

/** `env` is for tests only; production callers pass nothing and get the value baked in at build time. */
export function composeWordsConfirmed(env?: Record<string, string | undefined>): boolean {
  const v = env === undefined ? BUILT : env.NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED;
  return v === '1';
}
