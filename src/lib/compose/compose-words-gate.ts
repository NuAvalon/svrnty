// src/lib/compose/compose-words-gate.ts
// The production switch for the check-words. OFF unless explicitly built in. Flint lane:portal #1474 (3): "the card stays no-Approve in production until
// [the portal's] test is green"; Hypatia: no Approve until the vectors are pinned and green in BOTH code bases. The flag name says what it means, so setting it
// is a decision someone makes on purpose, not a default that drifts on: NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED=1 at BUILD time, set only for the e2e server
// until the portal confirms, then by whoever Flint and Athena name.
export function composeWordsConfirmed(env: Record<string, string | undefined> = process.env): boolean {
  return env.NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED === '1';
}
