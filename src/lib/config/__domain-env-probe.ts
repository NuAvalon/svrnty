// src/lib/config/__domain-env-probe.ts
// TEST HELPER — not application code, never imported by the app.
//
// domain.ts reads NEXT_PUBLIC_* at MODULE-EVAL time (consts, not lazy), so a changed env can
// only be observed in a FRESH process. domain.test.ts spawns this file with the env preset;
// it evaluates domain.ts once and prints a single JSON snapshot for the parent to assert on.
//
// Run standalone: NEXT_PUBLIC_SVRNTY_DOMAIN=id.example.com npx tsx src/lib/config/__domain-env-probe.ts

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SVRNTY_BASE_URL, SVRNTY_DOMAIN, shareUrl, shareUrlShort, slugUrlShort } from './domain';

/** Marker so the parent can find the payload even if the loader printed warnings first. */
export const SNAPSHOT_MARKER = '__DOMAIN_SNAPSHOT__';

/** Only emit when run as the entrypoint — the test imports this file for the marker. */
const isEntrypoint =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isEntrypoint) {
  const code = process.env.__PROBE_CODE ?? 'ABC123';
  const key = process.env.__PROBE_KEY ?? 'k';
  const slug = process.env.__PROBE_SLUG ?? 'alice';

  process.stdout.write(
    SNAPSHOT_MARKER +
      JSON.stringify({
        SVRNTY_DOMAIN,
        SVRNTY_BASE_URL,
        shareUrl: shareUrl(code, key),
        shareUrlShortNoKey: shareUrlShort(code),
        shareUrlShortWithKey: shareUrlShort(code, key),
        slugUrlShort: slugUrlShort(slug),
      }) +
      '\n',
  );
}
