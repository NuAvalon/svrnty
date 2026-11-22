// scripts/devin-know.ts — KNOW-layer commands for a THROWAWAY headless seat, against the DEV satellite only.
//
//   SVRNTY_AGENT_DIR=/abs/new/seat npx tsx scripts/devin-know.ts mint-throwaway    — mint a throwaway seat into a NEW directory; prints its card
//   SVRNTY_AGENT_DIR=/abs/seat      npx tsx scripts/devin-know.ts know-on <fp>      — consent to one peer already in the seat's book
//   SVRNTY_AGENT_DIR=/abs/seat      npx tsx scripts/devin-know.ts know-tick         — one KNOW sync tick (counts only)
//   SVRNTY_AGENT_DIR=/abs/seat      npx tsx scripts/devin-know.ts know-report --since <ISO-time>
//
// Thin wiring only: every rule lives in src/lib/headless/know-cli.ts (tested) and know-psi.ts. Separate from
// devin-comm.ts on purpose: its main() creates and chmods the seat directory before any command runs and falls back to a
// shared sandbox directory, and these commands must refuse both. Peers are admitted with devin-comm.ts admit.
//
// Order in main(): argv is checked, the seat directory comes from the environment only, then for every command except
// mint-throwaway the guards run BEFORE anything is read or written. Output is 8-hex prefixes and counts only.

import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { HeadlessStore } from '../src/lib/headless/headless-store';
import { mintHeadlessAgent, serializeMintArtifact, type SerializedMintArtifact } from '../src/lib/identity/headless-mint';
import { KnowCliGuardError, agentHomeFromEnv, assertSeatHome, buildKnowReport, knowOn, refuseDirInArgv } from '../src/lib/headless/know-cli';
import { headlessPsiOptions, runHeadlessKnowTick } from '../src/lib/headless/know-psi';

process.umask(0o077);

const out = (o: unknown): void => console.log(JSON.stringify(o));
const uid = (): number => (typeof process.getuid === 'function' ? process.getuid() : -1);
const flag = (rest: string[], name: string): string | undefined => {
  const i = rest.indexOf(name);
  return i >= 0 ? rest[i + 1] : undefined;
};

/** Counts only: array lengths and numbers/booleans, never a value. */
function countsOf(r: unknown): Record<string, number | boolean> {
  const o: Record<string, number | boolean> = {};
  for (const [k, v] of Object.entries((r ?? {}) as Record<string, unknown>)) {
    if (Array.isArray(v)) o[k] = v.length;
    else if (typeof v === 'number' || typeof v === 'boolean') o[k] = v;
  }
  return o;
}

async function mintThrowaway(dir: string): Promise<void> {
  // A NEW directory only: creating it here (0700 under the umask) means its permissions are known, never "fixed" afterwards.
  if (existsSync(dir)) throw new KnowCliGuardError('the seat directory already exists: mint into a new path');
  mkdirSync(dir, { mode: 0o700 });
  const s = serializeMintArtifact(await mintHeadlessAgent({ throwaway: true }));
  if (s.throwaway !== true) throw new KnowCliGuardError('the mint did not produce a throwaway');
  writeFileSync(`${dir}/mint.json`, JSON.stringify(s), { flag: 'wx', mode: 0o600 }); // create-only: never overwrite an identity
  chmodSync(`${dir}/mint.json`, 0o600);
  assertSeatHome(dir, s, { lstat: lstatSync }, uid());
  const id = s.public.card.identity;
  out({ durable_id: s.public.durable_id, fingerprint: id.fingerprint, public_key: id.public_key, pq_sig_public_key: id.pq_sig_public_key, pq_kem_public_key: id.pq_kem_public_key });
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  refuseDirInArgv(rest);
  const dir = agentHomeFromEnv(process.env);
  if (cmd === 'mint-throwaway') return mintThrowaway(dir);

  // Guards first: nothing below runs until the directory, the file and the throwaway flag all pass.
  const artifact = JSON.parse(readFileSync(`${dir}/mint.json`, 'utf8')) as SerializedMintArtifact;
  assertSeatHome(dir, artifact, { lstat: lstatSync }, uid());
  const store = new HeadlessStore({ path: `${dir}/store.json`, lockDir: dir });
  const ownerFp = artifact.public.durable_id;

  if (cmd === 'know-on') {
    const fp = rest[0];
    if (!fp) throw new KnowCliGuardError('usage: know-on <peer-fingerprint>');
    const r = await knowOn(artifact, store, fp);
    out(r);
    if (!r.ok) process.exitCode = 1;
    return;
  }
  if (cmd === 'know-tick') {
    const options = await headlessPsiOptions(artifact);
    if (!options) throw new KnowCliGuardError('this seat cannot sign or bind: no tick was run');
    out({ seat: ownerFp.slice(0, 8), tick: countsOf(await runHeadlessKnowTick(ownerFp, store, options)) });
    return;
  }
  if (cmd === 'know-report') {
    out({ seat: ownerFp.slice(0, 8), ...buildKnowReport(store, flag(rest, '--since')) });
    return;
  }
  throw new KnowCliGuardError(`unknown command ${cmd ?? '(none)'}`);
}

main().catch((e) => {
  console.error(e instanceof KnowCliGuardError ? e.message : `devin-know: ${e instanceof Error ? e.message : 'failed'}`);
  process.exit(e instanceof KnowCliGuardError ? 2 : 1);
});
