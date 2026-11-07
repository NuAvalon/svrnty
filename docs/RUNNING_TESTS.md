# Running the unit tests

The unit tests are plain Node test files run through `tsx`. There is no single `npm test` script; you name the files you want.

## One file, or a few

```bash
npx --no-install tsx --test src/lib/sync/epoch-seam.test.ts src/lib/sync/epoch-wiring.test.ts
```

The summary at the bottom prints `# pass N` and `# fail N`. Read both: a run that crashed before any test started prints neither.

## Type check

```bash
npx --no-install tsc --noEmit -p .
```

Compare the number of `error TS` lines with the same command on the branch you started from. Do not compare against zero.

## A wide run

Pass several directories' worth of test files in one command, for example:

```bash
export TMPDIR=/path/on/a/large/disk
mkdir -p "$TMPDIR"
npx --no-install tsx --test $(find src/lib/identity src/lib/contacts src/lib/trust src/lib/sync src/lib/crypto src/lib/headless src/components -name '*.test.ts' -o -name '*.test.tsx' | sort)
```

## Set `TMPDIR` first

Some suites (the writer lock, the at-rest store, the atomic file, the hop trail) create scratch directories and do not always remove them. If `/tmp` is a small in-memory filesystem, a few wide runs in a row can fill it, and a later test then fails on a truncated write instead of on its own assertion. Point `TMPDIR` at a disk with room before a wide run, and delete leftover scratch directories from that location when you are done.

## Running a test on its own after a change to a shared file

Run the test files that import the changed file, then the wide run. A test that passes alone and fails in the wide run is usually sharing state (a module-level cache, a lock, a scratch directory); look there first.
