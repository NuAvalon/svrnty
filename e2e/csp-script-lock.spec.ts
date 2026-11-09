import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { generateKey, enums } from 'openpgp';

/**
 * The script lock in a real browser: every kind of page loads under the policy and hydrates, injected
 * script is refused, and each response has its own nonce. Under `next dev` the policy also allows eval,
 * so the eval case only runs against a production build (E2E_PROD).
 */
const ROUTES: Array<[string, string]> = [
  ['/', 'home'],
  ['/msg', 'messages'],
  ['/c/notarealcode', 'join link'],
  ['/u/nobody-here', 'profile'],
  ['/nobody-here', 'rewritten profile'],
  ['/dev/seals', 'seals'],
  ['/no/such/page', 'not found'],
];

type Seen = { directive: string; blocked: string };
const seen = (page: Page) => page.evaluate(() => (window as unknown as { __csp: Seen[] }).__csp);

async function watch(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __csp: Seen[] };
    w.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => {
      w.__csp.push({ directive: e.effectiveDirective, blocked: e.blockedURI });
    });
  });
}

async function open(page: Page, path: string) {
  await page.goto(path, { waitUntil: 'load' });
  // React marks its root container once it has hydrated; if Next's inline scripts were refused this never happens.
  await page.waitForFunction(() => Object.keys(document).some((k) => k.startsWith('__reactContainer$')), null, { timeout: 45_000 });
}

test.describe('script lock', () => {
  test.setTimeout(150_000);

  for (const [path, name] of ROUTES) {
    test(`${name}: loads and hydrates with no violation`, async ({ page }) => {
      await watch(page);
      await open(page, path);
      await page.waitForTimeout(500);
      expect(await seen(page)).toEqual([]);
    });

    test(`${name}: injected script is refused`, async ({ page }) => {
      await watch(page);
      await open(page, path);
      const r = await page.evaluate(async () => {
        const w = window as unknown as { __csp: Seen[]; __a?: number; __b?: number; __c?: number };
        const before = w.__csp.length;
        const inline = document.createElement('script');
        inline.textContent = 'window.__a = 1';
        document.head.appendChild(inline);
        const guessed = document.createElement('script');
        guessed.setAttribute('nonce', 'AAAAAAAAAAAAAAAAAAAAAA==');
        guessed.textContent = 'window.__b = 1';
        document.head.appendChild(guessed);
        const foreign = document.createElement('script');
        foreign.src = 'https://example.invalid/x.js';
        document.head.appendChild(foreign);
        const holder = document.createElement('div');
        holder.innerHTML = '<img src="data:," onerror="window.__c = 1">';
        document.body.appendChild(holder);
        await new Promise((res) => setTimeout(res, 400));
        return { a: w.__a, b: w.__b, c: w.__c, events: w.__csp.slice(before) };
      });
      expect([r.a, r.b, r.c]).toEqual([undefined, undefined, undefined]);
      const blocked = r.events.map((e) => e.blocked);
      expect(blocked.filter((b) => b === 'inline').length).toBeGreaterThanOrEqual(3);
      expect(blocked).toContain('https://example.invalid/x.js');
    });
  }

  test('eval is refused in a production build', async ({ page }) => {
    test.skip(!process.env.E2E_PROD, 'next dev allows eval');
    await watch(page);
    await open(page, '/');
    // Playwright's evaluate is exempt from the eval check, so the attempt has to run from the page's own task.
    const name = await page.evaluate(() => new Promise<string>((resolve) => {
      setTimeout(() => {
        try { (0, eval)('1'); resolve('ran'); } catch (e) { resolve((e as Error).name); }
      }, 0);
    }));
    expect(name).toBe('EvalError');
  });

  for (const path of ['/', '/u/nobody-here']) {
    test(`${path}: each response has its own nonce, on every script, and may not be stored`, async ({ request }) => {
      const get = async () => {
        const r = await request.get(path);
        const csp = r.headersArray().filter((h) => h.name.toLowerCase() === 'content-security-policy');
        expect(csp.length).toBe(1);
        const nonce = /'nonce-([A-Za-z0-9+/=]+)'/.exec(csp[0].value)?.[1];
        expect(Buffer.from(nonce ?? '', 'base64').length).toBeGreaterThanOrEqual(16);
        const html = await r.text();
        const tags = html.match(/<script\b[^>]*>/g) ?? [];
        expect(tags.length).toBeGreaterThan(3);
        for (const t of tags) expect(t).toContain(`nonce="${nonce}"`);
        expect(r.headers()['cache-control']).toMatch(/no-store/);
        return nonce;
      };
      expect(await get()).not.toBe(await get());
    });
  }

  test('a real identity can be created, locked and unlocked under the policy', async ({ page }) => {
    await watch(page);
    await open(page, '/');
    await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
    await page.getByPlaceholder('Your name').fill('Policy E2E');
    await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
    await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
    await page.getByRole('button', { name: /^start$/i }).click();
    await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 60_000 });
    await page.getByRole('button', { name: /i have it/i }).click();
    await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
    expect(await seen(page)).toEqual([]);

    await page.getByRole('tab', { name: 'Identity' }).click();
    await page.getByTestId('identity-vault-toggle').click();
    await page.getByTestId('lock-now-btn').click();
    await page.getByPlaceholder('Enter passphrase').fill('e2e-passphrase-1234');
    await page.getByRole('button', { name: /^UNLOCK$/i }).click();
    await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 60_000 });
    expect(await seen(page)).toEqual([]);
  });

  test.describe('with a same-origin test harness', () => {
    // A service worker would take the harness request away from page.route.
    test.use({ serviceWorkers: 'block' });

    test('a key that needs the refused WebAssembly fails with an error instead of hanging', async ({ page }) => {
      test.skip(!process.env.E2E_PROD, 'next dev allows eval, and so WebAssembly');
      // OpenPGP.js opens Argon2-protected keys with WebAssembly, which this policy refuses. The app never makes such
      // keys, so the only way one arrives is a restore file; the restore path turns this rejection into a visible error.
      const { privateKey } = await generateKey({
        userIDs: [{ name: 'argon' }],
        passphrase: 'pw-pw-pw-pw',
        format: 'armored',
        config: { s2kType: enums.s2k.argon2, aeadProtect: true },
      });
      const bundle = execFileSync('npx', ['esbuild', '--bundle', '--format=iife', '--platform=browser', 'e2e/helpers/openpgp-probe-harness.ts'], { maxBuffer: 32 * 1024 * 1024 }).toString();
      await page.route('**/__openpgp_probe.js', (r) => r.fulfill({ contentType: 'text/javascript', body: bundle }));
      await watch(page);
      await open(page, '/');
      await page.addScriptTag({ url: '/__openpgp_probe.js' });
      const out = await page.evaluate(
        ([armored]) => new Promise<{ outcome: string; name?: string }>((resolve) => {
          // From the page's own task: Playwright's evaluate is exempt from the eval check.
          setTimeout(() => {
            try {
              const p = (window as unknown as { __probe: (a: string, b: string) => Promise<unknown> }).__probe(armored, 'pw-pw-pw-pw');
              const t = setTimeout(() => resolve({ outcome: 'hung' }), 30_000);
              p.then(() => { clearTimeout(t); resolve({ outcome: 'opened' }); },
                     (e: Error) => { clearTimeout(t); resolve({ outcome: 'rejected', name: `${e.name}: ${e.message}`.slice(0, 200) }); });
            } catch (e) {
              resolve({ outcome: 'threw', name: String(e).slice(0, 200) });
            }
          }, 0);
        }),
        [privateKey],
      );
      expect(out.outcome).toBe('rejected');
      expect((await seen(page)).map((v) => v.blocked)).toContain('wasm-eval');
    });
  });

  test('a client cannot pick the nonce', async ({ request }) => {
    const r = await request.get('/', {
      headers: { 'x-nonce': 'evilnonce', 'content-security-policy': "script-src 'nonce-evilnonce'" },
    });
    expect(r.headers()['content-security-policy']).not.toContain('evilnonce');
    expect(await r.text()).not.toContain('evilnonce');
  });

  test('a page served offline by the service worker runs its stored scripts with its stored nonce', async ({ page, context }) => {
    await watch(page);
    await page.addInitScript(() => localStorage.setItem('svrnty.ui', JSON.stringify({ appearance: 'light' })));
    await open(page, '/');
    await page.evaluate(() => navigator.serviceWorker.ready);
    await page.reload({ waitUntil: 'load' });
    await page.waitForFunction(() => !!navigator.serviceWorker.controller, null, { timeout: 30_000 });
    await page.reload({ waitUntil: 'load' });
    const stored = await page.evaluate(() => (document.querySelector('script[nonce]') as HTMLScriptElement).nonce);
    expect(stored?.length ?? 0).toBeGreaterThan(0);

    await context.setOffline(true);
    try {
      for (let i = 0; i < 2; i++) {
        await page.reload({ waitUntil: 'load' });
        const got = await page.evaluate(() => ({
          nonce: (document.querySelector('script[nonce]') as HTMLScriptElement).nonce,
          // The server sends data-appearance="dark"; only the inline boot script can make it light before React.
          appearance: document.documentElement.getAttribute('data-appearance'),
        }));
        // A response from the network would carry a new nonce, so the same one means this came from the cache.
        expect(got).toEqual({ nonce: stored, appearance: 'light' });
        expect(await seen(page)).toEqual([]);
      }
    } finally {
      await context.setOffline(false);
    }
  });
});
