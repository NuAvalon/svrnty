import { test, expect, type Page } from '@playwright/test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * Where a script that does run can send data. Each way out to another origin is tried for real, against a listener
 * that counts what arrives: it has to be refused, reported under its directive, and never arrive. A control shows the
 * listener would have seen it. What the app itself needs still works.
 *
 * This does not show that data can't leave. A script can still send through this origin, or navigate away: see
 * src/lib/csp.ts.
 */
let FOREIGN = '';
const arrived: string[] = [];
let listener: http.Server;

test.beforeAll(async () => {
  listener = http.createServer((req, res) => { arrived.push(req.url ?? ''); res.end(); });
  listener.on('upgrade', (req, socket) => { arrived.push(req.url ?? ''); socket.destroy(); });
  await new Promise<void>((done) => listener.listen(0, '127.0.0.1', done));
  FOREIGN = `http://127.0.0.1:${(listener.address() as AddressInfo).port}`;
});
test.afterAll(async () => { listener.closeAllConnections(); await new Promise((done) => listener.close(done)); });
test.beforeEach(() => { arrived.length = 0; });

// A fake camera, for the QR scanner case. These options can only be set for a whole file.
test.use({ launchOptions: { args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] }, permissions: ['camera'] });

type Seen = { directive: string; blocked: string };
const seen = (page: Page) => page.evaluate(() => (window as unknown as { __csp: Seen[] }).__csp);

async function open(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __csp: Seen[] };
    w.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => {
      w.__csp.push({ directive: e.effectiveDirective, blocked: e.blockedURI });
    });
  });
  await page.goto('/', { waitUntil: 'load' });
  await page.waitForFunction(() => Object.keys(document).some((k) => k.startsWith('__reactContainer$')), null, { timeout: 45_000 });
}

const DOORS: Array<[string, string]> = [
  ['fetch', 'connect-src'],
  ['XMLHttpRequest', 'connect-src'],
  ['sendBeacon', 'connect-src'],
  ['WebSocket', 'connect-src'],
  ['EventSource', 'connect-src'],
  ['image', 'img-src'],
  ['CSS background image', 'img-src'],
  ['stylesheet', 'style-src-elem'],
  ['font', 'font-src'],
  ['audio', 'media-src'],
  ['iframe', 'frame-src'],
];

test.describe('script egress', () => {
  test.setTimeout(120_000);

  for (const [door, directive] of DOORS) {
    test(`${door} to another origin is refused`, async ({ page }) => {
      await open(page);
      await page.evaluate(([name, host]) => {
        const swallow = (f: () => unknown) => { try { const r = f() as Promise<unknown> | undefined; r?.catch?.(() => {}); } catch { /* the door may throw instead */ } };
        const u = `${host}/x`;
        const add = (el: HTMLElement) => document.body.appendChild(el);
        switch (name) {
          case 'fetch': return swallow(() => fetch(u));
          case 'XMLHttpRequest': return swallow(() => { const x = new XMLHttpRequest(); x.open('GET', u); x.send(); });
          case 'sendBeacon': return swallow(() => navigator.sendBeacon(u, 'x'));
          case 'WebSocket': return swallow(() => new WebSocket(u.replace('http:', 'ws:')));
          case 'EventSource': return swallow(() => new EventSource(u));
          case 'image': return swallow(() => { new Image().src = u; });
          case 'CSS background image': return swallow(() => { const d = document.createElement('div'); d.style.backgroundImage = `url(${u})`; d.textContent = 'x'; add(d); });
          case 'stylesheet': return swallow(() => { const l = document.createElement('link'); l.rel = 'stylesheet'; l.href = u; document.head.appendChild(l); });
          case 'font': return swallow(() => { const s = document.createElement('style'); s.textContent = `@font-face{font-family:egress;src:url(${u})}`; document.head.appendChild(s); return document.fonts.load('16px egress'); });
          case 'audio': return swallow(() => { const a = new Audio(u); a.load(); });
          case 'iframe': return swallow(() => { const f = document.createElement('iframe'); f.src = u; add(f); });
        }
      }, [door, FOREIGN] as const);
      const host = new URL(FOREIGN).hostname;
      await expect.poll(async () => (await seen(page)).some((v) => v.directive === directive && v.blocked.includes(host)), { timeout: 10_000 }).toBe(true);
      await page.waitForTimeout(300);
      expect(arrived).toEqual([]);
    });
  }

  test('control: from this origin with no policy on the response, the listener does see the request', async ({ page }) => {
    const res = await page.goto('/api/version');
    expect(res!.headers()['content-security-policy']).toBeUndefined();
    await page.evaluate((u) => fetch(u, { mode: 'no-cors' }).catch(() => {}), `${FOREIGN}/control`);
    await expect.poll(() => arrived.length, { timeout: 10_000 }).toBeGreaterThan(0);
  });

  test('what the app needs still works, with no violation', async ({ page }) => {
    await open(page);
    const out = await page.evaluate(async () => {
      const loaded = (src: string) => new Promise<boolean>((res) => { const i = new Image(); i.onload = () => res(true); i.onerror = () => res(false); i.src = src; });
      const blob = URL.createObjectURL(new Blob(['<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>'], { type: 'image/svg+xml' }));
      const pixel = 'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==';
      const s = document.createElement('style'); s.textContent = 'body{--egress-check:1}'; document.head.appendChild(s);
      const d = document.createElement('div'); d.style.color = 'red'; document.body.appendChild(d);
      return { sameOrigin: (await fetch('/api/version')).status, data: await loaded(pixel), blob: await loaded(blob), inlineStyle: getComputedStyle(document.body).getPropertyValue('--egress-check').trim() };
    });
    expect(out).toEqual({ sameOrigin: 200, data: true, blob: true, inlineStyle: '1' });
    expect(await seen(page)).toEqual([]);
  });

  test('the QR scanner can show the camera', async ({ page }) => {
    await open(page);
    const playing = await page.evaluate(async () => {
      const v = document.createElement('video'); v.muted = true; document.body.appendChild(v);
      v.srcObject = await navigator.mediaDevices.getUserMedia({ video: true });
      await v.play();
      return v.readyState >= 2;
    });
    expect(playing).toBe(true);
    expect(await seen(page)).toEqual([]);
  });
});
