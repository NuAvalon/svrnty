import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  boundsOf,
  clientToWorld,
  fitCamera,
  zoomCamera,
  panCamera,
  cameraCenter,
  zoomLimits,
  wheelZoomFactor,
  hitTestNodes,
} from './graph-camera';

test('fitCamera matches viewport aspect and contains the bbox', () => {
  const cam = fitCamera({ minX: 100, minY: 100, maxX: 300, maxY: 220 }, 16 / 9, 20);
  assert.ok(Math.abs(cam.w / cam.h - 16 / 9) < 1e-6);
  assert.ok(cam.x <= 100);
  assert.ok(cam.y <= 100);
  assert.ok(cam.x + cam.w >= 300);
  assert.ok(cam.y + cam.h >= 220);
});

test('zoomCamera keeps the focal world point stable', () => {
  const cam = { x: 0, y: 0, w: 400, h: 400 };
  const next = zoomCamera(cam, 2, 100, 80, 40, 2000);
  assert.equal(next.w, 200);
  assert.equal(next.h, 200);
  // Point that was at (100,80) should still map to the same offset ratio
  const rx = (100 - cam.x) / cam.w;
  const ry = (80 - cam.y) / cam.h;
  assert.ok(Math.abs(100 - (next.x + rx * next.w)) < 1e-6);
  assert.ok(Math.abs(80 - (next.y + ry * next.h)) < 1e-6);
});

test('clientToWorld inverts linearly across the element', () => {
  const cam = { x: 10, y: 20, w: 100, h: 50 };
  const rect = { left: 0, top: 0, width: 200, height: 100 };
  const p = clientToWorld(cam, rect, 100, 50);
  assert.equal(p.x, 60);
  assert.equal(p.y, 45);
});

test('panCamera shifts the window opposite the drag', () => {
  const cam = { x: 0, y: 0, w: 100, h: 100 };
  const next = panCamera(cam, 10, -5);
  assert.equal(next.x, -10);
  assert.equal(next.y, 5);
});

test('boundsOf includes radii', () => {
  const b = boundsOf([{ x: 50, y: 50, radius: 10 }], 4);
  assert.equal(b.minX, 36);
  assert.equal(b.maxX, 64);
});

test('cameraCenter is the viewBox midpoint', () => {
  const c = cameraCenter({ x: 10, y: 20, w: 40, h: 30 });
  assert.equal(c.x, 30);
  assert.equal(c.y, 35);
});

test('zoomLimits keep fit between minW and maxW so zoom can step both ways', () => {
  const fit = 640;
  const { minW, maxW } = zoomLimits(fit);
  assert.ok(minW < fit, `minW ${minW} should be < fit`);
  assert.ok(maxW > fit, `maxW ${maxW} should be > fit`);
  const cam = { x: 0, y: 0, w: fit, h: fit };
  const inn = zoomCamera(cam, 1.12, 320, 320, minW, maxW);
  assert.ok(inn.w < cam.w && inn.w > minW * 0.99);
  const out = zoomCamera(cam, 1 / 1.12, 320, 320, minW, maxW);
  assert.ok(out.w > cam.w && out.w < maxW * 1.01);
});

test('wheelZoomFactor is a small step, not a jump to the stop', () => {
  const a = wheelZoomFactor(10, 0);
  const b = wheelZoomFactor(80, 0);
  assert.ok(a < 1 && a > 0.96, `small trackpad delta should be tiny, got ${a}`);
  assert.ok(b < 1 && b > 0.78, `clamped wheel tick should be stepwise, got ${b}`);
  const inn = wheelZoomFactor(-40, 0);
  assert.ok(inn > 1 && inn < 1.12);
});

test('hitTestNodes uses a pixel floor so zoomed-out seals stay tappable', () => {
  const cam = { x: 0, y: 0, w: 800, h: 800 };
  const rect = { left: 0, top: 0, width: 400, height: 400 };
  const nodes = [{ id: 'ada', x: 400, y: 400, radius: 10 }];
  // Center of the view
  assert.equal(hitTestNodes(nodes, cam, rect, 200, 200), 'ada');
  // 20px away — still inside minPx=22
  assert.equal(hitTestNodes(nodes, cam, rect, 218, 200), 'ada');
  assert.equal(hitTestNodes(nodes, cam, rect, 10, 10), null);
});
