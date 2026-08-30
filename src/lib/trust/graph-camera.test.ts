import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  boundsOf,
  clientToWorld,
  fitCamera,
  zoomCamera,
  panCamera,
  cameraCenter,
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
