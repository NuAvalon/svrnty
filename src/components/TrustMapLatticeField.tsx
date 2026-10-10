'use client';

import { useEffect, useRef } from 'react';

/**
 * Atmospheric particle wash behind the lattice.
 * Motes are NOT contacts — decorative field only. Respects reduced motion.
 */
export function TrustMapLatticeField() {
  const ref = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const reduce =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

    const motes = Array.from({ length: 48 }, (_, i) => {
      const t = (i + 1) * 0.173;
      return {
        x: (Math.sin(t * 12.1) * 0.5 + 0.5),
        y: (Math.cos(t * 9.7) * 0.5 + 0.5),
        r: 0.4 + (i % 5) * 0.22,
        a: 0.04 + (i % 7) * 0.012,
        s: 0.08 + (i % 4) * 0.03,
        p: t,
      };
    });

    let raf = 0;
    let start = performance.now();

    const draw = (now: number) => {
      const parent = canvas.parentElement;
      const w = parent?.clientWidth ?? 1;
      const h = parent?.clientHeight ?? 1;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      if (canvas.width !== Math.floor(w * dpr) || canvas.height !== Math.floor(h * dpr)) {
        canvas.width = Math.floor(w * dpr);
        canvas.height = Math.floor(h * dpr);
        canvas.style.width = `${w}px`;
        canvas.style.height = `${h}px`;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const g = ctx.createRadialGradient(w * 0.5, h * 0.42, 8, w * 0.5, h * 0.42, Math.max(w, h) * 0.62);
      g.addColorStop(0, 'rgba(249,168,37,0.10)');
      g.addColorStop(0.45, 'rgba(255,122,26,0.04)');
      g.addColorStop(1, 'rgba(15,10,6,0)');
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, w, h);

      const t = reduce ? 0 : (now - start) / 1000;
      for (const m of motes) {
        const x = (m.x + (reduce ? 0 : Math.sin(t * m.s + m.p) * 0.04)) * w;
        const y = (m.y + (reduce ? 0 : Math.cos(t * m.s * 0.8 + m.p) * 0.04)) * h;
        ctx.beginPath();
        ctx.arc(x, y, m.r * 2.2, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(249,168,37,${m.a})`;
        ctx.fill();
      }

      if (!reduce) raf = requestAnimationFrame(draw);
    };

    if (reduce) {
      draw(start);
      return;
    }
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, []);

  return (
    <canvas
      ref={ref}
      aria-hidden
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 0,
      }}
    />
  );
}
