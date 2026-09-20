import { useEffect, useRef } from 'react';

/**
 * A slowly rotating cloud of green points shaped like a two-lobed brain. Follows the pointer a little.
 * Canvas 2D, additive blending; point count drops on small screens.
 */
export default function ParticleOrb({ className = '' }) {
  const ref = useRef(null);

  useEffect(() => {
    const cv = ref.current;
    if (!cv) return undefined;
    const ctx = cv.getContext('2d');
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const N = window.innerWidth < 768 ? 1300 : 3000;

    // Fibonacci sphere with folded "cortex" ridges, split into two hemispheres.
    const pts = [];
    const golden = Math.PI * (1 + Math.sqrt(5));
    for (let i = 0; i < N; i++) {
      const k = i + 0.5;
      const phi = Math.acos(1 - (2 * k) / N);
      const theta = golden * k;
      let x = Math.sin(phi) * Math.cos(theta);
      let y = Math.cos(phi);
      let z = Math.sin(phi) * Math.sin(theta);
      const fold = 1 + 0.1 * Math.sin(7 * theta + 3 * phi) * Math.cos(4 * phi) + 0.045 * Math.sin(13 * phi + theta);
      x *= fold * 1.18;
      y *= fold * 0.92;
      z *= fold * 0.98;
      x += (x >= 0 ? 1 : -1) * 0.08; // gap between the hemispheres
      pts.push({ x, y, z, s: 0.8 + Math.random() * 1.4, a: 0.5 + Math.random() * 0.5, tw: Math.random() * 6.28 });
    }

    let w = 0;
    let h = 0;
    let raf = 0;
    let mx = 0;
    let my = 0;
    let tx = 0;
    let ty = 0;

    const resize = () => {
      w = cv.clientWidth;
      h = cv.clientHeight;
      cv.width = w * dpr;
      cv.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener('resize', resize);
    const onMove = (e) => {
      const r = cv.getBoundingClientRect();
      tx = ((e.clientX - r.left) / r.width - 0.5) * 2;
      ty = ((e.clientY - r.top) / r.height - 0.5) * 2;
    };
    window.addEventListener('pointermove', onMove);

    const t0 = performance.now();
    const draw = (now) => {
      const t = reduce ? 0 : (now - t0) / 1000;
      mx += (tx - mx) * 0.04;
      my += (ty - my) * 0.04;
      ctx.clearRect(0, 0, w, h);

      const cx = w / 2;
      const cy = h / 2;
      const R = Math.min(w, h) * 0.4;

      const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 1.5);
      g.addColorStop(0, 'rgba(99,227,26,0.20)');
      g.addColorStop(0.5, 'rgba(99,227,26,0.07)');
      g.addColorStop(1, 'rgba(99,227,26,0)');
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, w, h);

      const ry = t * 0.22 + mx * 0.55;
      const rx = -0.22 + my * 0.32;
      const cyw = Math.cos(ry);
      const syw = Math.sin(ry);
      const cxw = Math.cos(rx);
      const sxw = Math.sin(rx);

      ctx.globalCompositeOperation = 'lighter';
      ctx.fillStyle = '#86ff40';
      for (const p of pts) {
        const x1 = p.x * cyw + p.z * syw;
        const z1 = -p.x * syw + p.z * cyw;
        const y2 = p.y * cxw - z1 * sxw;
        const z2 = p.y * sxw + z1 * cxw;
        const persp = 1 / (1 + z2 * 0.32);
        const depth = (z2 + 1.4) / 2.8;
        const size = p.s * (0.6 + depth * 1.4) * dpr * 0.9;
        ctx.globalAlpha = Math.min(1, p.a * (0.3 + 0.9 * depth) * (0.8 + 0.2 * Math.sin(t * 2 + p.tw)));
        ctx.fillRect(cx + x1 * R * persp, cy + y2 * R * persp, size, size);
      }
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = 'source-over';
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', onMove);
    };
  }, []);

  return <canvas ref={ref} aria-hidden className={`pointer-events-none ${className}`} />;
}
