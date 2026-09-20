import { useEffect, useRef } from 'react';

/**
 * Fixed ambient background: green light beams from the top and bottom, drifting light
 * streaks, and slow floating particles. Purely decorative, pointer-events none.
 */
export default function Aurora() {
  const ref = useRef(null);

  useEffect(() => {
    const cv = ref.current;
    if (!cv) return undefined;
    const ctx = cv.getContext('2d');
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let w = 0;
    let h = 0;
    let raf = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const count = window.innerWidth < 768 ? 70 : 150;
    const dots = Array.from({ length: count }, () => ({
      x: Math.random(),
      y: Math.random(),
      r: 0.5 + Math.random() * 1.3,
      v: 0.006 + Math.random() * 0.02,
      a: 0.15 + Math.random() * 0.5,
      p: Math.random() * 6.28,
    }));

    const resize = () => {
      w = cv.clientWidth;
      h = cv.clientHeight;
      cv.width = w * dpr;
      cv.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener('resize', resize);

    let last = performance.now();
    const frame = (now) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      ctx.clearRect(0, 0, w, h);
      for (const d of dots) {
        if (!reduce) {
          d.y -= d.v * dt * 6;
          d.p += dt;
          if (d.y < -0.02) {
            d.y = 1.02;
            d.x = Math.random();
          }
        }
        const tw = 0.6 + 0.4 * Math.sin(d.p * 1.4);
        ctx.fillStyle = `rgba(140, 255, 70, ${d.a * tw})`;
        ctx.beginPath();
        ctx.arc(d.x * w, d.y * h, d.r, 0, 6.283);
        ctx.fill();
      }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      <div
        className="absolute inset-0"
        style={{
          background:
            'radial-gradient(70% 46% at 50% -10%, rgba(99,227,26,0.20), transparent 70%), radial-gradient(60% 40% at 50% 112%, rgba(99,227,26,0.14), transparent 70%)',
        }}
      />
      <div className="beam beam-top" />
      <div className="beam beam-bottom" />
      <div className="streak s1" />
      <div className="streak s2" />
      <div className="streak s3" />
      <canvas ref={ref} className="absolute inset-0 h-full w-full" />
    </div>
  );
}
