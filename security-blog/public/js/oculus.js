(() => {
  // EMPYREAN: the Oculus — a disc of gilded light crowning the hero. A slow
  // breathing glow, concentric gilt rings, a rotating inscriptional rim, and a
  // counter-rotating inner ring. Theme-aware (brighter on Nocturne, deeper on
  // Day), and frozen to a single static frame under prefers-reduced-motion.
  function initHeroOculus() {
    const canvas = document.getElementById('hero-oculus-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const TWO_PI = Math.PI * 2;
    const reduceMotion = window.matchMedia
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const state = {
      width: 0,
      height: 0,
      dpr: Math.min(window.devicePixelRatio || 1, 2),
      rafId: 0,
      running: false,
      retryFrames: 0,
      resizeObserver: null,
      gold: '224, 188, 104',  // gilt leaf
      glowMul: 1,
    };

    const applyTheme = () => {
      const light = document.documentElement.getAttribute('data-theme') === 'light';
      state.gold = light ? '178, 138, 74' : '224, 188, 104';
      state.glowMul = light ? 1.35 : 1;
      // a static design needs an explicit repaint when the theme flips
      if (reduceMotion && state.width && state.height) renderFrame(0);
    };

    const getSize = () => {
      let rect = canvas.getBoundingClientRect();
      if ((!rect.width || !rect.height) && canvas.parentElement) {
        rect = canvas.parentElement.getBoundingClientRect();
      }
      return {
        width: Math.max(0, Math.round(rect.width)),
        height: Math.max(0, Math.round(rect.height)),
      };
    };

    const resize = () => {
      const { width, height } = getSize();
      if (!width || !height) return false;

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      if (width !== state.width || height !== state.height || dpr !== state.dpr) {
        state.width = width;
        state.height = height;
        state.dpr = dpr;
        canvas.width = Math.max(1, Math.floor(width * dpr));
        canvas.height = Math.max(1, Math.floor(height * dpr));
        canvas.style.width = `${width}px`;
        canvas.style.height = `${height}px`;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        if (reduceMotion) renderFrame(0);
      }
      return true;
    };

    const renderFrame = (t) => {
      const { width: w, height: h, gold: g, glowMul: gm } = state;
      ctx.clearRect(0, 0, w, h);

      // crowning the hero: centered horizontally, riding a touch high
      const cx = w / 2;
      const cy = h * 0.42;
      const R = Math.min(Math.min(w, h) * 0.42, 280);
      const breathe = 0.5 + 0.5 * Math.sin(t * 1.5);  // 0..1

      // outer breathing glow — the spill of light over the title
      const glowR = R * (1.7 + breathe * 0.2);
      const glow = ctx.createRadialGradient(cx, cy, R * 0.08, cx, cy, glowR);
      glow.addColorStop(0, `rgba(${g}, ${(0.12 + breathe * 0.05) * gm})`);
      glow.addColorStop(0.45, `rgba(${g}, ${0.04 * gm})`);
      glow.addColorStop(1, `rgba(${g}, 0)`);
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(cx, cy, glowR, 0, TWO_PI);
      ctx.fill();

      // concentric gilt rings
      const rings = [0.40, 0.60, 0.80, 1.0];
      rings.forEach((rr, i) => {
        const outer = i === rings.length - 1;
        ctx.beginPath();
        ctx.lineWidth = outer ? 1.4 : 1;
        ctx.strokeStyle = `rgba(${g}, ${(outer ? 0.22 : 0.09) * gm})`;
        ctx.arc(cx, cy, R * rr, 0, TWO_PI);
        ctx.stroke();
      });

      // rotating inscriptional rim — fine ticks, every 6th a major mark
      const ticks = 72;
      const rot = t * 0.45;
      const tickOuter = R * 0.99;
      ctx.lineCap = 'round';
      for (let i = 0; i < ticks; i++) {
        const a = rot + (i / ticks) * TWO_PI;
        const major = i % 6 === 0;
        const inner = major ? R * 0.82 : R * 0.88;
        const ca = Math.cos(a);
        const sa = Math.sin(a);
        ctx.beginPath();
        ctx.lineWidth = major ? 1.4 : 0.7;
        ctx.strokeStyle = `rgba(${g}, ${(major ? 0.24 : 0.10) * gm})`;
        ctx.moveTo(cx + ca * inner, cy + sa * inner);
        ctx.lineTo(cx + ca * tickOuter, cy + sa * tickOuter);
        ctx.stroke();
      }

      // counter-rotating inner ring of dots
      const dots = 36;
      const rot2 = -t * 0.32;
      const dotR = R * 0.50;
      for (let i = 0; i < dots; i++) {
        const a = rot2 + (i / dots) * TWO_PI;
        ctx.beginPath();
        ctx.fillStyle = `rgba(${g}, ${0.14 * gm})`;
        ctx.arc(cx + Math.cos(a) * dotR, cy + Math.sin(a) * dotR, 0.9, 0, TWO_PI);
        ctx.fill();
      }

      // the gilded eye — central disc, faintly breathing
      const discR = R * 0.26 * (1 + breathe * 0.05);
      const disc = ctx.createRadialGradient(
        cx - discR * 0.3, cy - discR * 0.3, discR * 0.1, cx, cy, discR);
      disc.addColorStop(0, `rgba(${g}, ${0.42 * gm})`);
      disc.addColorStop(0.65, `rgba(${g}, ${0.16 * gm})`);
      disc.addColorStop(1, `rgba(${g}, 0)`);
      ctx.fillStyle = disc;
      ctx.beginPath();
      ctx.arc(cx, cy, discR, 0, TWO_PI);
      ctx.fill();
    };

    const draw = (now) => {
      if (!state.running) return;
      if (!state.width || !state.height) {
        state.rafId = requestAnimationFrame(draw);
        return;
      }
      renderFrame(now * 0.0006);
      state.rafId = requestAnimationFrame(draw);
    };

    const start = () => {
      if (!resize()) {
        state.retryFrames += 1;
        const delay = state.retryFrames < 90 ? requestAnimationFrame : setTimeout;
        delay(start, state.retryFrames < 90 ? undefined : 120);
        return;
      }
      if (reduceMotion) {
        renderFrame(0);
        return;
      }
      if (!state.running) {
        state.running = true;
        state.rafId = requestAnimationFrame(draw);
      }
    };

    const handleResize = () => { resize(); };

    applyTheme();
    window.addEventListener('themechange', applyTheme);

    start();

    if (typeof ResizeObserver !== 'undefined') {
      state.resizeObserver = new ResizeObserver(handleResize);
      state.resizeObserver.observe(canvas.parentElement || canvas);
    } else {
      window.addEventListener('resize', handleResize);
    }

    window.addEventListener('pageshow', handleResize);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') handleResize();
    });

    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(handleResize);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHeroOculus);
  } else {
    initHeroOculus();
  }
})();
