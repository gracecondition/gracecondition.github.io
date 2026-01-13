(() => {
  function initHeroWaveCanvas() {
    const canvas = document.getElementById('hero-wave-canvas');
    if (!canvas) {
      return;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      return;
    }

    const state = {
      width: 0,
      height: 0,
      dpr: Math.min(window.devicePixelRatio || 1, 2),
      lines: [],
      rafId: 0,
      running: false,
      retryFrames: 0,
      resizeObserver: null,
    };

    const config = {
      xGap: 9,
      yGap: 9,
      amplitude: 10,
      amplitudeBoost: 40,
      amplitudeSecondary: 4,
      amplitudeSecondaryBoost: 12,
      slope: 0,
      speed: 0.00085,
      alphaBase: 0.03,
      alphaBoost: 0.24,
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

    const buildLines = () => {
      const { width, height } = state;
      const oWidth = width + 160;
      const oHeight = height + 80;
      const cols = Math.ceil(oWidth / config.xGap);
      const rows = Math.ceil(oHeight / config.yGap);
      const xStart = (width - cols * config.xGap) / 2;
      const yStart = (height - rows * config.yGap) / 2;

      state.lines = Array.from({ length: cols + 1 }, (_, colIndex) => {
        const points = Array.from({ length: rows + 1 }, (_, j) => {
          const seed = (colIndex * 0.35) + (j * 0.22);
          return {
            y: yStart + j * config.yGap,
            seed,
          };
        });
        return {
          baseX: xStart + colIndex * config.xGap,
          colIndex,
          points,
        };
      });
    };

    const resize = () => {
      const { width, height } = getSize();
      if (!width || !height) {
        return false;
      }

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
        buildLines();
      }

      return true;
    };

    const blobs = [
      { phaseX: 0.2, phaseY: 1.6, speedX: 0.32, speedY: 0.24, radius: 0.22 },
      { phaseX: 2.1, phaseY: 0.7, speedX: 0.26, speedY: 0.28, radius: 0.18 },
      { phaseX: 3.4, phaseY: 2.4, speedX: 0.2, speedY: 0.22, radius: 0.26 },
      { phaseX: 4.6, phaseY: 3.1, speedX: 0.24, speedY: 0.18, radius: 0.2 },
    ];

    const bubbleField = (x, y, t) => {
      const minSize = Math.max(1, Math.min(state.width, state.height));
      let value = 0;

      blobs.forEach((blob) => {
        const cx = (Math.sin(t * blob.speedX + blob.phaseX) * 0.35 + 0.5) * state.width;
        const cy = (Math.cos(t * blob.speedY + blob.phaseY) * 0.35 + 0.5) * state.height;
        const radius = minSize * blob.radius;
        const dx = x - cx;
        const dy = y - cy;
        value += Math.exp(-(dx * dx + dy * dy) / (radius * radius));
      });

      return Math.min(1, value);
    };

    const waveField = (y, t, amp, ampSecondary) => {
      const wave1 = Math.sin(y * 0.013 + t * 1.35) * amp;
      const wave2 = Math.sin(y * 0.024 - t * 1.1) * ampSecondary;
      return wave1 + wave2;
    };

    const draw = (now) => {
      if (!state.running) {
        return;
      }

      if (!state.width || !state.height) {
        state.rafId = requestAnimationFrame(draw);
        return;
      }

      const t = now * config.speed;
      ctx.clearRect(0, 0, state.width, state.height);
      ctx.lineWidth = 1;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';

      const centerY = state.height * 0.5;

      state.lines.forEach((line) => {
        const bubbleLine = Math.pow(bubbleField(line.baseX, centerY, t), 1.4);
        const alpha = config.alphaBase + bubbleLine * config.alphaBoost;
        ctx.strokeStyle = `rgba(255, 255, 255, ${alpha})`;
        ctx.lineWidth = 0.45 + bubbleLine * 1.9;
        ctx.beginPath();

        line.points.forEach((point, pointIndex) => {
          const baseX = line.baseX + (point.y - centerY) * config.slope;
          const bubble = Math.pow(bubbleField(baseX, point.y, t), 1.3);
          const amp = config.amplitude + bubble * config.amplitudeBoost;
          const ampSecondary = config.amplitudeSecondary + bubble * config.amplitudeSecondaryBoost;
          const wave = waveField(point.y, t, amp, ampSecondary);
          const x = baseX + wave;
          const y = point.y;

          if (pointIndex === 0) {
            ctx.moveTo(x, y);
          } else {
            ctx.lineTo(x, y);
          }
        });

        ctx.stroke();
      });

      state.rafId = requestAnimationFrame(draw);
    };

    const start = () => {
      if (!resize()) {
        state.retryFrames += 1;
        const delay = state.retryFrames < 90 ? requestAnimationFrame : setTimeout;
        delay(start, state.retryFrames < 90 ? undefined : 120);
        return;
      }

      if (!state.running) {
        state.running = true;
        state.rafId = requestAnimationFrame(draw);
      }
    };

    const handleResize = () => {
      resize();
    };

    start();

    if (typeof ResizeObserver !== 'undefined') {
      state.resizeObserver = new ResizeObserver(handleResize);
      const target = canvas.parentElement || canvas;
      state.resizeObserver.observe(target);
    } else {
      window.addEventListener('resize', handleResize);
    }

    window.addEventListener('pageshow', handleResize);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        handleResize();
      }
    });

    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(handleResize);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHeroWaveCanvas);
  } else {
    initHeroWaveCanvas();
  }
})();
