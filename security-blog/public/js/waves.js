// Proper Perlin noise implementation
class Noise {
  constructor(seed) {
    this.seed = seed || Math.random();
    this.p = [];
    for (let i = 0; i < 256; i++) this.p[i] = Math.floor((this.seed * 9301 + 49297) % 233280 / 233280 * 256);
    for (let i = 0; i < 256; i++) this.p[256 + i] = this.p[i];
  }

  fade(t) { return t * t * t * (t * (t * 6 - 15) + 10); }
  lerp(t, a, b) { return a + t * (b - a); }
  grad(hash, x, y) {
    const h = hash & 15;
    const u = h < 8 ? x : y;
    const v = h < 4 ? y : h === 12 || h === 14 ? x : 0;
    return ((h & 1) === 0 ? u : -u) + ((h & 2) === 0 ? v : -v);
  }

  perlin2(x, y) {
    const X = Math.floor(x) & 255;
    const Y = Math.floor(y) & 255;
    x -= Math.floor(x);
    y -= Math.floor(y);
    const u = this.fade(x);
    const v = this.fade(y);
    const A = this.p[X] + Y;
    const AA = this.p[A];
    const AB = this.p[A + 1];
    const B = this.p[X + 1] + Y;
    const BA = this.p[B];
    const BB = this.p[B + 1];

    return this.lerp(v, this.lerp(u, this.grad(this.p[AA], x, y),
                                     this.grad(this.p[BA], x - 1, y)),
                        this.lerp(u, this.grad(this.p[AB], x, y - 1),
                                     this.grad(this.p[BB], x - 1, y - 1)));
  }
}

class AWaves extends HTMLElement {
  connectedCallback() {
    this.svg = this.querySelector('.js-svg');
    this.lines = [];
    this.paths = [];
    this.noise = new Noise(Math.random());

    this.setSize();
    this.setLines();

    window.addEventListener('resize', this.onResize.bind(this));
    requestAnimationFrame(this.tick.bind(this));
  }

  onResize() {
    this.setSize();
    this.setLines();
  }

  setSize() {
    this.bounding = this.getBoundingClientRect();
    this.svg.style.width = `${this.bounding.width}px`;
    this.svg.style.height = `${this.bounding.height}px`;
  }

  setLines() {
    const { width, height } = this.bounding;

    this.lines = [];
    this.paths.forEach((path) => path.remove());
    this.paths = [];

    const xGap = 10;
    const yGap = 32;
    const oWidth = width + 200;
    const oHeight = height + 30;
    const totalLines = Math.ceil(oWidth / xGap);
    const totalPoints = Math.ceil(oHeight / yGap);
    const xStart = (width - xGap * totalLines) / 2;
    const yStart = (height - yGap * totalPoints) / 2;

    for (let i = 0; i <= totalLines; i++) {
      const points = [];

      for (let j = 0; j <= totalPoints; j++) {
        const point = {
          x: xStart + xGap * i,
          y: yStart + yGap * j,
          wave: { x: 0, y: 0 },
          cursor: { x: 0, y: 0, vx: 0, vy: 0 },
        };
        points.push(point);
      }

      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.classList.add('a__line');
      path.classList.add('js-line');
      this.svg.appendChild(path);
      this.paths.push(path);
      this.lines.push(points);
    }
  }

  movePoints(time) {
    const { lines, noise } = this;

    lines.forEach((points) => {
      points.forEach((p) => {
        // Wave movement - keep original logic
        const move = noise.perlin2(
          (p.x + time * 0.0125) * 0.002,
          (p.y + time * 0.005) * 0.0015
        ) * 12;
        p.wave.x = Math.cos(move) * 32;
        p.wave.y = Math.sin(move) * 16;

        // Cursor effects (but no actual cursor interaction)
        p.cursor.vx += (0 - p.cursor.x) * 0.005;
        p.cursor.vy += (0 - p.cursor.y) * 0.005;
        p.cursor.vx *= 0.925;
        p.cursor.vy *= 0.925;
        p.cursor.x += p.cursor.vx * 2;
        p.cursor.y += p.cursor.vy * 2;
        p.cursor.x = Math.min(100, Math.max(-100, p.cursor.x));
        p.cursor.y = Math.min(100, Math.max(-100, p.cursor.y));
      });
    });
  }

  moved(point, withCursorForce = true) {
    const coords = {
      x: point.x + point.wave.x + (withCursorForce ? point.cursor.x : 0),
      y: point.y + point.wave.y + (withCursorForce ? point.cursor.y : 0),
    };

    coords.x = Math.round(coords.x * 10) / 10;
    coords.y = Math.round(coords.y * 10) / 10;
    return coords;
  }

  drawLines() {
    const { lines, paths } = this;

    lines.forEach((points, lIndex) => {
      let p1 = this.moved(points[0], false);
      let d = `M ${p1.x} ${p1.y}`;

      points.forEach((p1, pIndex) => {
        const isLast = pIndex === points.length - 1;
        p1 = this.moved(p1, !isLast);
        d += `L ${p1.x} ${p1.y}`;
      });

      paths[lIndex].setAttribute('d', d);
    });
  }

  tick(time) {
    this.movePoints(time);
    this.drawLines();
    requestAnimationFrame(this.tick.bind(this));
  }
}

customElements.define('a-waves', AWaves);