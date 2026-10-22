// Minimal force-directed graph on canvas. No dependencies.
(function () {
  const COLORS = {
    username: '#33ff66', full_name: '#ffb000', email: '#27e8ff',
    phone: '#c08bff', domain: '#ff7a1a', ip: '#ff2e4d', url: '#9affc0',
    account: '#27e8ff', host: '#ff9d4d', location: '#ff5be8',
    org: '#ffe066', image: '#8affb0', metadata: '#2a6b3e'
  };

  class Graph {
    constructor(canvas) {
      this.cv = canvas; this.ctx = canvas.getContext('2d');
      this.nodes = new Map(); this.links = [];
      this.hover = null; this.selected = null;
      this.onSelect = null;
      this.filter = null;          // optional predicate(data) -> boolean
      this._bind(); this._resize(); this._loop();
    }
    setFilter(fn) { this.filter = fn || null; }
    _shown(n) { return !this.filter || this.filter(n.data); }
    _resize() {
      const r = this.cv.getBoundingClientRect();
      this.cv.width = r.width; this.cv.height = r.height;
      this.cx = r.width / 2; this.cy = r.height / 2;
    }
    clear() { this.nodes.clear(); this.links = []; this.selected = null; }
    addNode(e) {
      if (this.nodes.has(e.id)) { this.nodes.get(e.id).data = e; return; }
      const ang = Math.random() * Math.PI * 2, rad = 60 + Math.random() * 120;
      this.nodes.set(e.id, {
        id: e.id, x: this.cx + Math.cos(ang) * rad, y: this.cy + Math.sin(ang) * rad,
        vx: 0, vy: 0, data: e, born: performance.now()
      });
    }
    addLink(l) {
      if (this.nodes.has(l.src) && this.nodes.has(l.dst)) this.links.push(l);
    }
    _bind() {
      addEventListener('resize', () => this._resize());
      this.cv.addEventListener('mousemove', ev => {
        const n = this._pick(ev); this.hover = n ? n.id : null;
        this.cv.style.cursor = n ? 'pointer' : 'default';
      });
      this.cv.addEventListener('click', ev => {
        const n = this._pick(ev);
        this.selected = n ? n.id : null;
        if (this.onSelect) this.onSelect(n ? n.data : null);
      });
    }
    _pick(ev) {
      const r = this.cv.getBoundingClientRect();
      const mx = ev.clientX - r.left, my = ev.clientY - r.top;
      for (const n of this.nodes.values()) {
        if (!this._shown(n)) continue;          // filtered-out nodes aren't pickable
        const rr = this._radius(n);
        if ((mx - n.x) ** 2 + (my - n.y) ** 2 < (rr + 4) ** 2) return n;
      }
      return null;
    }
    _radius(n) {
      const d = n.data;
      if (d.basis === 'seed') return 11;
      return d.basis === 'candidate' ? 5 : 7;
    }
    _physics() {
      const ns = [...this.nodes.values()];
      for (const a of ns) {
        for (const b of ns) {
          if (a === b) continue;
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy || 1;
          const f = 1400 / d2;
          a.vx += dx / Math.sqrt(d2) * f; a.vy += dy / Math.sqrt(d2) * f;
        }
        // gravity to center
        a.vx += (this.cx - a.x) * 0.004;
        a.vy += (this.cy - a.y) * 0.004;
      }
      for (const l of this.links) {
        const a = this.nodes.get(l.src), b = this.nodes.get(l.dst);
        if (!a || !b) continue;
        let dx = b.x - a.x, dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (dist - 90) * 0.01;
        a.vx += dx / dist * f; a.vy += dy / dist * f;
        b.vx -= dx / dist * f; b.vy -= dy / dist * f;
      }
      for (const a of ns) {
        a.vx *= 0.82; a.vy *= 0.82;
        if (a.data.basis !== 'seed') { a.x += a.vx; a.y += a.vy; }
        else { a.x += a.vx * .3; a.y += a.vy * .3; }
      }
    }
    _loop() {
      const ctx = this.ctx;
      this._physics();
      ctx.clearRect(0, 0, this.cv.width, this.cv.height);
      // links
      ctx.lineWidth = 1;
      for (const l of this.links) {
        const a = this.nodes.get(l.src), b = this.nodes.get(l.dst);
        if (!a || !b) continue;
        const dim = !this._shown(a) || !this._shown(b);
        ctx.strokeStyle = dim ? 'rgba(28,138,62,0.1)' : 'rgba(28,138,62,0.5)';
        ctx.setLineDash(l.basis === 'candidate' ? [3, 4] : []);   // dashed = unconfirmed
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      }
      ctx.setLineDash([]);
      // nodes
      const now = performance.now();
      for (const n of this.nodes.values()) {
        const c = COLORS[n.data.type] || '#33ff66';
        const r = this._radius(n);
        const age = now - n.born;
        if (!this._shown(n)) {
          // Filtered out: faint dot, no glow/label — still placed so the layout
          // doesn't jump when the filter changes.
          ctx.globalAlpha = 0.12; ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 7);
          ctx.fillStyle = c; ctx.fill(); ctx.globalAlpha = 1;
          continue;
        }
        if (age < 900) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, r + (1 - age / 900) * 18, 0, 7);
          ctx.strokeStyle = c; ctx.globalAlpha = age / 900 * .6;
          ctx.stroke(); ctx.globalAlpha = 1;
        }
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 7);
        if (n.data.basis === 'candidate' || n.data.basis === 'derived') {
          // Unconfirmed: hollow, dim — must not look as certain as an observation.
          ctx.globalAlpha = 0.55; ctx.strokeStyle = c; ctx.lineWidth = 1.5; ctx.stroke();
          ctx.globalAlpha = 1;
        } else {
          ctx.fillStyle = c; ctx.shadowColor = c; ctx.shadowBlur = 10;
          ctx.fill(); ctx.shadowBlur = 0;
        }
        const vs = n.data.validation && n.data.validation.state;
        if (vs === 'not_found' || vs === 'soft_404' || vs === 'unsafe') {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 3, 0, 7);
          ctx.strokeStyle = '#ff2e4d'; ctx.lineWidth = 2; ctx.stroke();
        }
        if (n.id === this.selected || n.id === this.hover) {
          ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.stroke();
          ctx.fillStyle = '#d7ffe4'; ctx.font = '11px monospace';
          const label = (n.data.value || '').slice(0, 28);
          ctx.fillText(label, n.x + r + 4, n.y + 3);
        }
      }
      requestAnimationFrame(() => this._loop());
    }
  }
  window.UnisintGraph = Graph;
})();
