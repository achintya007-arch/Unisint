// Matrix rain background. Toggleable via window.UNISINT_FX.
(function () {
  const cv = document.getElementById('matrix');
  const ctx = cv.getContext('2d');
  const chars = 'アイウエオ0123456789ABCDEF<>/\\{}[]#$%&@UNISINT'.split('');
  let cols, drops, raf, running = true;

  function resize() {
    cv.width = innerWidth; cv.height = innerHeight;
    cols = Math.floor(cv.width / 14);
    drops = Array(cols).fill(1);
  }
  function draw() {
    if (!running) { raf = requestAnimationFrame(draw); return; }
    ctx.fillStyle = 'rgba(2,6,10,0.08)';
    ctx.fillRect(0, 0, cv.width, cv.height);
    ctx.fillStyle = '#33ff66';
    ctx.font = '14px monospace';
    for (let i = 0; i < drops.length; i++) {
      const t = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(t, i * 14, drops[i] * 14);
      if (drops[i] * 14 > cv.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
    raf = requestAnimationFrame(draw);
  }
  addEventListener('resize', resize);
  resize(); draw();

  window.UNISINT_FX = {
    set(on) {
      running = on;
      cv.style.display = on ? 'block' : 'none';
      document.getElementById('scanlines').style.display = on ? 'block' : 'none';
    }
  };
})();
