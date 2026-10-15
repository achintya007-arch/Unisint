// UNISINT console controller.
(function () {
  const $ = s => document.querySelector(s);
  const el = (t, c, txt) => { const n = document.createElement(t); if (c) n.className = c; if (txt != null) n.textContent = txt; return n; };

  let MODE = 'self', GRAPH = null, DOSSIER = null, SNAP = { entities: [], links: [] };
  let ws = null, UPLOAD = null;

  /* ---------- BOOT SEQUENCE ---------- */
  const BOOT = [
    'UNISINT BIOS v1.0 .... OK',
    'loading entity engine ................ OK',
    'mounting adapter bus ................. OK',
    'calibrating link graph ............... OK',
    'arming matrix renderer ............... OK',
    '',
    '>> UNIFIED OSINT CONSOLE READY',
  ];
  function boot() {
    const log = $('#boot-log'); let i = 0, line = 0, buf = '';
    const tick = () => {
      if (line >= BOOT.length) { setTimeout(showGate, 350); return; }
      const cur = BOOT[line];
      if (i <= cur.length) { log.textContent = buf + cur.slice(0, i) + '_'; i++; setTimeout(tick, 12); }
      else { buf += cur + '\n'; line++; i = 0; setTimeout(tick, 60); }
    };
    tick();
  }
  function showGate() { $('#boot').classList.add('hidden'); $('#gate').classList.remove('hidden'); }

  $('#auth-chk').addEventListener('change', e => $('#auth-ok').disabled = !e.target.checked);
  $('#auth-ok').addEventListener('click', () => {
    $('#gate').classList.add('hidden'); $('#app').classList.remove('hidden');
    initApp();
  });

  /* ---------- APP INIT ---------- */
  function initApp() {
    GRAPH = new UnisintGraph($('#graph'));
    GRAPH.onSelect = showNode;

    document.querySelectorAll('.tab').forEach(t =>
      t.addEventListener('click', () => switchView(t.dataset.view)));
    document.querySelectorAll('.mode').forEach(m =>
      m.addEventListener('click', () => {
        document.querySelectorAll('.mode').forEach(x => x.classList.remove('active'));
        m.classList.add('active'); MODE = m.dataset.mode;
        $('#target').placeholder = MODE === 'recon'
          ? 'domain or IP you own / are authorized to test'
          : 'your username, email, phone, domain, IP — or drop an image';
      }));

    const inp = $('#target');
    inp.addEventListener('input', debounce(updateTypeTag, 250));
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') engage(); });
    $('#engage').addEventListener('click', engage);
    $('#cancel').addEventListener('click', () => ws && ws.send(JSON.stringify({ action: 'cancel' })));

    // image drop
    const drop = $('#target');
    ['dragover', 'drop'].forEach(ev => drop.addEventListener(ev, e => e.preventDefault()));
    drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) uploadImage(f); });
    $('#imgfile').addEventListener('change', e => { if (e.target.files[0]) uploadImage(e.target.files[0]); });

    $('#export-json').addEventListener('click', exportJSON);
    $('#export-csv').addEventListener('click', exportCSV);
    $('#export-html').addEventListener('click', exportHTML);
    $('#refresh-arsenal').addEventListener('click', loadArsenal);
    $('#save-keys').addEventListener('click', saveKeys);
    $('#fx-toggle').addEventListener('change', e => window.UNISINT_FX.set(e.target.checked));

    // Report-a-gap modal
    $('#report-gap').addEventListener('click', openGap);
    $('#gap-cancel').addEventListener('click', () => $('#gap-modal').classList.add('hidden'));
    $('#gap-save').addEventListener('click', saveGap);

    loadArsenal(); loadConfig();
  }

  async function openGap() {
    $('#gap-modal').classList.remove('hidden');
    try {
      const d = await (await fetch('/api/gaps')).json();
      $('#gap-count').textContent = d.count ? `${d.count} gap(s) logged so far → ${d.path}` : '';
    } catch { }
  }
  async function saveGap() {
    const body = {
      what: $('#gap-what').value, missing: $('#gap-missing').value,
      severity: $('#gap-sev').value,
    };
    if (!body.what && !body.missing) { $('#gap-modal').classList.add('hidden'); return; }
    try {
      const d = await (await fetch('/api/gap', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json();
      log(`gap logged (${d.count} total) → ${d.path}`, 'ok');
    } catch { log('could not save gap', 'err'); }
    $('#gap-what').value = ''; $('#gap-missing').value = '';
    $('#gap-modal').classList.add('hidden');
  }

  function switchView(v) {
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.view === v));
    document.querySelectorAll('.view').forEach(x => x.classList.toggle('active', x.id === 'view-' + v));
    if (v === 'map') renderMap();
  }

  function debounce(fn, ms) { let h; return (...a) => { clearTimeout(h); h = setTimeout(() => fn(...a), ms); }; }

  async function updateTypeTag() {
    const v = $('#target').value.trim();
    if (!v) { $('#type-tag').textContent = '?'; return; }
    try {
      const r = await fetch('/api/detect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value: v }) });
      $('#type-tag').textContent = (await r.json()).type.toUpperCase();
    } catch { }
  }

  async function uploadImage(file) {
    log('uploading ' + file.name + ' ...', 'run');
    const fd = new FormData(); fd.append('file', file);
    const r = await fetch('/api/upload', { method: 'POST', body: fd });
    UPLOAD = await r.json();
    $('#target').value = UPLOAD.name; $('#type-tag').textContent = 'IMAGE';
    log('image staged: ' + UPLOAD.name, 'ok');
  }

  /* ---------- SCAN ---------- */
  function engage() {
    const v = $('#target').value.trim();
    if (!v && !UPLOAD) return;
    GRAPH.clear(); $('#dossier').innerHTML = ''; $('#terminal').innerHTML = '';
    SNAP = { entities: [], links: [] };
    setStatus('run');
    $('#engage').classList.add('hidden'); $('#cancel').classList.remove('hidden');

    let targets;
    if (UPLOAD && $('#type-tag').textContent === 'IMAGE')
      targets = [{ type: 'image', value: UPLOAD.name, path: UPLOAD.path }];
    else targets = [v];

    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => ws.send(JSON.stringify({
      mode: MODE, preset: $('#preset').value, authorized: true, targets
    }));
    ws.onmessage = ev => handle(JSON.parse(ev.data));
    ws.onclose = () => { setStatus('idle'); $('#engage').classList.remove('hidden'); $('#cancel').classList.add('hidden'); UPLOAD = null; };
    ws.onerror = () => log('socket error', 'err');
  }

  function handle(m) {
    if (m.type === 'log') log(m.msg, m.level, m.module);
    else if (m.type === 'entity') { GRAPH.addNode(m.entity); upsert(SNAP.entities, m.entity); bumpExposure(); liveDossier(); }
    else if (m.type === 'link') { GRAPH.addLink(m.link); SNAP.links.push(m.link); }
    else if (m.type === 'done') log(`done — ${m.entities} entities, ${m.links} links`, 'ok');
    else if (m.type === 'dossier') { DOSSIER = m.dossier; DOSSIER._final = true; renderDossier(); }
  }
  function upsert(arr, e) { const i = arr.findIndex(x => x.id === e.id); if (i >= 0) arr[i] = e; else arr.push(e); }
  function bumpExposure() {
    const n = SNAP.entities.filter(e => e.type === 'account').length;
    $('#exposure').textContent = n;
  }

  /* ---------- TERMINAL ---------- */
  function log(msg, level = 'info', module = '') {
    const t = $('#terminal');
    const line = el('div', 'line l-' + level);
    const ts = new Date().toLocaleTimeString('en-GB');
    line.innerHTML = `<span class="ts">${ts}</span> ${module ? '' : ''}${escapeHtml(msg)}`;
    t.appendChild(line); t.scrollTop = t.scrollHeight;
    while (t.children.length > 600) t.removeChild(t.firstChild);
  }
  function escapeHtml(s) { return (s + '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }

  function setStatus(s) {
    const n = $('#status'); n.textContent = s.toUpperCase();
    n.classList.toggle('run', s === 'run');
  }

  /* ---------- NODE INFO ---------- */
  function showNode(d) {
    const box = $('#nodeinfo');
    if (!d) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');
    const m = d.meta || {};
    let html = `<b>${d.type.toUpperCase()}</b><br>${escapeHtml(d.value)}<br>` +
      `<small>src: ${(m.sources || [d.source]).join(', ')} · conf ${(d.confidence || 0).toFixed(2)}</small>`;
    if (m.url) html += `<br><a href="${m.url}" target="_blank" rel="noopener">open ↗</a>`;
    if (m.links) html += '<br>' + m.links.map(l => `<a href="${l.url}" target="_blank" rel="noopener">${l.name}</a>`).join(' · ');
    box.innerHTML = html;
  }

  /* ---------- DOSSIER ---------- */
  // Build a dossier client-side from streamed entities so the panel fills
  // live; the server's final dossier (with risk flags) refines it.
  const liveDossier = debounce(() => {
    if (DOSSIER && DOSSIER._final) return;      // server dossier arrived
    const by = {};
    SNAP.entities.forEach(e => (by[e.type] = by[e.type] || []).push(e));
    const vals = t => (by[t] || []).sort((a, b) => (b.confidence || 0) - (a.confidence || 0)).map(e => e.value);
    DOSSIER = {
      names: vals('full_name').slice(0, 8), usernames: vals('username').slice(0, 15),
      emails: vals('email').slice(0, 15), phones: vals('phone').slice(0, 8),
      locations: vals('location').slice(0, 10), orgs: vals('org').slice(0, 8),
      domains: vals('domain').slice(0, 10), hosts: vals('host').slice(0, 100),
      ips: vals('ip').slice(0, 20),
      accounts: (by['account'] || []).map(e => ({ site: (e.meta || {}).site || '?', url: (e.meta || {}).url || e.value, confidence: +(e.confidence || 0).toFixed(2) })),
      findings: (by['metadata'] || []).map(e => ({ text: e.value, source: e.source, meta: e.meta || {}, confidence: +(e.confidence || 0).toFixed(2) })),
      exposure_count: (by['account'] || []).length, risk_flags: []
    };
    renderDossier();
  }, 300);

  function renderDossier() {
    const d = DOSSIER; if (!d) return;
    $('#exposure').textContent = d.exposure_count;
    $('#risk').innerHTML = (d.risk_flags || []).map(r => '⚠ ' + escapeHtml(r)).join('<br>');
    const root = $('#dossier'); root.innerHTML = '';

    const chipGroup = (title, arr) => {
      if (!arr || !arr.length) return;
      const g = el('div', 'dgroup'); g.appendChild(el('h4', null, title));
      arr.forEach(v => g.appendChild(el('span', 'chip', v)));
      root.appendChild(g);
    };
    if (d.names && d.names.length) chipGroup('LIKELY NAMES', d.names);
    chipGroup('USERNAMES', d.usernames);
    chipGroup('EMAILS', d.emails);
    chipGroup('PHONES', d.phones);
    chipGroup('LOCATIONS', d.locations);
    chipGroup('ORGANIZATIONS', d.orgs);
    chipGroup('DOMAINS', d.domains);
    chipGroup('HOSTS / SUBDOMAINS', d.hosts);
    chipGroup('IP ADDRESSES', d.ips);

    if (d.accounts && d.accounts.length) {
      const g = el('div', 'dgroup'); g.appendChild(el('h4', null, 'ACCOUNTS (' + d.accounts.length + ')'));
      d.accounts.forEach(a => {
        const row = el('div', 'acc-row');
        row.appendChild(el('span', 'acc-site', a.site || '?'));
        const link = el('a', null, a.url); link.href = a.url; link.target = '_blank'; link.rel = 'noopener';
        row.appendChild(link);
        row.appendChild(el('span', 'conf', a.confidence));
        g.appendChild(row);
      });
      root.appendChild(g);
    }
    if (d.findings && d.findings.length) {
      const g = el('div', 'dgroup'); g.appendChild(el('h4', null, 'FINDINGS'));
      d.findings.forEach(f => {
        const row = el('div', 'acc-row');
        row.appendChild(el('span', 'acc-site', f.source));
        row.appendChild(el('span', null, f.text));
        g.appendChild(row);
      });
      root.appendChild(g);
    }

    if (d.remediation && d.remediation.length) {
      const g = el('div', 'dgroup remediation');
      g.appendChild(el('h4', null, 'REMEDIATION // FIX THIS'));
      d.remediation.forEach(r => {
        const card = el('div', 'rem-card sev-' + (r.severity || 'medium'));
        const head = el('div', 'rem-head');
        head.appendChild(el('span', 'rem-sev', (r.severity || 'medium').toUpperCase()));
        head.appendChild(el('span', 'rem-title', r.title));
        card.appendChild(head);
        card.appendChild(el('div', 'rem-action', r.action));
        if (r.url) {
          const a = el('a', 'rem-link', r.url); a.href = r.url; a.target = '_blank'; a.rel = 'noopener';
          card.appendChild(a);
        }
        if (r.links) {
          const wrap = el('div', 'rem-links');
          r.links.forEach(l => {
            const a = el('a', null, l.name); a.href = l.url; a.target = '_blank'; a.rel = 'noopener';
            wrap.appendChild(a);
          });
          card.appendChild(wrap);
        }
        g.appendChild(card);
      });
      root.appendChild(g);
    }
  }

  /* ---------- MAP ---------- */
  let MAP = null, leafletTried = false;
  function coords() {
    const out = [];
    SNAP.entities.forEach(e => {
      const m = e.meta || {};
      if (typeof m.lat === 'number' && typeof m.lon === 'number') out.push({ lat: m.lat, lon: m.lon, label: e.value });
      else if (e.type === 'location' && /^-?\d+\.\d+,-?\d+\.\d+$/.test(e.value)) {
        const [a, b] = e.value.split(','); out.push({ lat: +a, lon: +b, label: e.value });
      }
    });
    return out;
  }
  function renderMap() {
    const pts = coords();
    const host = $('#map');
    if (!pts.length) { host.innerHTML = '<div style="padding:20px;color:var(--dim)">no geo coordinates found</div>'; return; }
    if (!leafletTried) {
      leafletTried = true;
      const css = el('link'); css.rel = 'stylesheet'; css.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
      document.head.appendChild(css);
      const s = el('script'); s.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
      s.onload = () => drawMap(pts); s.onerror = () => fallbackMap(pts);
      document.body.appendChild(s);
    } else if (window.L) drawMap(pts); else fallbackMap(pts);
  }
  function drawMap(pts) {
    if (!window.L) return fallbackMap(pts);
    $('#map').innerHTML = '';
    if (MAP) { MAP.remove(); MAP = null; }
    MAP = L.map('map').setView([pts[0].lat, pts[0].lon], 5);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(MAP);
    pts.forEach(p => L.marker([p.lat, p.lon]).addTo(MAP).bindPopup(p.label));
  }
  function fallbackMap(pts) {
    $('#map').innerHTML = '<div style="padding:20px">' +
      pts.map(p => `<div><a href="https://www.openstreetmap.org/?mlat=${p.lat}&mlon=${p.lon}#map=14/${p.lat}/${p.lon}" target="_blank" rel="noopener">${p.label}</a></div>`).join('') +
      '</div>';
  }

  /* ---------- ARSENAL ---------- */
  async function loadArsenal() {
    const r = await fetch('/api/arsenal'); const d = await r.json();
    const root = $('#arsenal'); root.innerHTML = '';
    d.tools.forEach(t => {
      const c = el('div', 'tool');
      c.appendChild(el('div', 'tn', t.label));
      c.appendChild(el('div', 'tp', t.purpose));
      let cls = 'off', txt = '○ MISSING (' + t.kind + ')';
      if (t.installed && t.failures > 0) { cls = 'failing'; txt = '● ONLINE • FAILING (' + t.failures + ')'; }
      else if (t.installed) { cls = 'on'; txt = '● ONLINE'; }
      c.appendChild(el('div', 'st ' + cls, txt));
      if (!t.installed) {
        const b = el('button', 'btn sm', 'INSTALL'); b.style.marginTop = '8px';
        b.onclick = async () => {
          b.textContent = 'INSTALLING…'; b.disabled = true;
          const res = await (await fetch('/api/install/' + t.name, { method: 'POST' })).json();
          b.textContent = res.ok ? 'DONE' : 'FAILED'; log('install ' + t.name + ': ' + (res.ok ? 'ok' : res.msg), res.ok ? 'ok' : 'err');
          if (res.ok) loadArsenal();
        };
        c.appendChild(b);
      }
      root.appendChild(c);
    });
  }

  /* ---------- SETTINGS ---------- */
  const KEY_NAMES = ['shodan', 'hibp', 'hunter', 'virustotal', 'anthropic'];
  async function loadConfig() {
    const d = await (await fetch('/api/config')).json();
    const root = $('#keys'); root.innerHTML = '';
    KEY_NAMES.forEach(k => {
      const lab = el('label');
      lab.appendChild(el('span', null, k));
      const inp = el('input'); inp.type = 'password'; inp.dataset.key = k;
      inp.placeholder = d.api_keys_set[k] ? '•••• set' : 'not set';
      lab.appendChild(inp); root.appendChild(lab);
    });
    $('#fx-toggle').checked = d.effects !== false;
    const cases = $('#cases'); cases.innerHTML = '';
    (d.cases || []).forEach(c => cases.appendChild(el('div', 'case-row',
      `${c.when || ''} · ${c.mode || ''} · ${JSON.stringify(c.target)}`)));
  }
  async function saveKeys() {
    const keys = {};
    document.querySelectorAll('#keys input').forEach(i => { if (i.value) keys[i.dataset.key] = i.value; });
    await fetch('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ api_keys: keys, effects: $('#fx-toggle').checked }) });
    log('settings saved', 'ok'); loadConfig(); loadArsenal();
  }

  /* ---------- EXPORT ---------- */
  function download(name, text, type) {
    const b = new Blob([text], { type }); const u = URL.createObjectURL(b);
    const a = el('a'); a.href = u; a.download = name; a.click(); URL.revokeObjectURL(u);
  }
  function exportJSON() {
    download('unisint-case.json', JSON.stringify({ snapshot: SNAP, dossier: DOSSIER }, null, 2), 'application/json');
  }
  function csvCell(v) { return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; }
  function exportCSV() {
    const rows = [['type', 'value', 'source', 'confidence', 'site', 'url']];
    SNAP.entities.forEach(e => {
      const m = e.meta || {};
      rows.push([e.type, e.value, (m.sources || [e.source]).join('|'),
        (e.confidence || 0).toFixed(2), m.site || '', m.url || '']);
    });
    download('unisint-entities.csv', rows.map(r => r.map(csvCell).join(',')).join('\n'), 'text/csv');
  }
  function exportHTML() {
    const d = DOSSIER || {};
    const sec = (t, a) => a && a.length ? `<h2>${t}</h2><p>${a.map(escapeHtml).join(', ')}</p>` : '';
    const acc = (d.accounts || []).map(a => `<li><b>${escapeHtml(a.site)}</b> — <a href="${a.url}">${escapeHtml(a.url)}</a> (${a.confidence})</li>`).join('');
    const find = (d.findings || []).map(f => `<li>[${escapeHtml(f.source)}] ${escapeHtml(f.text)}</li>`).join('');
    const rem = (d.remediation || []).map(r => `<li><b>[${escapeHtml((r.severity || '').toUpperCase())}] ${escapeHtml(r.title)}</b><br>${escapeHtml(r.action)}${r.url ? ` <a href="${r.url}">${escapeHtml(r.url)}</a>` : ''}${(r.links || []).map(l => ` · <a href="${l.url}">${escapeHtml(l.name)}</a>`).join('')}</li>`).join('');
    const html = `<!doctype html><meta charset=utf-8><title>UNISINT dossier</title>
<style>body{font-family:monospace;background:#02060a;color:#33ff66;padding:40px;max-width:900px;margin:auto}
h1{color:#ffb000}h2{color:#27e8ff;border-bottom:1px solid #1c8a3e}a{color:#27e8ff}li{margin:3px 0}</style>
<h1>UNISINT DOSSIER</h1><p>mode: ${escapeHtml(SNAP.mode || '')} · generated ${new Date().toISOString()}</p>
<p><b>${d.exposure_count || 0}</b> accounts/signals. Risk: ${(d.risk_flags || []).map(escapeHtml).join('; ') || 'none flagged'}</p>
${sec('Names', d.names)}${sec('Usernames', d.usernames)}${sec('Emails', d.emails)}
${sec('Phones', d.phones)}${sec('Locations', d.locations)}${sec('Orgs', d.orgs)}
${sec('Domains', d.domains)}${sec('Hosts', d.hosts)}${sec('IPs', d.ips)}
<h2>Accounts</h2><ul>${acc}</ul><h2>Findings</h2><ul>${find}</ul>
${rem ? `<h2>Remediation — Fix This</h2><ul>${rem}</ul>` : ''}
<hr><p><small>Public-source OSINT. For authorized self-audit / assessment only.</small></p>`;
    download('unisint-dossier.html', html, 'text/html');
  }

  boot();
})();
