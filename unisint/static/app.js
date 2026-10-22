// UNISINT console controller.
// Security: all untrusted text (tool output, search snippets, URLs) is
// rendered via textContent; links are built with safeLink(), which only
// accepts http(s) URLs. No untrusted data ever reaches innerHTML.
(function () {
  const $ = s => document.querySelector(s);
  const el = (t, c, txt) => { const n = document.createElement(t); if (c) n.className = c; if (txt != null) n.textContent = txt; return n; };

  let MODE = 'self', GRAPH = null, DOSSIER = null;
  let SNAP = { entities: [], links: [], pivots: [] };
  let ws = null, UPLOAD = null, FINAL = false, TARGETS = [];
  // Client-side view filter (dossier rows + graph nodes). Each dimension is a
  // Set of allowed values, or absent for "no constraint".
  const FILTER = { type: null, source: null, vstate: null, basis: null };

  function safeHref(u) {
    if (typeof u !== 'string') return null;
    try { const x = new URL(u); return (x.protocol === 'http:' || x.protocol === 'https:') ? x.href : null; }
    catch { return null; }
  }
  function safeLink(url, text, cls) {
    const href = safeHref(url);
    if (!href) return el('span', 'nolink', text || url || '');
    const a = el('a', cls || null, text || href);
    a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer';
    return a;
  }
  const badge = (txt, cls, title) => { const b = el('span', 'badge ' + (cls || ''), txt); if (title) b.title = title; return b; };

  /* ---------- BOOT ---------- */
  const BOOT = [
    'UNISINT v3.0 .... OK',
    'loading evidence engine .............. OK',
    'arming SSRF guard .................... OK',
    'loading pivot policy ................. OK',
    'health-checking adapters ............. OK',
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
    $('#gate').classList.add('hidden'); $('#app').classList.remove('hidden'); initApp();
  });

  /* ---------- INIT ---------- */
  function initApp() {
    GRAPH = new UnisintGraph($('#graph'));
    GRAPH.onSelect = showNode;
    document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => switchView(t.dataset.view)));
    document.querySelectorAll('.mode').forEach(m => m.addEventListener('click', () => setMode(m.dataset.mode)));
    const inp = $('#target');
    inp.addEventListener('input', debounce(updateTypeTag, 250));
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') engage(); });
    $('#engage').addEventListener('click', () => engage());
    $('#cancel').addEventListener('click', () => ws && ws.send(JSON.stringify({ action: 'cancel' })));
    ['dragover', 'drop'].forEach(ev => inp.addEventListener(ev, e => e.preventDefault()));
    inp.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) uploadImage(f); });
    $('#imgfile').addEventListener('change', e => { if (e.target.files[0]) uploadImage(e.target.files[0]); });
    $('#export-json').addEventListener('click', exportJSON);
    $('#export-csv').addEventListener('click', () => exportServer('csv', 'unisint-evidence.csv'));
    $('#export-html').addEventListener('click', () => exportServer('html', 'unisint-dossier.html'));
    $('#refresh-arsenal').addEventListener('click', () => loadArsenal(true));
    $('#save-keys').addEventListener('click', saveKeys);
    $('#fx-toggle').addEventListener('change', e => window.UNISINT_FX.set(e.target.checked));
    $('#report-gap').addEventListener('click', openGap);
    $('#gap-cancel').addEventListener('click', () => $('#gap-modal').classList.add('hidden'));
    $('#gap-save').addEventListener('click', saveGap);
    $('#preset').addEventListener('change', previewPlan);
    $('#plan-hide').addEventListener('click', () => $('#plan-panel').classList.add('hidden'));
    loadArsenal(false); loadConfig();
  }
  function setMode(mode) {
    MODE = mode;
    previewPlan();
    document.querySelectorAll('.mode').forEach(x => x.classList.toggle('active', x.dataset.mode === mode));
    $('#target').placeholder = MODE === 'recon'
      ? 'domain or IP you own / are authorized to test'
      : 'your username, email, phone, domain, IP — or drop an image';
  }

  async function openGap() {
    $('#gap-modal').classList.remove('hidden');
    try {
      const d = await (await fetch('/api/gaps')).json();
      $('#gap-count').textContent = d.count ? `${d.count} gap(s) logged so far → ${d.path}` : '';
    } catch { }
  }
  async function saveGap() {
    const body = { what: $('#gap-what').value, missing: $('#gap-missing').value, severity: $('#gap-sev').value };
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
    if (!v) { $('#type-tag').textContent = '?'; $('#plan-panel').classList.add('hidden'); return; }
    try {
      const r = await fetch('/api/detect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value: v }) });
      $('#type-tag').textContent = (await r.json()).type.toUpperCase();
    } catch { }
    previewPlan();
  }

  /* ---------- PLAN PREVIEW ---------- */
  const PLAN_STATUS = {
    will_run: ['WILL RUN', 'v-ok'], needs_credentials: ['NEEDS KEY', 'v-unk'],
    needs_authorization: ['NEEDS AUTH', 'v-unk'], unavailable: ['UNAVAILABLE', 'off'],
    skipped_preset: ['SKIPPED (preset)', 'dimmed'],
  };
  const previewPlan = debounce(async () => {
    const v = $('#target').value.trim();
    const targets = (UPLOAD && $('#type-tag').textContent === 'IMAGE')
      ? [{ type: 'image', value: UPLOAD.name, path: UPLOAD.path }] : (v ? [v] : []);
    if (!targets.length) { $('#plan-panel').classList.add('hidden'); return; }
    let p;
    try {
      p = await (await fetch('/api/plan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ targets, mode: MODE, preset: $('#preset').value }) })).json();
    } catch { return; }
    renderPlan(p);
  }, 300);
  function renderPlan(p) {
    const body = $('#plan-body'); body.replaceChildren();
    const c = p.counts || {};
    $('#plan-sub').textContent = `${MODE.toUpperCase()} · ${c.will_run || 0} will run · `
      + `${c.needs_credentials || 0} need keys · ${c.unavailable || 0} unavailable`
      + (c.needs_authorization ? ` · ${c.needs_authorization} need authorization` : '');
    (p.targets || []).forEach(tp => {
      const grp = el('div', 'plan-target');
      grp.appendChild(el('div', 'plan-ttype', `${tp.type}: ${tp.value}`));
      tp.modules.forEach(m => {
        const [lab, cls] = PLAN_STATUS[m.status] || [m.status, ''];
        const row = el('div', 'plan-row');
        row.appendChild(badge(lab, cls));
        row.appendChild(el('span', 'plan-mod', m.label + (m.active ? ' ⚡' : '')));
        row.appendChild(el('span', 'note', m.detail));
        grp.appendChild(row);
      });
      body.appendChild(grp);
    });
    $('#plan-panel').classList.remove('hidden');
  }
  async function uploadImage(file) {
    log('uploading ' + file.name + ' ...', 'run');
    const fd = new FormData(); fd.append('file', file);
    UPLOAD = await (await fetch('/api/upload', { method: 'POST', body: fd })).json();
    $('#target').value = UPLOAD.name; $('#type-tag').textContent = 'IMAGE';
    log('image staged: ' + UPLOAD.name, 'ok');
  }

  /* ---------- SCAN ---------- */
  function engage(seedValue) {
    const v = (seedValue || $('#target').value).trim();
    if (!v && !UPLOAD) return;
    if (seedValue) $('#target').value = seedValue;
    $('#plan-panel').classList.add('hidden');
    GRAPH.clear(); $('#dossier').replaceChildren(); $('#terminal').replaceChildren();
    SNAP = { entities: [], links: [], pivots: [] }; DOSSIER = null; FINAL = false;
    setStatus('run');
    $('#engage').classList.add('hidden'); $('#cancel').classList.remove('hidden');
    const targets = (UPLOAD && $('#type-tag').textContent === 'IMAGE')
      ? [{ type: 'image', value: UPLOAD.name, path: UPLOAD.path }] : [v];
    TARGETS = targets;   // remembered so a single source can be re-run
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => ws.send(JSON.stringify({
      mode: MODE, preset: $('#preset').value, authorized: true, targets,
      validate_links: $('#validate-links').checked,
    }));
    ws.onmessage = ev => handle(JSON.parse(ev.data));
    ws.onclose = () => { setStatus('idle'); $('#engage').classList.remove('hidden'); $('#cancel').classList.add('hidden'); UPLOAD = null; };
    ws.onerror = () => log('socket error', 'err');
  }

  let notExpandedLogged = 0;
  function handle(m) {
    if (m.type === 'log') log(m.msg, m.level);
    else if (m.type === 'entity') { GRAPH.addNode(m.entity); upsert(SNAP.entities, m.entity); livePreview(); }
    else if (m.type === 'link') { GRAPH.addLink(m.link); SNAP.links.push(m.link); }
    else if (m.type === 'pivot') { SNAP.pivots.push(m.pivot); }
    else if (m.type === 'done') log(`done — ${m.entities} entities, ${m.links} links`, 'ok');
    else if (m.type === 'dossier') { DOSSIER = m.dossier; FINAL = true; renderDossier(); }
  }
  function upsert(arr, e) { const i = arr.findIndex(x => x.id === e.id); if (i >= 0) arr[i] = e; else arr.push(e); }

  // Live preview: the SERVER builds the dossier (single builder for UI + exports).
  const livePreview = debounce(async () => {
    if (FINAL) return;
    try {
      const r = await fetch('/api/dossier', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: MODE, entities: SNAP.entities, pivots: SNAP.pivots })
      });
      if (!FINAL) { DOSSIER = await r.json(); renderDossier(); }
    } catch { }
  }, 800);

  /* ---------- TERMINAL ---------- */
  function log(msg, level = 'info') {
    const t = $('#terminal');
    const line = el('div', 'line l-' + level);
    line.appendChild(el('span', 'ts', new Date().toLocaleTimeString('en-GB') + ' '));
    line.appendChild(document.createTextNode(String(msg)));
    t.appendChild(line); t.scrollTop = t.scrollHeight;
    while (t.children.length > 800) t.removeChild(t.firstChild);
  }
  function setStatus(s) { const n = $('#status'); n.textContent = s.toUpperCase(); n.classList.toggle('run', s === 'run'); }

  /* ---------- EVIDENCE RENDERING ---------- */
  const VSTATE_CLASS = { reachable: 'v-ok', not_found: 'v-bad', soft_404: 'v-bad', unsafe: 'v-bad', invalid: 'v-bad' };
  function vBadge(v) {
    if (!v) return badge('unchecked', 'v-unk', 'link not validated (enable VERIFY LINKS)');
    return badge(v.state, VSTATE_CLASS[v.state] || 'v-unk', (v.detail || '') + (v.final_url ? ' → ' + v.final_url : ''));
  }
  const LABEL_CLASS = { seeded: 'l-strong', linked_proof: 'l-strong', linked_profile: 'l-strong',
    corroborated_handle: 'l-mid', handle_match: 'l-weak', weak: 'l-weak', candidate: 'l-cand' };
  function whyBox(it) {
    const a = it.assessment || {}, p = it.provenance || {};
    const d = el('details', 'why');
    d.appendChild(el('summary', null, 'why?'));
    const ul = el('ul');
    (a.supports || []).forEach(s => ul.appendChild(el('li', 'sup', '+ ' + s)));
    (a.conflicts || []).forEach(s => ul.appendChild(el('li', 'con', '− ' + s)));
    (a.unknown || []).forEach(s => ul.appendChild(el('li', 'unk', '? ' + s)));
    const prov = el('li', 'prov', `sources: ${(p.sources || []).join(', ')} · via ${p.via || '-'} of ${p.parent || '-'}`);
    ul.appendChild(prov);
    if (p.source_url) { const li = el('li', 'prov', 'source URL: '); li.appendChild(safeLink(p.source_url)); ul.appendChild(li); }
    d.appendChild(ul);
    return d;
  }
  function itemRow(it, opts = {}) {
    const row = el('div', 'ev-row');
    tagFilter(row, it);
    const head = el('div', 'ev-head');
    if (it.site) head.appendChild(el('span', 'acc-site', it.site));
    if (it.url) head.appendChild(safeLink(it.url, opts.text || it.url,
      (it.validation && ['not_found', 'soft_404'].includes(it.validation.state)) ? 'broken' : null));
    else head.appendChild(el('span', 'ev-val', it.value));
    if (it.type === 'account' || it.type === 'url') head.appendChild(vBadge(it.validation));
    const a = it.assessment || {};
    if (a.title) head.appendChild(badge(a.title, LABEL_CLASS[a.label] || ''));
    if (a.conflicting) head.appendChild(badge('conflicting evidence', 'l-con'));
    row.appendChild(head);
    if (opts.snippet) row.appendChild(el('div', 'snippet', opts.snippet));
    row.appendChild(whyBox(it));
    return row;
  }
  function group(root, title, nodes, note) {
    if (!nodes || !nodes.length) return;
    const g = el('div', 'dgroup');
    g.appendChild(el('h4', null, `${title} (${nodes.length})`));
    if (note) g.appendChild(el('div', 'note', note));
    nodes.forEach(n => g.appendChild(n));
    root.appendChild(g);
  }
  function chips(root, title, arr, note) {
    if (!arr || !arr.length) return;
    group(root, title, arr.map(v => el('span', 'chip', v)), note);
  }

  /* ---------- VIEW FILTER (dossier rows + graph nodes) ---------- */
  const BASIS_LABEL = { seed: 'seeded', observed: 'observed', derived: 'derived', candidate: 'candidate' };
  // Pull the filterable facets off an entity dict OR a built dossier item.
  function fsources(e) {
    if (e.meta && Array.isArray(e.meta.sources)) return e.meta.sources;
    if (e.provenance && Array.isArray(e.provenance.sources)) return e.provenance.sources; // dossier item
    if (Array.isArray(e.provenance)) return e.provenance.map(p => p.source).filter(Boolean); // raw entity
    return e.source ? [e.source] : [];
  }
  function facets(e) {
    return {
      type: e.type,
      basis: e.basis || 'observed',
      vstate: (e.validation && e.validation.state) || 'unchecked',
      sources: fsources(e),
    };
  }
  function matchFilter(e) {
    const f = facets(e);
    if (FILTER.type && !FILTER.type.has(f.type)) return false;
    if (FILTER.basis && !FILTER.basis.has(f.basis)) return false;
    if (FILTER.vstate && !FILTER.vstate.has(f.vstate)) return false;
    if (FILTER.source && !f.sources.some(s => FILTER.source.has(s))) return false;
    return true;
  }
  function tagFilter(row, it) {
    const f = facets(it);
    row.dataset.f = '1';
    row.dataset.ftype = f.type;
    row.dataset.fbasis = f.basis;
    row.dataset.fvstate = f.vstate;
    row.dataset.fsrc = f.sources.join(',');
  }
  function rowMatches(row) {
    if (FILTER.type && !FILTER.type.has(row.dataset.ftype)) return false;
    if (FILTER.basis && !FILTER.basis.has(row.dataset.fbasis)) return false;
    if (FILTER.vstate && !FILTER.vstate.has(row.dataset.fvstate)) return false;
    if (FILTER.source) {
      const srcs = (row.dataset.fsrc || '').split(',').filter(Boolean);
      if (!srcs.some(s => FILTER.source.has(s))) return false;
    }
    return true;
  }
  const FILTER_DIMS = [
    ['type', 'TYPE', e => [e.type]],
    ['source', 'SOURCE', e => fsources(e)],
    ['vstate', 'VALIDATION', e => [(e.validation && e.validation.state) || 'unchecked']],
    ['basis', 'EVIDENCE', e => [e.basis || 'observed'], v => BASIS_LABEL[v] || v],
  ];
  function buildFilterBar() {
    const bar = $('#dossier-filter'); if (!bar) return;
    bar.replaceChildren();
    const ents = SNAP.entities || [];
    if (!ents.length) { bar.classList.add('hidden'); return; }
    let any = false;
    FILTER_DIMS.forEach(([key, title, get, lbl]) => {
      const present = new Set();
      ents.forEach(e => get(e).forEach(v => { if (v) present.add(v); }));
      if (present.size < 2) return;              // nothing to choose between
      any = true;
      const grp = el('div', 'dfilter-grp');
      grp.appendChild(el('span', 'dfilter-lbl', title));
      [...present].sort().forEach(v => {
        const on = FILTER[key] && FILTER[key].has(v);
        const chip = el('span', 'fchip' + (on ? ' on' : ''), (lbl ? lbl(v) : v));
        chip.onclick = () => {
          FILTER[key] = FILTER[key] || new Set();
          if (FILTER[key].has(v)) FILTER[key].delete(v); else FILTER[key].add(v);
          if (!FILTER[key].size) FILTER[key] = null;
          buildFilterBar(); applyFilter();
        };
        grp.appendChild(chip);
      });
      bar.appendChild(grp);
    });
    if (FILTER.type || FILTER.source || FILTER.vstate || FILTER.basis) {
      const clr = el('span', 'fchip clear', '✕ CLEAR');
      clr.onclick = () => { FILTER.type = FILTER.source = FILTER.vstate = FILTER.basis = null; buildFilterBar(); applyFilter(); };
      bar.appendChild(clr);
    }
    bar.classList.toggle('hidden', !any);
  }
  // Hide dossier rows that don't match; recount group headers; sync the graph.
  function applyFilter() {
    const active = !!(FILTER.type || FILTER.source || FILTER.vstate || FILTER.basis);
    $('#dossier').querySelectorAll('.dgroup').forEach(g => {
      const rows = [...g.querySelectorAll('.ev-row[data-f]')];
      if (!rows.length) return;                  // summary group (chips/findings): leave as is
      let shown = 0;
      rows.forEach(r => { const ok = rowMatches(r); r.classList.toggle('fhide', !ok); if (ok) shown++; });
      const h4 = g.querySelector('h4');
      if (h4 && !h4.dataset.base) h4.dataset.base = h4.textContent;
      if (h4) h4.textContent = active ? `${h4.dataset.base} · ${shown} shown` : h4.dataset.base;
      g.classList.toggle('fhide', active && shown === 0);
    });
    if (GRAPH) GRAPH.setFilter(active ? matchFilter : null);
  }
  function renderLegend() {
    const box = $('#graph-legend'); if (!box || box.childElementCount) return;
    const add = (swatch, text) => { const r = el('div', 'leg-row'); r.appendChild(swatch); r.appendChild(el('span', null, text)); box.appendChild(r); };
    const dot = (cls) => el('span', 'leg-dot ' + cls);
    add(dot('solid'), 'observed / seeded (solid)');
    add(dot('hollow'), 'candidate / derived — unconfirmed (hollow)');
    add(dot('broken'), 'broken / unsafe link (red ring)');
    box.appendChild(el('div', 'leg-sep'));
    box.appendChild(el('div', 'note', 'dashed edge = unconfirmed link'));
  }

  // Source-run status → badge style, and which states are worth re-running.
  const SRC_CLASS = {
    ok: 'v-ok', empty: 'dimmed', skipped: 'dimmed',
    not_configured: 'dimmed', unavailable: 'dimmed',
    partial: 'v-unk', rate_limited: 'v-unk', timeout: 'v-unk',
    error: 'v-bad', blocked: 'v-bad', auth_error: 'v-bad',
  };
  const RETRYABLE = new Set(['error', 'partial', 'rate_limited', 'timeout',
    'blocked', 'auth_error']);
  function sourceRow(name, v) {
    const r = el('div', 'ev-row');
    const head = el('div', 'ev-head');
    head.appendChild(el('span', 'acc-site', (v.label || name) + (v.active ? ' ⚡' : '')));
    head.appendChild(badge(v.state || '?', SRC_CLASS[v.state] || 'v-unk', v.last_error || ''));
    // Honest run facts: only shown when the source actually reached out.
    const facts = [];
    if (v.contacted) facts.push(v.live === false ? 'fixture-backed' : 'contacted');
    if (v.findings) facts.push(`${v.findings} finding${v.findings === 1 ? '' : 's'}`);
    if (v.results_retrieved) facts.push(`${v.results_retrieved} retrieved`);
    if (v.truncated) facts.push('truncated');
    if (facts.length) head.appendChild(el('span', 'srcfacts', facts.join(' · ')));
    if (TARGETS.length && (RETRYABLE.has(v.state) || v.contacted === false && v.state === 'empty')) {
      const b = el('button', 'retry', 'RETRY');
      b.title = 'Re-run just this source against the original target(s)';
      b.onclick = () => rerunSource(name, b);
      head.appendChild(b);
    }
    r.appendChild(head);
    if (v.last_error) r.appendChild(el('div', 'note', v.last_error));
    return r;
  }
  async function rerunSource(name, btn) {
    if (!TARGETS.length) return;
    if (btn) { btn.disabled = true; btn.textContent = 'RUNNING…'; }
    log(`re-running source: ${name}`, 'run');
    let res;
    try {
      res = await (await fetch('/api/rerun-source', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ module: name, mode: MODE, targets: TARGETS })
      })).json();
    } catch { log(`retry failed: ${name}`, 'err'); if (btn) { btn.disabled = false; btn.textContent = 'RETRY'; } return; }
    if (res.error) { log(`retry: ${res.error}`, 'err'); if (btn) { btn.disabled = false; btn.textContent = 'RETRY'; } return; }
    // Replace this source's status and fold its fresh entities into the snapshot.
    DOSSIER = DOSSIER || {}; DOSSIER.module_status = DOSSIER.module_status || {};
    DOSSIER.module_status[name] = res.status;
    (res.entities || []).forEach(e => { GRAPH.addNode(e); mergeEntity(e); });
    const st = res.status.state;
    log(`${name}: ${st} — ${res.entities.length} entities`, st === 'ok' ? 'ok' : 'warn');
    await rebuildDossier();
  }
  // Merge by identity (type + normalised value), replacing any stale copy so a
  // re-run never duplicates rows.
  function mergeEntity(e) {
    const k = e.type + ':' + String(e.value).trim().toLowerCase();
    const i = SNAP.entities.findIndex(x => x.type + ':' + String(x.value).trim().toLowerCase() === k);
    if (i >= 0) SNAP.entities[i] = e; else SNAP.entities.push(e);
  }
  // Rebuild the dossier server-side, preserving the current per-source statuses
  // (the dossier builder keeps whatever module_status we pass it).
  async function rebuildDossier() {
    try {
      const r = await fetch('/api/dossier', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: MODE, entities: SNAP.entities, pivots: SNAP.pivots,
          scope: (DOSSIER && DOSSIER.scope) || undefined,
          module_status: (DOSSIER && DOSSIER.module_status) || {} })
      });
      DOSSIER = await r.json(); renderDossier();
    } catch { }
  }

  function renderDossier() {
    const d = DOSSIER; if (!d) return;
    const c = d.counts || {};
    $('#exposure').textContent = c.accounts || 0;
    $('#exposure-lbl').textContent = `ACCOUNTS · ${c.accounts_strong || 0} LINKED`;
    const risk = $('#risk'); risk.replaceChildren();
    (d.risk_flags || []).forEach(r => risk.appendChild(el('div', null, '⚠ ' + r)));
    if (!FINAL) risk.appendChild(el('div', 'note', 'live preview — final dossier when scan completes'));
    const root = $('#dossier'); root.replaceChildren();

    chips(root, 'SEEDS', (d.seeds || []).map(s => `${s.type}: ${s.value}`));
    Object.entries(d.account_groups || {}).forEach(([label, items]) =>
      group(root, 'ACCOUNTS — ' + (items[0].assessment.title || label).toUpperCase(), items.map(i => itemRow(i)),
        label === 'handle_match' ? 'Same handle on another site. That alone is not proof it is the same person.' : null));
    group(root, 'LINKS LISTED ON PROFILES', (d.linked_urls || []).map(i => itemRow(i)));
    group(root, 'REGISTRATIONS', (d.registrations || []).map(reg => {
      const r = el('div', 'ev-row', `${reg.value}  [${(reg.provenance.sources || []).join(', ')}]`);
      tagFilter(r, reg); return r;
    }), 'The tool reports the email/phone is registered on this site. No profile URL is known, so none is shown.');
    Object.entries(d.identifiers || {}).forEach(([t, items]) =>
      group(root, t.toUpperCase() + 'S FOUND', items.map(i => itemRow(i))));
    group(root, 'NAMES SHOWN ON PROFILES', (d.names_on_profiles || []).map(n => el('div', 'ev-row', `${n.name} — on ${n.on}`)),
      'Display names observed on profiles. Names are common and are not evidence of identity.');
    const inf = d.infrastructure || {};
    chips(root, 'IN-SCOPE HOSTS', inf.in_scope_hosts);
    chips(root, 'IPS', inf.ips);
    chips(root, 'OUT-OF-SCOPE HOSTS (recorded only, never probed)', inf.out_of_scope_hosts);
    chips(root, 'CANDIDATE HOSTS (from search results, unverified)', inf.candidate_hosts);
    renderScope(root, d.scope_report);
    group(root, 'SEARCH RESULTS — CANDIDATES', (d.search_results || []).map(i =>
      itemRow(i, { text: (i.meta && i.meta.title) || i.url, snippet: `${(i.meta && i.meta.snippet) || ''}  [${((i.meta && i.meta.providers) || []).join(', ')}]` })),
      'Retrieved via search APIs. A result mentions the query; it is not verified evidence.');
    group(root, 'FINDINGS', (d.findings || []).map(f => {
      const r = el('div', 'ev-row', `[${(f.provenance.sources || ['?'])[0]}] ${f.value}`);
      tagFilter(r, f); return r;
    }));
    group(root, 'SEARCH PROVIDER STATUS', (d.provider_status || []).map(f => el('div', 'ev-row l-warn', `${f.value} — ${(f.meta && f.meta.detail) || ''}`)));
    group(root, 'MODULE STATUS', Object.entries(d.module_status || {}).sort()
      .map(([k, v]) => sourceRow(k, v)));
    const ps = d.pivot_summary || {};
    if (ps.expanded != null) group(root, 'PIVOTS', [
      el('div', 'ev-row', `expanded ${ps.expanded} · not expanded ${ps.not_expanded}`),
      ...(ps.skip_reasons || []).map(([r, n]) => el('div', 'ev-row note', `${r}  ×${n}`))]);
    group(root, 'MANUAL SEARCH LINKS (not executed)', (d.manual_links || []).flatMap(f =>
      ((f.meta && f.meta.links) || []).map(l => { const r = el('div', 'ev-row'); r.appendChild(safeLink(l.url, l.name)); return r; })));
    renderRemediation(root, d.remediation || []);
    if (!root.childElementCount) emptyState(root, d);
    renderLegend();
    buildFilterBar();
    applyFilter();
  }
  // Explain an empty dossier in terms of what the sources actually did.
  function emptyState(root, d) {
    const ms = Object.values(d.module_status || {});
    const failed = ms.filter(v => ['error', 'blocked', 'rate_limited', 'auth_error', 'timeout', 'partial'].includes(v.state)).length;
    const needKeys = ms.filter(v => v.state === 'not_configured').length;
    const g = el('div', 'dgroup empty-state');
    g.appendChild(el('h4', null, FINAL ? 'NO RESULTS' : 'NO RESULTS YET'));
    let msg = FINAL ? 'Nothing was recorded for this target.' : 'Scanning…';
    const bits = [];
    if (failed) bits.push(`${failed} source${failed === 1 ? '' : 's'} failed`);
    if (needKeys) bits.push(`${needKeys} need credentials`);
    if (bits.length) msg += ' ' + bits.join(', ') + ' — see the PLAN panel and MODULE STATUS.';
    g.appendChild(el('div', 'note', msg));
    root.appendChild(g);
  }

  function renderScope(root, sr) {
    if (!sr || (!sr.authorized_domains.length && !sr.authorized_ips.length && !sr.blocked_count)) return;
    const nodes = [];
    const auth = [...(sr.authorized_domains || []), ...(sr.authorized_ips || [])];
    nodes.push(el('div', 'ev-row', 'Authorized for active probing: ' + (auth.join(', ') || '(none)')));
    (sr.active_blocked || []).forEach(a => {
      const r = el('div', 'ev-row');
      r.appendChild(el('span', 'acc-site', a.target || '?'));
      r.appendChild(badge('blocked: ' + a.class, 'v-bad'));
      r.appendChild(el('span', 'note', ' ' + a.reason));
      nodes.push(r);
    });
    group(root, 'ACTIVE-PROBE SCOPE' + (sr.blocked_count ? ` — ${sr.blocked_count} blocked` : ''),
      nodes, 'Active probes (HTTP fingerprint, link checks) only run on authorized assets; '
      + 'everything else is recorded, not touched.');
  }

  function renderRemediation(root, steps) {
    if (!steps.length) return;
    const g = el('div', 'dgroup remediation');
    g.appendChild(el('h4', null, 'REMEDIATION // FIX THIS'));
    steps.forEach(r => {
      const card = el('div', 'rem-card sev-' + (r.severity || 'medium'));
      const head = el('div', 'rem-head');
      head.appendChild(el('span', 'rem-sev', (r.severity || 'medium').toUpperCase()));
      head.appendChild(el('span', 'rem-title', r.title));
      card.appendChild(head);
      card.appendChild(el('div', 'rem-action', r.action));
      if (r.url) card.appendChild(safeLink(r.url, r.url, 'rem-link'));
      if (r.links) { const w = el('div', 'rem-links'); r.links.forEach(l => w.appendChild(safeLink(l.url, l.name))); card.appendChild(w); }
      g.appendChild(card);
    });
    root.appendChild(g);
  }

  /* ---------- NODE INFO ---------- */
  function findItem(id) {
    const d = DOSSIER || {};
    const pools = [d.seeds, d.accounts, d.linked_urls, d.search_results, d.findings,
      ...Object.values(d.identifiers || {})];
    for (const p of pools) for (const it of (p || [])) if (it.id === id) return it;
    return null;
  }
  function showNode(e) {
    const box = $('#nodeinfo');
    if (!e) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden'); box.replaceChildren();
    box.appendChild(el('b', null, e.type.toUpperCase() + ' · ' + (e.basis || '')));
    box.appendChild(el('div', 'ev-val', e.value));
    const it = findItem(e.id);
    if (it) {
      const h = el('div'); if (it.assessment) h.appendChild(badge(it.assessment.title, LABEL_CLASS[it.assessment.label] || ''));
      if (e.type === 'account' || e.type === 'url') h.appendChild(vBadge(e.validation));
      box.appendChild(h); box.appendChild(whyBox(it));
    } else {
      box.appendChild(el('small', null, 'sources: ' + ((e.meta && e.meta.sources) || [e.source]).join(', ')));
    }
    const url = (e.meta && e.meta.url) || (['account', 'url'].includes(e.type) ? e.value : null);
    if (url) { const d = el('div'); d.appendChild(safeLink(url, 'open ↗')); box.appendChild(d); }
    if (['username', 'email', 'domain', 'phone'].includes(e.type) && e.basis !== 'seed') {
      const b = el('button', 'btn sm', 'SCAN AS SEED');
      b.title = MODE === 'recon' ? 'Only if this asset is in your authorised scope'
        : 'Only if this identifier is yours — it will be scanned as a seed';
      b.onclick = () => { if (confirm(b.title + '\n\nStart a new scan of: ' + e.value + '?')) engage(e.value); };
      box.appendChild(b);
    }
  }

  /* ---------- MAP ---------- */
  let MAP = null, leafletTried = false;
  function coords() {
    const out = [];
    SNAP.entities.forEach(e => {
      const m = e.meta || {};
      if (typeof m.lat === 'number' && typeof m.lon === 'number') out.push({ lat: m.lat, lon: m.lon, label: e.value + (m.note ? ' (' + m.note + ')' : '') });
    });
    return out;
  }
  function renderMap() {
    const pts = coords(), host = $('#map');
    if (!pts.length) { host.replaceChildren(el('div', 'note pad', 'no coordinates found')); return; }
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
    $('#map').replaceChildren();
    if (MAP) { MAP.remove(); MAP = null; }
    MAP = L.map('map').setView([pts[0].lat, pts[0].lon], 5);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(MAP);
    pts.forEach(p => { const m = L.marker([p.lat, p.lon]).addTo(MAP); m.bindPopup(el('span', null, p.label)); });
  }
  function fallbackMap(pts) {
    const w = el('div', 'pad');
    pts.forEach(p => { const r = el('div'); r.appendChild(safeLink(`https://www.openstreetmap.org/?mlat=${p.lat}&mlon=${p.lon}`, p.label)); w.appendChild(r); });
    $('#map').replaceChildren(w);
  }

  /* ---------- ARSENAL ---------- */
  const STATE_CLS = { operational: 'on', runnable: 'on', installed: 'dimmed', misconfigured: 'failing', failing: 'failing', unavailable: 'off' };
  async function loadArsenal(force) {
    if (force) await fetch('/api/health', { method: 'POST' });
    const d = await (await fetch('/api/arsenal')).json();
    const root = $('#arsenal'); root.replaceChildren();
    d.tools.forEach(t => {
      const c = el('div', 'tool');
      c.appendChild(el('div', 'tn', t.label));
      c.appendChild(el('div', 'tp', t.purpose));
      c.appendChild(el('div', 'st ' + (STATE_CLS[t.state] || 'off'), '● ' + t.state.toUpperCase()));
      if (t.detail) c.appendChild(el('div', 'tp', t.detail));
      if (t.state === 'unavailable' || t.state === 'misconfigured') {
        const b = el('button', 'btn sm', t.state === 'unavailable' ? 'INSTALL' : 'REINSTALL'); b.style.marginTop = '8px';
        b.onclick = async () => {
          b.textContent = 'INSTALLING…'; b.disabled = true;
          const res = await (await fetch('/api/install/' + encodeURIComponent(t.name), { method: 'POST' })).json();
          b.textContent = res.ok ? 'DONE' : 'FAILED';
          log('install ' + t.name + ': ' + (res.ok ? 'ok' : '') + ' ' + (res.msg || ''), res.ok ? 'ok' : 'err');
          loadArsenal(false);
        };
        c.appendChild(b);
      }
      root.appendChild(c);
    });
  }

  /* ---------- SETTINGS ---------- */
  const KEY_NAMES = [['brave', 'Brave Search API key'], ['google_cse_key', 'Google Programmable Search key'], ['google_cse_cx', 'Google search engine ID (cx)']];
  async function loadConfig() {
    const d = await (await fetch('/api/config')).json();
    const src = d.key_sources || {};
    const root = $('#keys'); root.replaceChildren();
    KEY_NAMES.forEach(([k, label]) => {
      const lab = el('label'); lab.appendChild(el('span', null, label));
      const inp = el('input'); inp.type = 'password'; inp.dataset.key = k; inp.autocomplete = 'off';
      if (src[k] === 'env') { inp.disabled = true; inp.placeholder = 'set via environment variable'; }
      else inp.placeholder = d.api_keys_set[k] ? '•••• saved in config.json' : 'not set';
      lab.appendChild(inp);
      if (src[k] === 'file') {
        const x = el('button', 'btn sm', 'CLEAR'); x.type = 'button';
        x.onclick = async () => {
          await fetch('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ clear_keys: [k] }) });
          log(label + ' cleared', 'ok'); loadConfig(); loadArsenal(false);
        };
        lab.appendChild(x);
      }
      root.appendChild(lab);
    });
    $('#searxng-url').value = d.searxng_url || '';
    $('#searxng-url').disabled = d.searxng_source === 'env';
    $('#trust-proxy').checked = !!d.trust_proxy_resolution;
    $('#fx-toggle').checked = d.effects !== false;
    const cases = $('#cases'); cases.replaceChildren();
    (d.cases || []).forEach(c => cases.appendChild(el('div', 'case-row', `${c.when || ''} · ${c.mode || ''} · ${JSON.stringify(c.target)}`)));
  }
  async function saveKeys() {
    const keys = {};
    document.querySelectorAll('#keys input').forEach(i => { if (i.value && !i.disabled) keys[i.dataset.key] = i.value; });
    const body = { api_keys: keys, effects: $('#fx-toggle').checked, trust_proxy_resolution: $('#trust-proxy').checked };
    if (!$('#searxng-url').disabled) body.searxng_url = $('#searxng-url').value;
    const r = await fetch('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    document.querySelectorAll('#keys input').forEach(i => { i.value = ''; });   // never keep secrets in the DOM
    log(r.ok ? 'settings saved' : 'settings NOT saved', r.ok ? 'ok' : 'err'); loadConfig(); loadArsenal(false);
  }

  /* ---------- EXPORT (server-rendered from the same dossier) ---------- */
  function download(name, blob) {
    const u = URL.createObjectURL(blob); const a = el('a'); a.href = u; a.download = name; a.click(); URL.revokeObjectURL(u);
  }
  function exportJSON() {
    download('unisint-case.json', new Blob([JSON.stringify({ dossier: DOSSIER, snapshot: SNAP }, null, 2)], { type: 'application/json' }));
  }
  async function exportServer(fmt, name) {
    if (!DOSSIER) { log('nothing to export yet', 'warn'); return; }
    const r = await fetch('/api/export/' + fmt, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ dossier: DOSSIER }) });
    download(name, await r.blob());
  }

  boot();
})();
