// Behaviour Watch console. One page; the server (server.py) does the reading and scoring.
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
// the browser's storage can be unavailable (private windows, embedded previews): the console must work without it
const store = {get: k => { try { return localStorage.getItem(k); } catch (e) { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) {} }};
const S = {st: null, me: store.get('bw_me') || '', key: false, day: null, tab: 'queue', rows: [], sel: -1, psel: null, msel: null};
const TABS = [['queue', 'Queue'], ['people', 'People'], ['machines', 'Machines'], ['cases', 'Cases'], ['measured', 'Measured'], ['setup', 'Setup']];
const STATE_LABEL = {new: 'New', watching: 'Watching', escalated: 'Escalated', confirmed: 'Confirmed', dismissed: 'Dismissed'};
const SCEN = {1: 'after-hours theft', 2: 'leaver taking data', 3: 'impersonation'};

async function api(path, body) {
  const r = await fetch(path, body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {});
  if (!r.ok) { let m = r.statusText; try { m = (await r.json()).detail || m; } catch (e) {} toast(m); throw new Error(m); }
  return r.json();
}
const qs = o => Object.entries(o).filter(([, v]) => v !== '' && v != null).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');
let toastT; function toast(m) { const t = $('toast'); t.textContent = m; t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => t.hidden = true, 3200); }
let debT; function debounce(f) { clearTimeout(debT); debT = setTimeout(f, 220); }
const fmtDay = d => new Date(d + 'T00:00').toLocaleDateString('en-GB', {weekday: 'short', day: 'numeric', month: 'short', year: 'numeric'});
const nines = r => Math.min(4, -Math.log10(Math.max(1e-4, 1 - r / 100)));        // 90 -> 1, 99 -> 2, 99.9 -> 3
const riskTxt = r => r >= 99.95 ? r.toFixed(2) : r.toFixed(1);

// ---------------------------------------------------------------- start
async function init() {
  S.st = await api('/api/state');
  const st = S.st;
  if (!st.open) { document.body.innerHTML = '<div class="empty">No watch is open. Start with: python -m watch serve &lt;folder&gt;</div>'; return; }
  $('wname').textContent = st.name;
  document.title = 'Behaviour Watch: ' + st.name;
  $('me').innerHTML = '<option value="">Who are you?</option>' + st.analysts.map(a => `<option ${a === S.me ? 'selected' : ''}>${esc(a)}</option>`).join('');
  if (!st.analysts.includes(S.me)) S.me = '';
  $('keybox').hidden = !st.has_labels;
  $('tabs').innerHTML = TABS.filter(t => t[0] !== 'measured' || st.has_labels).filter(t => t[0] !== 'machines' || st.has_hosts)
    .map((t, i) => `<a id="t-${t[0]}" onclick="go('${t[0]}')" title="${i + 1}">${t[1]}</a>`).join('');
  if (!st.scored) { go('setup'); return; }
  $('day').min = st.days[0]; $('day').max = st.days[st.days.length - 1];
  const saved = store.get('bw_day_' + st.name);
  S.day = st.days.includes(saved) ? saved : st.days[Math.max(0, st.alerts.findLastIndex(a => a > 0))] || st.days[st.days.length - 1];   // the latest day with something to review
  $('p-role').innerHTML = '<option value="">Every role</option>' + st.roles.map(r => `<option>${esc(r)}</option>`).join('');
  go(location.hash.slice(1) && TABS.some(t => t[0] === location.hash.slice(1)) ? location.hash.slice(1) : 'queue');
}

function go(tab) {
  if (!S.st.scored && tab !== 'setup') { toast('This watch has no scores yet. Use "Read new logs and re-score" first.'); tab = 'setup'; }
  S.tab = tab; location.hash = tab;
  for (const [t] of TABS) { const m = $('v-' + t); if (m) m.hidden = t !== tab; const a = $('t-' + t); if (a) a.classList.toggle('on', t === tab); }
  $('daybar').hidden = !S.st.scored || ['cases', 'measured', 'setup'].includes(tab);
  if (S.st.scored && !$('daybar').hidden) drawStrip();
  ({queue: loadQueue, people: loadPeople, machines: loadMachines, cases: loadCases, measured: loadMeasured, setup: loadSetup})[tab]();
}
function setMe(v) { S.me = v; store.set('bw_me', v); go(S.tab); }
function setKey(v) { S.key = v; drawStrip(); go(S.tab); }
function setDay(d) {
  const ds = S.st.days; if (!d) return;
  if (!ds.includes(d)) d = ds.reduce((a, b) => Math.abs(new Date(b) - new Date(d)) < Math.abs(new Date(a) - new Date(d)) ? b : a);   // nearest day with activity
  S.day = d; store.set('bw_day_' + S.st.name, d); S.sel = -1; drawStrip(); go(S.tab);
}
function stepDay(n) { const ds = S.st.days, i = ds.indexOf(S.day) + n; if (i >= 0 && i < ds.length) setDay(ds[i]); }

// ---------------------------------------------------------------- the strip: alerts per day around the day shown
function drawStrip() {
  const st = S.st, ds = st.days, i0 = ds.indexOf(S.day);
  $('day').value = S.day;
  const W = Math.max(200, $('strip').clientWidth), n = Math.min(ds.length, Math.floor(W / 7));
  let a = Math.max(0, Math.min(ds.length - n, i0 - Math.floor(n / 2)));
  const max = Math.max(4, ...st.alerts.slice(a, a + n)), bw = Math.min(W / n, 18), H = 40, base = 24;   // a short period does not stretch into slabs
  let g = '', lastM = '', lastX = -99;
  for (let k = 0; k < n; k++) {
    const i = a + k, v = st.alerts[i], h = v ? Math.max(2, v / max * (base - 3)) : 0, x = k * bw, on = i === i0;
    const m = ds[i].slice(0, 7);
    if (m !== lastM) { if (k) g += `<line x1="${x}" x2="${x}" y1="0" y2="${base}" stroke="var(--line)"/>`; if (x - lastX > 44 && W - x > 36) { lastX = x; g += `<text x="${x + 3}" y="${H - 1}" font-size="9.5" fill="var(--mute)">${new Date(ds[i] + 'T00:00').toLocaleDateString('en-GB', {month: 'short', year: '2-digit'})}</text>`; } lastM = m; }
    if (h) g += `<rect x="${x + 1}" y="${base - h}" width="${Math.max(1, bw - 2)}" height="${h}" rx="1.5" fill="${on ? 'var(--blue)' : 'var(--line2)'}"/>`;
    if (on) g += `<rect x="${x}" y="0" width="${bw}" height="${base + 1}" fill="var(--blue)" opacity=".12"/>`;
    if (S.key && st.known && st.known[i]) g += `<circle cx="${x + bw / 2}" cy="${base + 4}" r="1.8" fill="var(--red)"/>`;
    g += `<rect x="${x}" y="0" width="${bw}" height="${H}" fill="transparent" data-tip="${fmtDay(ds[i])}: ${v} alert${v === 1 ? '' : 's'}${S.key && st.known && st.known[i] ? ', ' + st.known[i] + ' known incident day' + (st.known[i] > 1 ? 's' : '') : ''}" onclick="setDay('${ds[i]}')"/>`;
  }
  $('strip').innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Alerts per day"><line x1="0" x2="${W}" y1="${base}" y2="${base}" stroke="var(--line2)"/>${g}</svg>`;
}
window.addEventListener('resize', () => { if (S.st && S.st.scored && !$('daybar').hidden) drawStrip(); });

// ---------------------------------------------------------------- queue
function who(p, big) {
  const c = `<span class="${big ? 'big' : 'code'}">${esc(p.code)}</span>`;
  return p.named && S.st.pseudonyms ? `${big ? `<span class="name">${esc(p.name)}</span>` : `<b>${esc(p.name)}</b>`} ${c}` : p.named ? `<b class="${big ? 'name' : ''}">${esc(p.name)}</b> <span class="mute mono">${esc(p.account)}</span>` : c;
}
function qrow(r, i, extra = '') {
  const thr = S.st.alert_percentile, fill = Math.max(4, Math.min(100, (nines(r.risk) - nines(thr)) / (4 - nines(thr)) * 100));
  return `<div class="q ${i === S.sel ? 'on' : ''} ${r.state === 'dismissed' ? 'done' : ''}" id="q${i}" onclick="pick(${i})">
    <div class="risk num" data-tip="Stranger than ${riskTxt(r.risk)}% of the days this watch learned from">${riskTxt(r.risk)}<i><b style="width:${r.risk > thr ? fill : 0}%"></b></i></div>
    <div class="who">${who(r)} <span class="mute">${esc(r.role)}${r.department ? ' · ' + esc(r.department) : ''}</span>${r.left ? `<span class="pill" data-tip="No longer in the directory after ${r.left}">left ${r.left}</span>` : ''}${r.known ? `<span class="known" data-tip="Answer key: ${SCEN[r.known] || 'known incident'}">KNOWN</span>` : ''}${r.case && r.case !== r.state ? `<span class="pill ${r.case}" data-tip="An open case on this person from another day">${STATE_LABEL[r.case]}</span>` : ''}</div>
    <div class="why">${esc(r.why.join('  ·  '))}</div>
    <div class="end">${extra}<span class="pill ${r.state}">${STATE_LABEL[r.state]}</span><span class="acts">
      <button class="ib ok" data-tip="Dismiss (d)" onclick="event.stopPropagation();pick(${i},1);dismissMenu(this)">✓</button>
      <button class="ib wa" data-tip="Watch (w)" onclick="event.stopPropagation();pick(${i},1);decide('watching')">◉</button>
      <button class="ib no" data-tip="Escalate (e)" onclick="event.stopPropagation();pick(${i},1);decide('escalated')">▲</button></span></div></div>`;
}
async function loadQueue() {
  const q = await api('/api/queue?' + qs({day: S.day, analyst: S.me, key: S.key ? 1 : 0}));
  S.rows = q.rows.concat(q.missed || []); S.nq = q.rows.length;
  const open = q.rows.filter(r => r.state === 'new').length;
  $('daystats').innerHTML = `<div><b>${q.active.toLocaleString()}</b><span>people active</span></div><div><b>${q.rows.length}</b><span>alerts</span></div><div><b>${open}</b><span>to review</span></div>`;
  let h = q.rows.map((r, i) => qrow(r, i)).join('') || `<div class="empty">No alerts on ${fmtDay(S.day)}.<br><span class="small">Nobody's day was stranger than ${S.st.alert_percentile}% of the days this watch learned from.</span></div>`;
  if (q.missed && q.missed.length) h += `<div class="sect">Known incident days the queue did not raise (answer key)</div>` + q.missed.map((r, i) => qrow(r, q.rows.length + i)).join('');
  $('q-list').innerHTML = h;
  if (S.sel < 0 || S.sel >= S.rows.length) S.sel = S.rows.length ? 0 : -1;
  if (S.sel >= 0) pick(S.sel, 1); else $('q-detail').innerHTML = '<div class="empty">Pick a day with alerts on the strip above.</div>';
}
function pick(i, quiet) {
  document.querySelectorAll('#q-list .q.on').forEach(e => e.classList.remove('on'));
  S.sel = i; const el = $('q' + i); if (el) { el.classList.add('on'); el.scrollIntoView({block: 'nearest'}); }
  loadAlert(S.rows[i]);
}
function meter(v, max = 4) { return `<span class="meter" data-tip="How seldom this count deviates this much: about one day in ${Math.round(10 ** v).toLocaleString()}"><b style="width:${Math.min(100, v / max * 100)}%"></b></span>`; }

async function loadAlert(r) {
  const a = await api('/api/alert?' + qs({code: r.code, day: r.day, analyst: S.me, key: S.key ? 1 : 0}));
  S.cur = a;
  const hrs = S.st.hours, off = t => { const h = +t.slice(0, 2); return h < hrs.start || h >= hrs.end; };
  let h = `<div class="dhead">${who(a, 1)}<span class="mute">${esc(a.role)}${a.department ? ' · ' + esc(a.department) : ''}</span>
      ${a.left ? `<span class="pill">left the directory after ${a.left}</span>` : ''}${a.known ? `<span class="known">KNOWN: ${SCEN[a.known] || 'incident'}</span>` : ''}
      <span class="sp"></span><span class="pill ${a.state}">${STATE_LABEL[a.state]}</span></div>
    <div class="mute small">${fmtDay(a.day)} · active ${hm(a.first_hour)} to ${hm(a.last_hour)} · risk <b class="num" style="color:var(--ink)">${riskTxt(a.risk)}</b>
      ${a.seq ? `· sequence model <span class="num" data-tip="How unusual the order of the day's events is, as a percentile of learned days. A second opinion: it does not rank the queue.">${a.seq.toFixed(1)}</span>` : ''}${a.named && a.manager ? ' · manager ' + esc(a.manager) : ''}</div>
    <div class="acts2">
      <button class="btn" onclick="dismissMenu(this)">✓ Dismiss <kbd>d</kbd></button><button class="btn" onclick="decide('watching')">◉ Watch <kbd>w</kbd></button>
      <button class="btn" onclick="decide('escalated')">▲ Escalate <kbd>e</kbd></button><button class="btn" onclick="noteMenu(this)">Note <kbd>n</kbd></button>
      <span class="sp"></span>${a.named ? '' : `<button class="btn" onclick="revealMenu(this,'${a.code}')">Show name <kbd>r</kbd></button>`}
      <button class="btn" onclick="openPerson('${a.code}')">Profile <kbd>p</kbd></button></div>
    <h2>Why this day stands out</h2><ul class="why">${a.why.map(w => `<li>${esc(w)}</li>`).join('')}</ul>
    <div class="grid2"><div><h2>Counts against their own usual and their role</h2><table><tr><th>Count</th><th class="n">Today</th><th class="n">Their usual</th><th class="n">Role today</th><th>How rare</th><th></th></tr>
      ${a.counts.map(c => `<tr class="${c.rare >= 2 ? 'hot' : ''}"><td>${esc(c.label)}</td><td class="n">${c.today}</td><td class="n">${c.usual == null ? '<span class="mute">new</span>' : c.usual}</td><td class="n mute">${c.role}</td><td>${c.rare > 0 ? meter(c.rare) : ''}</td>
        <td>${c.rare >= 2 ? `<a class="small nowrap hov" onclick="expectedMenu(this,'${c.key}','${esc(c.label)}')" data-tip="Stop alerting on this for this person or their role">normal?</a>` : ''}</td></tr>`).join('')}</table></div>
    <div><h2>Risk, last 90 days</h2><div class="chart" id="spark"></div>
      <h2>Decisions on this person</h2><div class="hist">${a.history.map(x => `<div><span class="pill ${x.state}">${STATE_LABEL[x.state] || x.state}</span> <span class="mute small">${x.day} · ${esc(x.analyst)} · ${x.at}</span>${x.reason ? ' ' + esc(x.reason) : ''}${x.note ? `<div class="note">${esc(x.note)}</div>` : ''}</div>`).join('') || '<span class="mute">None yet.</span>'}</div></div></div>
    <h2>The day, event by event</h2><table class="tl"><tr><th>Time</th><th>Event</th><th>Detail</th><th>Machine</th><th data-tip="How unexpected this event was to the sequence model">Surprise</th></tr>
      ${a.timeline.map(e => `<tr class="${off(e.t) ? 'off' : ''} ${e.known ? 'kn' : ''}"><td class="t" ${off(e.t) ? 'data-tip="Outside working hours"' : ''}>${e.t}</td><td>${esc(e.a)}${e.known ? ' <span class="known">KNOWN</span>' : ''}</td><td class="mute">${esc(e.d)}</td>
        <td class="nowrap">${e.h ? `<span class="mono">${esc(e.h)}</span> <span class="tag ${e.w}">${e.w === 'own' ? 'their own' : e.w === 'other' ? "someone else's" : 'shared'}</span>` : ''}</td><td>${e.s > 0.05 ? meter(e.s / 2.3, 4) : ''}</td></tr>`).join('')}</table>
    ${a.plain_web ? `<div class="mute small" style="margin-top:4px">Plus ${a.plain_web} ordinary web visits to ${a.plain_sites} site${a.plain_sites === 1 ? '' : 's'} they use regularly.</div>` : ''}`;
  $('q-detail').innerHTML = h; $('q-detail').scrollTop = 0;
  riskChart($('spark'), a.spark, a.day, a.threshold);
}
const hm = x => String(Math.floor(x)).padStart(2, '0') + ':' + String(Math.round((x % 1) * 60)).padStart(2, '0');

// A risk line on a scale of "nines": 90, 99, 99.9 are evenly spaced, because the top is where it matters.
function riskChart(el, series, today, thr, H = 96) {
  if (!series.length) { el.innerHTML = '<span class="mute">No history.</span>'; return; }
  const W = Math.max(260, el.clientWidth), L = 30, R = 6, T = 6, B = 16, n = series.length;
  const t0 = +new Date(series[0][0]), t1 = Math.max(t0 + 864e5, +new Date(series[n - 1][0]));
  const X = d => L + (new Date(d) - t0) / (t1 - t0) * (W - L - R), Y = r => T + (1 - nines(r) / 4) * (H - T - B);
  let g = '';
  for (const [v, lab] of [[90, '90'], [99, '99'], [99.9, '99.9']]) g += `<line x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}" stroke="var(--line)"/><text x="${L - 4}" y="${Y(v) + 3}" text-anchor="end" font-size="9.5" fill="var(--mute)">${lab}</text>`;
  g += `<line x1="${L}" x2="${W - R}" y1="${Y(thr)}" y2="${Y(thr)}" stroke="var(--ink2)" stroke-dasharray="3 3"/><text x="${L + 3}" y="${T + 7}" font-size="9.5" fill="var(--ink2)">dashed: alert above ${thr}</text>`;
  g += `<text x="${L}" y="${H - 3}" font-size="9.5" fill="var(--mute)">${series[0][0]}</text><text x="${W - R}" y="${H - 3}" text-anchor="end" font-size="9.5" fill="var(--mute)">${series[n - 1][0]}</text>`;
  g += `<polyline fill="none" stroke="var(--blue)" stroke-width="1.5" stroke-linejoin="round" points="${series.map(s => X(s[0]).toFixed(1) + ',' + Y(s[1]).toFixed(1)).join(' ')}"/>`;
  for (const s of series) {
    if (s[2]) g += `<circle cx="${X(s[0])}" cy="${Y(s[1])}" r="3.5" fill="none" stroke="var(--red)" stroke-width="1.5"/>`;
    else if (s[1] > thr) g += `<circle cx="${X(s[0])}" cy="${Y(s[1])}" r="2.2" fill="var(--blue)"/>`;
    if (s[0] === today) g += `<circle cx="${X(s[0])}" cy="${Y(s[1])}" r="4.5" fill="var(--blue)" stroke="var(--panel)" stroke-width="2"/>`;
  }
  g += `<line id="xh" y1="${T}" y2="${H - B}" stroke="var(--ink2)" stroke-width="1" visibility="hidden"/>`;
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="Risk over time">${g}<rect x="${L}" y="0" width="${W - L - R}" height="${H}" fill="transparent" style="cursor:pointer"/></svg>`;
  const near = ev => { const b = el.getBoundingClientRect(), x = (ev.clientX - b.left) / b.width * W; let best = series[0]; for (const s of series) if (Math.abs(X(s[0]) - x) < Math.abs(X(best[0]) - x)) best = s; return best; };
  const svg = el.firstChild, xh = svg.querySelector('#xh');
  svg.onmousemove = ev => { const s = near(ev); xh.setAttribute('x1', X(s[0])); xh.setAttribute('x2', X(s[0])); xh.setAttribute('visibility', 'visible'); tip(ev, `${fmtDay(s[0])}: risk ${riskTxt(s[1])}${s[2] ? ' (known incident day)' : ''}`); };
  svg.onmouseleave = () => { xh.setAttribute('visibility', 'hidden'); $('tip').hidden = true; };
  svg.onclick = ev => { S.tab = 'queue'; setDay(near(ev)[0]); };
}

// ---------------------------------------------------------------- decisions
async function decide(state, reason, note) {
  const a = S.cur; if (!a) return;
  if (!S.me) { toast('Choose who you are (top right) first'); $('me').focus(); return; }
  await api('/api/decide', {code: a.code, day: a.day, state, reason: reason || '', note: note || '', analyst: S.me});
  closeMenu(); toast(`${a.code}: ${STATE_LABEL[state].toLowerCase()}`);
  if (S.tab !== 'queue') return go(S.tab);
  const i = S.sel; S.rows[i].state = state;
  const next = S.rows.findIndex((r, k) => k > i && r.state === 'new');
  S.sel = next >= 0 ? next : i; loadQueue();
}
function menu(anchor, html) {
  const m = $('menu'); m.innerHTML = html; m.hidden = false;
  const b = anchor.getBoundingClientRect(); m.style.left = Math.min(b.left, innerWidth - m.offsetWidth - 8) + 'px'; m.style.top = Math.min(b.bottom + 4, innerHeight - m.offsetHeight - 8) + 'px';
  const first = m.querySelector('a,textarea'); if (first) first.focus && first.focus();
}
function closeMenu() { $('menu').hidden = true; }
document.addEventListener('mousedown', e => { if (!$('menu').hidden && !$('menu').contains(e.target)) closeMenu(); });
function dismissMenu(el) { menu(el, '<div class="mt">Dismiss because</div>' + S.st.dismiss_reasons.map((r, i) => `<a href="#" onclick="decide('dismissed','${esc(r).replace(/'/g, "\\'")}');return false"><kbd>${i + 1}</kbd> ${esc(r)}</a>`).join('')); S.menuKeys = S.st.dismiss_reasons.map(r => () => decide('dismissed', r)); }
function noteMenu(el) { S.menuKeys = null; menu(el, `<div class="mt">Note on ${S.cur.code}, ${S.cur.day}</div><textarea id="notetx" placeholder="What you checked, who you asked"></textarea><div class="row"><button class="btn blue" onclick="decide(S.cur.state==='new'?'watching':S.cur.state,'',$('notetx').value)">Save</button><span class="mute small">A note on a new alert sets it to Watching.</span></div>`); }
function revealMenu(el, code) {
  if (!S.me) { toast('Choose who you are (top right) first'); return; }
  S.menuKeys = S.st.reveal_reasons.map(r => () => reveal(code, r));
  menu(el, '<div class="mt">Show the name because (this is recorded)</div>' + S.st.reveal_reasons.map((r, i) => `<a href="#" onclick="reveal('${code}','${esc(r).replace(/'/g, "\\'")}');return false"><kbd>${i + 1}</kbd> ${esc(r)}</a>`).join(''));
}
async function reveal(code, reason) { await api('/api/reveal', {code, reason, analyst: S.me}); closeMenu(); go(S.tab); }
function expectedMenu(el, key, label) {
  const a = S.cur; S.menuKeys = null;
  menu(el, `<div class="mt">"${label}" is normal for</div><a href="#" onclick="expected('code:${a.code}','${key}');return false">this person only</a>
    <a href="#" onclick="expected('role:${esc(a.role)}','${key}');return false">everyone in the role ${esc(a.role)}</a><div class="mt">It stops raising alerts for them. Undo it in Setup.</div>`);
}
async function expected(who, what) {
  if (!S.me) { toast('Choose who you are (top right) first'); return; }
  closeMenu(); toast('Re-scoring…');
  const r = await api('/api/expected', {who, what, analyst: S.me});
  S.st = await api('/api/state'); toast(`Alerts over the whole period: ${r.alerts_before.toLocaleString()} → ${r.alerts_after.toLocaleString()}`); drawStrip(); go(S.tab);
}

// ---------------------------------------------------------------- people
async function loadPeople() {
  const p = await api('/api/people?' + qs({day: S.day, window: $('p-win').value, q: $('p-q').value.trim(), role: $('p-role').value, analyst: S.me}));
  S.people = p.rows;
  $('daystats').innerHTML = `<div><b>${p.rows.filter(r => r.alerts).length}</b><span>people with alerts in ${p.window} days</span></div>`;
  $('p-list').innerHTML = `<table style="margin:0"><tr><th style="padding-left:10px">Person</th><th>Role</th><th class="n">Alerts</th><th class="n">Peak risk</th><th>Last alert</th><th></th></tr>` +
    p.rows.map(r => `<tr style="cursor:pointer" class="${r.code === S.psel ? 'hot' : ''}" onclick="openPerson('${r.code}')"><td style="padding-left:10px">${who(r)}</td><td class="mute">${esc(r.role)}</td><td class="n">${r.alerts || ''}</td><td class="n">${r.peak.toFixed(1)}</td><td class="mute nowrap">${r.last || ''}</td><td>${r.case ? `<span class="pill ${r.case}">${STATE_LABEL[r.case]}</span>` : ''}</td></tr>`).join('') + '</table>' +
    (p.rows.length ? '' : '<div class="empty">Nobody matches.</div>');
  if (S.psel) showPerson(S.psel); else $('p-detail').innerHTML = '<div class="empty">Pick a person to see what is normal for them.</div>';
}
function openPerson(code) { S.psel = code; if (S.tab !== 'people') go('people'); else loadPeople(); }
async function showPerson(code) {
  const p = await api('/api/person?' + qs({code, analyst: S.me}));
  const hrs = S.st.hours, mx = Math.max(1, ...p.hours), tot = p.hours.reduce((a, b) => a + b, 0) || 1;
  const W = 300, H = 70, bw = W / 24;
  let bars = `<rect x="${hrs.start * bw}" y="0" width="${(hrs.end - hrs.start) * bw}" height="${H - 14}" fill="var(--sunk)"/>`;
  p.hours.forEach((v, i) => { const h = v ? Math.max(1.5, v / mx * (H - 18)) : 0; bars += `<rect x="${i * bw + 1}" y="${H - 14 - h}" width="${bw - 2}" height="${h}" rx="1.5" fill="var(--blue)"/><rect x="${i * bw}" y="0" width="${bw}" height="${H}" fill="transparent" data-tip="${String(i).padStart(2, '0')}:00 to ${String(i + 1).padStart(2, '0')}:00: ${(v / tot * 100).toFixed(1)}% of their activity"/>`; if (i % 6 === 0) bars += `<text x="${i * bw + 1}" y="${H - 2}" font-size="9.5" fill="var(--mute)">${String(i).padStart(2, '0')}</text>`; });
  $('p-detail').innerHTML = `<div class="dhead">${who(p, 1)}<span class="mute">${esc(p.role)}${p.department ? ' · ' + esc(p.department) : ''}</span>${p.left ? `<span class="pill">left the directory after ${p.left}</span>` : ''}${p.case ? `<span class="pill ${p.case.state}">${STATE_LABEL[p.case.state]}</span>` : ''}
      <span class="sp"></span>${p.named ? '' : `<button class="btn" onclick="revealMenu(this,'${p.code}')">Show name</button>`}</div>
    <div class="mute small">Seen ${p.first} to ${p.last} · active on ${p.active_days} days${p.named && p.manager ? ' · manager ' + esc(p.manager) : ''}</div>
    <h2>Risk over the whole period</h2><div class="chart" id="pchart"></div>
    <div class="grid2"><div><h2>When they are active (shaded: working hours)</h2><div class="chart"><svg viewBox="0 0 ${W} ${H}" height="${H}" style="max-width:${W}px" role="img" aria-label="Activity by hour">${bars}</svg></div>
      <h2>Machines they log on to</h2>${p.machines.map(m => `<div><span class="mono">${esc(m[0])}</span> <span class="mute">${m[1].toLocaleString()} logons</span></div>`).join('') || '<span class="mute">No logons in the logs.</span>'}
      <h2>What they do</h2>${p.kinds.map(k => `<div>${esc(k[0])} <span class="mute num">${k[1].toLocaleString()}</span></div>`).join('')}</div>
    <div><h2>A typical day</h2><table><tr><th>Count</th><th class="n">Median</th><th class="n" data-tip="19 days in 20 are at or below this">High day</th><th class="n">Most</th><th class="n">Days seen</th></tr>
      ${p.typical.map(t => `<tr><td>${esc(t.label)}</td><td class="n">${t.median}</td><td class="n">${t.high}</td><td class="n">${t.max}</td><td class="n mute">${t.days}</td></tr>`).join('')}</table></div></div>
    <h2>Days that raised an alert</h2>${p.alerts.map(a => `<div class="q" style="grid-template-columns:86px minmax(0,1fr) auto" onclick="S.tab='queue';setDay('${a.day}')"><div class="mono">${a.day}</div><div class="why" style="grid-column:2">${esc(a.why.join('  ·  '))}</div><div class="end"><b class="num">${riskTxt(a.risk)}</b><span class="pill ${a.state}">${STATE_LABEL[a.state]}</span></div></div>`).join('') || '<span class="mute">None.</span>'}
    <h2>Decisions</h2><div class="hist">${p.history.map(x => `<div><span class="pill ${x.state}">${STATE_LABEL[x.state] || x.state}</span> <span class="mute small">${x.day} · ${esc(x.analyst)} · ${x.at}</span> ${esc(x.reason || '')}${x.note ? `<div class="note">${esc(x.note)}</div>` : ''}</div>`).join('') || '<span class="mute">None yet.</span>'}</div>`;
  riskChart($('pchart'), p.series, S.day, p.threshold, 110);
}

// ---------------------------------------------------------------- machines
async function loadMachines() {
  const m = await api('/api/machines?' + qs({day: S.day, analyst: S.me}));
  S.mrows = m.rows;
  $('daystats').innerHTML = `<div><b>${m.rows.length}</b><span>machines unlike themselves</span></div>`;
  $('m-list').innerHTML = m.rows.map((r, i) => `<div class="q ${r.host === S.msel ? 'on' : ''}" onclick="showMachine(${i})"><div class="risk num">${riskTxt(r.risk)}</div>
    <div class="who"><span class="code">${esc(r.host)}</span><span class="mute">${r.owner ? 'used mostly by ' + (r.owner.named ? esc(r.owner.name) : r.owner.code) + (r.owner.role ? ' · ' + esc(r.owner.role) : '') : 'shared machine'}</span></div><div class="why">${esc(r.why.join('  ·  '))}</div><div class="end"></div></div>`).join('')
    || `<div class="empty">No machine stood out on ${fmtDay(S.day)}.</div>`;
  $('m-detail').innerHTML = '<div class="empty">Pick a machine to see who used it that day.</div>';
}
async function showMachine(i) {
  const r = S.mrows[i]; S.msel = r.host;
  const m = await api('/api/machine?' + qs({host: r.host, day: S.day, analyst: S.me}));
  $('m-detail').innerHTML = `<div class="dhead"><span class="big">${esc(r.host)}</span><span class="mute">${r.owner ? 'used mostly by ' + r.owner.code + (r.owner.role ? ' · ' + esc(r.owner.role) : '') : 'shared machine'}</span></div>
    <h2>Why this machine stands out</h2><ul class="why">${r.why.map(w => `<li>${esc(w)}</li>`).join('')}</ul>
    <h2>Counts against its own usual</h2><table><tr><th>Count</th><th class="n">Today</th><th class="n">Its usual</th></tr>${r.counts.map(c => `<tr><td>${esc(c.label)}</td><td class="n">${c.today}</td><td class="n">${c.usual ?? ''}</td></tr>`).join('')}</table>
    <h2>The day on this machine</h2><table class="tl"><tr><th>Time</th><th>Who</th><th>Event</th><th>Detail</th></tr>
    ${m.events.map(e => `<tr><td class="t">${e.t}</td><td><a onclick="openPerson('${e.who.code}')">${e.who.named ? esc(e.who.name) : e.who.code}</a> <span class="mute">${esc(e.who.role)}</span></td><td>${esc(e.a)}</td><td class="mute">${esc(e.d)}</td></tr>`).join('')}</table>`;
  document.querySelectorAll('#m-list .q').forEach((e, k) => e.classList.toggle('on', k === i));
}

// ---------------------------------------------------------------- cases, measured, setup
async function loadCases() {
  const c = await api('/api/cases?' + qs({analyst: S.me}));
  const line = x => `<tr><td>${who(x.person)}</td><td class="mute">${esc(x.person.role)}</td><td><span class="pill ${x.state}">${STATE_LABEL[x.state] || x.state}</span></td><td class="nowrap"><a onclick="S.tab='queue';setDay('${x.day}')">${x.day}</a></td><td>${esc(x.reason || '')}${x.note ? `<div class="note">${esc(x.note)}</div>` : ''}</td><td class="mute nowrap">${esc(x.analyst)}</td><td class="mute nowrap">${x.at}</td></tr>`;
  const head = '<tr><th>Person</th><th>Role</th><th>State</th><th>Alert day</th><th>Reason and notes</th><th>By</th><th>When</th></tr>';
  $('c-body').innerHTML = `<div class="row"><h1>Cases</h1><span class="sp"></span><a class="btn" href="/api/export/decisions.csv">Download decisions (CSV)</a><a class="btn" href="/api/export/alerts.csv">Download all alerts (CSV)</a></div><h2>Open: watching, escalated or confirmed</h2>${c.open.length ? `<table>${head}${c.open.map(line).join('')}</table>` : '<div class="mute">Nothing is open.</div>'}
    <h2>Every decision, newest first</h2>${c.rows.length ? `<table>${head}${c.rows.map(line).join('')}</table>` : '<div class="mute">No decisions have been recorded in this watch.</div>'}`;
}
async function loadMeasured() {
  const m = await api('/api/measured');
  if (!m.detectors) { $('e-body').innerHTML = '<div class="empty">Nothing measured yet.</div>'; return; }
  const sc = Object.keys(m.detectors[0].all.by_scenario);
  const row = (d, k) => { const r = d[k]; return `<tr class="${d.queue ? 'hot' : ''}"><td>${esc(d.label)}${d.queue ? ' <span class="pill b">the queue</span>' : ''}</td><td class="n">${r.alerts_per_day}</td><td class="n"><b>${r.found}</b> of ${r.insiders}</td><td class="n">${r.found_first_week}</td><td class="n">${r.found_first_day}</td>${sc.map(s => `<td class="n">${r.by_scenario[s] ? r.by_scenario[s][0] + '/' + r.by_scenario[s][1] : ''}</td>`).join('')}<td class="n">${(r.precision * 100).toFixed(1)}%</td><td class="n">${r.roc_auc.toFixed(3)}</td></tr>`; };
  const head = `<tr><th>Detector</th><th class="n">Alerts a day</th><th class="n">Insiders found</th><th class="n" data-tip="Flagged within 7 days of their first scripted act">in their first week</th><th class="n">on their first day</th>${sc.map(s => `<th class="n" data-tip="${SCEN[s] || ''}">Scenario ${s}</th>`).join('')}<th class="n" data-tip="Share of alerts that fall on a known incident day">Alerts that are real</th><th class="n">ROC-AUC</th></tr>`;
  const best = m.detectors.find(d => d.queue) || m.detectors[m.detectors.length - 1];
  $('e-body').innerHTML = `<h1>Measured against the answer key</h1>
    <div class="mute" style="margin:4px 0 10px">This watch has ${m.incidents} known insider incidents. Thresholds and the sequence model learned only from days before ${m.learn_until}; the ${m.test_days} days after are the test. An alert is any person-day above the ${m.alert_percentile}th percentile of the learned days.</div>
    <div class="cols3"><div class="tile"><b>${best.all.found} of ${best.all.insiders}</b><span>insiders raised at least one alert</span></div><div class="tile"><b>${best.all.found_first_week}</b><span>were raised in their first week</span></div>
      <div class="tile"><b>${best.all.alerts_per_day}</b><span>alerts a day to review, for ${S.st.meta.people.toLocaleString()} people</span></div><div class="tile"><b>${(best.all.precision * 100).toFixed(1)}%</b><span>of alerts fall on a known incident day</span></div></div>
    <h2>All ${m.incidents} incidents</h2><table>${head}${m.detectors.map(d => row(d, 'all')).join('')}</table>
    <h2>The ${m.held_out} incidents held out while the scoring was designed</h2><table>${head}${m.detectors.map(d => row(d, 'held_out')).join('')}</table>
    <div class="mute small" style="margin-top:10px;max-width:820px">Scenario 1: logs on after hours, uses a USB drive, uploads to a leak site, leaves. Scenario 2: browses job sites, contacts a competitor, copies data to USB over about two months. Scenario 3: an administrator plants a keylogger and logs on as their supervisor.
      "Found" for a long incident is easy to reach by luck, which is why the random row and the first-week column are there. The data is simulated: this shows the method works, not how it will score on real logs.</div>`;
}
let jobT;
async function loadSetup() {
  const s = await api('/api/setup'), st = S.st, m = s.meta || {};
  $('s-body').innerHTML = `<h1>${esc(st.name)}</h1><div class="mute mono">${esc(s.folder)}</div>
    <div class="cols3"><div class="tile"><b>${(m.people || 0).toLocaleString()}</b><span>people</span></div><div class="tile"><b>${(m.events || 0).toLocaleString()}</b><span>events${m.first_day ? `, ${m.first_day} to ${m.last_day}` : ''}</span></div>
      <div class="tile"><b>${(m.sources || []).join(', ') || 'none'}</b><span>kinds of log in use</span></div><div class="tile"><b>${m.scored || 'never'}</b><span>last scored${m.sequence ? ', with the sequence model' : ''}</span></div></div>
    <h2>Log sources</h2><table><tr><th>Name</th><th>Kind</th><th>Where</th><th class="n">Files read</th><th></th></tr>${s.sources.map(x => `<tr><td>${esc(x.name)}</td><td>${esc(x.adapter)}</td><td class="mono">${esc(x.path)}</td><td class="n">${x.files}</td><td>${x.found ? '' : '<span class="pill r">not found</span>'}</td></tr>`).join('')}</table>
    <div class="row" style="margin-top:8px"><button class="btn blue" id="upd" onclick="runUpdate()">Read new logs and re-score</button><label class="check small"><input type="checkbox" id="retrain">retrain the sequence model (after adding a kind of log)</label></div>
    <pre class="log" id="joblog" hidden></pre>
    <h2>Behaviour marked as expected</h2>${st.expected && st.expected.length ? `<table><tr><th>Who</th><th>What</th><th>By</th><th>When</th><th></th></tr>${st.expected.map((r, i) => `<tr><td>${esc(r.who.startsWith('actor:') ? 'one person' : r.who.replace('role:', 'Role: '))}</td><td>${esc((st.counts.find(c => c.key === r.what) || {label: r.what}).label)}</td><td class="mute">${esc(r.by || '')}</td><td class="mute">${r.at || ''}</td><td><a onclick="removeRule(${i})">remove</a></td></tr>`).join('')}</table>` : '<div class="mute">Nothing yet. In an alert, use "normal?" beside a count, or add a rule here.</div>'}
    ${st.scored ? `<div class="row" style="margin-top:6px;max-width:720px"><select id="r-who">${st.roles.map(r => `<option value="role:${esc(r)}">Role: ${esc(r)}</option>`).join('')}</select><select id="r-what">${st.counts.map(c => `<option value="${c.key}">${esc(c.label)}</option>`).join('')}</select><button class="btn" onclick="expected($('r-who').value,$('r-what').value)">Add</button></div>` : ''}
    <h2>Settings</h2><div class="row wrap"><span>Alert when a day is stranger than</span><input type="number" id="s-pct" value="${st.alert_percentile}" min="90" max="99.99" step="0.1" style="width:80px"><span>% of learned days</span>
      <span style="margin-left:14px">Working hours</span><input type="number" id="s-h0" value="${st.hours ? st.hours.start : 7}" min="0" max="23" style="width:58px"><span>to</span><input type="number" id="s-h1" value="${st.hours ? st.hours.end : 19}" min="1" max="24" style="width:58px">
      <label class="check" style="margin-left:14px"><input type="checkbox" id="s-ps" ${st.pseudonyms ? 'checked' : ''}>Hide names until an analyst gives a reason</label><button class="btn" onclick="saveSettings()">Save</button></div>
    <div class="mute small" style="margin-top:3px">Working hours take effect at the next re-score. Analysts, site categories and dismissal reasons are lists in watch.json.</div>
    <h2>Access log: who opened whose record</h2><table><tr><th>When</th><th>Analyst</th><th>Did</th><th>Person</th><th>Detail</th></tr>${s.audit.slice(0, 80).map(a => `<tr><td class="mute nowrap">${a.at}</td><td>${esc(a.analyst || '(not chosen)')}</td><td>${{open: 'opened an alert', profile: 'opened a profile', reveal: 'revealed a name', rule: 'changed a rule', settings: 'changed settings'}[a.action] || a.action}</td><td class="mono">${esc(a.code || '')}</td><td class="mute">${esc(a.reason || a.day || '')}</td></tr>`).join('')}</table>`;
  if (s.job.running || s.job.log.length) pollJob();
}
async function runUpdate() { await api('/api/update', {retrain: $('retrain').checked, force: $('retrain').checked}); pollJob(); }
async function pollJob() {
  clearTimeout(jobT); const j = await api('/api/job'), el = $('joblog'); if (!el) return;
  el.hidden = false; el.textContent = j.log.join('\n') + (j.error ? '\n' + j.error : ''); el.scrollTop = el.scrollHeight; $('upd').disabled = j.running;
  if (j.running) jobT = setTimeout(pollJob, 1500); else if (j.log[j.log.length - 1] === 'done' && !S.st.scored) init();
}
async function removeRule(i) { toast('Re-scoring…'); await api('/api/expected', {remove: i, analyst: S.me}); S.st = await api('/api/state'); go('setup'); }
async function saveSettings() {
  await api('/api/settings', {alert_percentile: +$('s-pct').value, pseudonyms: $('s-ps').checked, hours: {...S.st.hours, start: +$('s-h0').value, end: +$('s-h1').value}, analyst: S.me});
  S.st = await api('/api/state'); toast('Saved'); go('setup');
}

// ---------------------------------------------------------------- tooltip, keys, help
function tip(ev, text) { const t = $('tip'); t.textContent = text; t.hidden = false; t.style.left = Math.min(ev.clientX + 12, innerWidth - t.offsetWidth - 6) + 'px'; t.style.top = (ev.clientY > innerHeight - 50 ? ev.clientY - 28 : ev.clientY + 16) + 'px'; }
document.addEventListener('mousemove', e => { const el = e.target.closest && e.target.closest('[data-tip]'); if (el) tip(e, el.dataset.tip); else if (!e.target.closest || !e.target.closest('.chart svg')) $('tip').hidden = true; });
function help() {
  menu($('me'), `<div class="mt">Keyboard</div>${[['j / k  or  ↓ / ↑', 'next / previous alert'], ['← / →', 'previous / next day'], ['d', 'dismiss (then 1 to 6 for the reason)'], ['w', 'watch'], ['e', 'escalate'], ['n', 'note'], ['r', 'show the name (a reason is recorded)'], ['p', 'open the profile'], ['1 … 6', 'switch tab'], ['/', 'find a person'], ['Esc', 'close a menu']].map(k => `<div style="padding:2px 8px"><kbd>${k[0]}</kbd> <span class="mute">${k[1]}</span></div>`).join('')}`); S.menuKeys = null;
}
document.addEventListener('keydown', e => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(e.target.tagName);
  if (e.key === 'Escape') { closeMenu(); if (typing) e.target.blur(); return; }
  if (typing || e.ctrlKey || e.metaKey || e.altKey || !S.st || !S.st.scored) return;
  if (!$('menu').hidden) { const f = S.menuKeys && S.menuKeys[+e.key - 1]; if (f) { e.preventDefault(); f(); } return; }
  const k = e.key;
  if (/^[1-6]$/.test(k)) { const a = $('tabs').children[+k - 1]; if (a) a.click(); return; }
  if (k === '?') return help();
  if (k === '/') { e.preventDefault(); if (S.tab !== 'people') go('people'); $('p-q').focus(); return; }
  if (!$('daybar').hidden && k === 'ArrowLeft') return stepDay(-1);
  if (!$('daybar').hidden && k === 'ArrowRight') return stepDay(1);
  if (S.tab !== 'queue') return;
  if ((k === 'j' || k === 'ArrowDown') && S.sel < S.rows.length - 1) { e.preventDefault(); pick(S.sel + 1); }
  else if ((k === 'k' || k === 'ArrowUp') && S.sel > 0) { e.preventDefault(); pick(S.sel - 1); }
  else if (S.cur && k === 'd') dismissMenu($('q' + S.sel) || $('me'));
  else if (S.cur && k === 'w') decide('watching');
  else if (S.cur && k === 'e') decide('escalated');
  else if (S.cur && k === 'n') { e.preventDefault(); noteMenu($('q' + S.sel) || $('me')); }
  else if (S.cur && k === 'r' && !S.cur.named) revealMenu($('q' + S.sel) || $('me'), S.cur.code);
  else if (S.cur && k === 'p') openPerson(S.cur.code);
});
init();
