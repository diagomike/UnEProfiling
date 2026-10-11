async function api(path, body) {
  // Snapshot build: answers come from the data embedded in this page (see build_demo.py).
  const u = new URL(path, 'http://x'), p = u.pathname, q = Object.fromEntries(u.searchParams), D = DEMO, M = DEMO.mem;
  const key = q.key === '1', now = () => new Date().toISOString().slice(0, 19).replace('T', ' ');
  const stamp = o => {                       // names this session has revealed, decisions it has taken, and the answer key
    if (Array.isArray(o)) return o.map(stamp);
    if (!o || typeof o !== 'object') return o;
    const r = {};
    for (const k in o) { if (!key && (k === 'known' || k === 'missed')) continue; r[k] = stamp(o[k]); }
    if (r.code && M.shown[r.code] && D.names[r.code]) Object.assign(r, D.names[r.code], {named: true});
    if (r.code && r.day && 'state' in r) { r.state = (M.last[r.code + '|' + r.day] || {}).state || 'new'; const c = M.open[r.code]; if (c) r.case = c.state; }
    return r;
  };
  const log = (action, more) => M.audit.unshift({at: now(), analyst: S.me, action, ...more});
  const missing = what => { toast(what + ' is not carried in this snapshot'); throw new Error('not in snapshot'); };
  if (p === '/api/state') return {...D.state, expected: M.expected};
  if (p === '/api/queue') return stamp(D.queue[q.day] || {day: q.day, rows: [], active: 0});
  if (p === '/api/alert') {
    const a = D.alert[q.code + '|' + q.day]; if (!a) missing('This day');
    log('open', {code: q.code, day: q.day});
    const r = stamp(a); if (!key) r.spark = r.spark.map(s => s.slice(0, 2));
    r.history = M.decisions.filter(x => x.code === q.code); return r;
  }
  if (p === '/api/people') {
    let rows = D.people.rows; const ql = (q.q || '').toLowerCase();
    if (q.role) rows = rows.filter(r => r.role === q.role);
    if (ql) rows = rows.filter(r => r.code.toLowerCase().includes(ql) || (M.shown[r.code] && D.names[r.code] && D.names[r.code].name.toLowerCase().includes(ql)));
    return stamp({rows: rows.map(r => ({...r, case: (M.open[r.code] || {}).state})), window: D.people.window});
  }
  if (p === '/api/person') {
    const x = D.person[q.code]; if (!x) missing('This profile');
    log('profile', {code: q.code});
    const r = stamp(x); r.history = M.decisions.filter(d => d.code === q.code); r.case = M.open[q.code] || null;
    r.alerts = r.alerts.map(a => ({...a, state: (M.last[q.code + '|' + a.day] || {}).state || 'new'})); return r;
  }
  if (p === '/api/machines') return stamp(D.machines[q.day] || {rows: [], day: q.day});
  if (p === '/api/machine') { const x = D.machine[q.host + '|' + q.day]; if (!x) missing('This machine'); return stamp(x); }
  if (p === '/api/cases') { const row = d => ({...d, person: stamp({code: d.code, role: d.role})}); return {rows: M.decisions.map(row), open: Object.values(M.open).map(row)}; }
  if (p === '/api/measured') return D.measured;
  if (p === '/api/setup') return {...D.setup, audit: M.audit, job: {running: false, log: [], error: null}};
  if (p === '/api/job') return {running: false, log: [], error: null};
  if (p === '/api/decide') {
    const role = ((D.alert[body.code + '|' + body.day] || {}).role) || '';
    const d = {at: now(), code: body.code, day: body.day, state: body.state, reason: body.reason, note: body.note, analyst: body.analyst, role};
    M.decisions.unshift(d); M.last[body.code + '|' + body.day] = d;
    if (['watching', 'escalated', 'confirmed'].includes(body.state)) M.open[body.code] = d; else if ((M.open[body.code] || {}).day === body.day) delete M.open[body.code];
    return {ok: true, state: body.state};
  }
  if (p === '/api/reveal') { M.shown[body.code] = true; log('reveal', {code: body.code, reason: body.reason}); return stamp({code: body.code}); }
  toast('This is a snapshot: re-scoring, settings and reading new logs run only in the installed tool'); throw new Error('snapshot');
}
