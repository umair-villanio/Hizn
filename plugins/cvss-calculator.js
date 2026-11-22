// @name        CVSS 3.1 Calculator
// @description Interactive CVSS v3.1 calculator — Base, Temporal and Environmental scores, severity rating and vector string, with a vector parser. Sample extension plugin.
// @version     1.0.0
// @author      hizn
// @kind        extension

// A self-contained CVSS v3.1 calculator (no network, no deps). Implements the
// official FIRST.org v3.1 specification, including the exact integer "roundup".

// ---- metric coefficients (FIRST.org CVSS v3.1) -------------------------------
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const AC = { L: 0.77, H: 0.44 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { H: 0.56, L: 0.22, N: 0.00 };          // C / I / A impact
const Ev = { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1.00 };
const RLv = { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1.00 };
const RCv = { X: 1, U: 0.92, R: 0.96, C: 1.00 };
const REQ = { X: 1, L: 0.5, M: 1.0, H: 1.5 };       // CR / IR / AR

// Privileges Required is Scope-dependent.
function prVal(pr, scope) {
  if (pr === 'N') return 0.85;
  if (pr === 'L') return scope === 'C' ? 0.68 : 0.62;
  return scope === 'C' ? 0.50 : 0.27; // H
}

// Official v3.1 roundup: smallest 1-dp number >= input, via integer math.
function roundup(input) {
  const i = Math.round(input * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

function severity(score) {
  if (score <= 0) return ['None', '#8a8f98'];
  if (score < 4.0) return ['Low', '#3fb37f'];
  if (score < 7.0) return ['Medium', '#e0a100'];
  if (score < 9.0) return ['High', '#fd7e14'];
  return ['Critical', '#e5484d'];
}

// ---- metric definitions (id, label, [value, label]...) -----------------------
const BASE = [
  ['AV', 'Attack Vector', [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']]],
  ['AC', 'Attack Complexity', [['L', 'Low'], ['H', 'High']]],
  ['PR', 'Privileges Required', [['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  ['UI', 'User Interaction', [['N', 'None'], ['R', 'Required']]],
  ['S', 'Scope', [['U', 'Unchanged'], ['C', 'Changed']]],
  ['C', 'Confidentiality', [['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  ['I', 'Integrity', [['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  ['A', 'Availability', [['N', 'None'], ['L', 'Low'], ['H', 'High']]],
];
const TEMPORAL = [
  ['E', 'Exploit Code Maturity', [['X', 'Not Defined'], ['U', 'Unproven'], ['P', 'PoC'], ['F', 'Functional'], ['H', 'High']]],
  ['RL', 'Remediation Level', [['X', 'Not Defined'], ['O', 'Official Fix'], ['T', 'Temporary Fix'], ['W', 'Workaround'], ['U', 'Unavailable']]],
  ['RC', 'Report Confidence', [['X', 'Not Defined'], ['U', 'Unknown'], ['R', 'Reasonable'], ['C', 'Confirmed']]],
];
const ENV_REQ = [
  ['CR', 'Confidentiality Req.', [['X', 'Not Defined'], ['L', 'Low'], ['M', 'Medium'], ['H', 'High']]],
  ['IR', 'Integrity Req.', [['X', 'Not Defined'], ['L', 'Low'], ['M', 'Medium'], ['H', 'High']]],
  ['AR', 'Availability Req.', [['X', 'Not Defined'], ['L', 'Low'], ['M', 'Medium'], ['H', 'High']]],
];
const ENV_MOD = [
  ['MAV', 'Mod. Attack Vector', [['X', 'Not Defined'], ['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']]],
  ['MAC', 'Mod. Attack Complexity', [['X', 'Not Defined'], ['L', 'Low'], ['H', 'High']]],
  ['MPR', 'Mod. Privileges Required', [['X', 'Not Defined'], ['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  ['MUI', 'Mod. User Interaction', [['X', 'Not Defined'], ['N', 'None'], ['R', 'Required']]],
  ['MS', 'Mod. Scope', [['X', 'Not Defined'], ['U', 'Unchanged'], ['C', 'Changed']]],
  ['MC', 'Mod. Confidentiality', [['X', 'Not Defined'], ['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  ['MI', 'Mod. Integrity', [['X', 'Not Defined'], ['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  ['MA', 'Mod. Availability', [['X', 'Not Defined'], ['N', 'None'], ['L', 'Low'], ['H', 'High']]],
];
const ALL = [...BASE, ...TEMPORAL, ...ENV_REQ, ...ENV_MOD];
const ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'];
const OPTIONAL = new Set(['E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA']);

// ---- state -------------------------------------------------------------------
const S = {
  AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N',
  E: 'X', RL: 'X', RC: 'X', CR: 'X', IR: 'X', AR: 'X',
  MAV: 'X', MAC: 'X', MPR: 'X', MUI: 'X', MS: 'X', MC: 'X', MI: 'X', MA: 'X',
};
let scoreEl = null, vecEl = null, vecInput = null;

function resetState() {
  for (const d of BASE) S[d[0]] = d[2][0][0]; // each base metric → its first option
  for (const id of OPTIONAL) S[id] = 'X';
}

// ---- scoring -----------------------------------------------------------------
function baseScore() {
  const iss = 1 - (1 - CIA[S.C]) * (1 - CIA[S.I]) * (1 - CIA[S.A]);
  const impact = S.S === 'U'
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const expl = 8.22 * AV[S.AV] * AC[S.AC] * prVal(S.PR, S.S) * UI[S.UI];
  if (impact <= 0) return 0;
  const raw = S.S === 'U' ? impact + expl : 1.08 * (impact + expl);
  return roundup(Math.min(raw, 10));
}

function temporalScore(base) {
  return roundup(base * Ev[S.E] * RLv[S.RL] * RCv[S.RC]);
}

function environmentalScore() {
  const r = (m, base) => (S[m] === 'X' ? S[base] : S[m]); // resolve modified → base
  const ms = r('MS', 'S');
  const mc = CIA[r('MC', 'C')], mi = CIA[r('MI', 'I')], ma = CIA[r('MA', 'A')];
  const cr = REQ[S.CR], ir = REQ[S.IR], ar = REQ[S.AR];
  const miss = Math.min(1 - (1 - cr * mc) * (1 - ir * mi) * (1 - ar * ma), 0.915);
  const modImpact = ms === 'U'
    ? 6.42 * miss
    : 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);
  const modExpl = 8.22 * AV[r('MAV', 'AV')] * AC[r('MAC', 'AC')]
    * prVal(r('MPR', 'PR'), ms) * UI[r('MUI', 'UI')];
  if (modImpact <= 0) return 0;
  const raw = ms === 'U' ? modImpact + modExpl : 1.08 * (modImpact + modExpl);
  const inner = roundup(Math.min(raw, 10));
  return roundup(inner * Ev[S.E] * RLv[S.RL] * RCv[S.RC]);
}

function vector() {
  let v = 'CVSS:3.1';
  for (const id of ORDER) {
    if (OPTIONAL.has(id) && S[id] === 'X') continue;
    v += '/' + id + ':' + S[id];
  }
  return v;
}

// ---- rendering ---------------------------------------------------------------
function chip(label, val, color, note) {
  return '<div style="flex:1;min-width:120px;background:var(--panel,rgba(127,127,127,.08));border:1px solid var(--border,rgba(127,127,127,.25));border-radius:8px;padding:10px 12px">' +
    '<div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--faint)">' + label + '</div>' +
    '<div style="font-size:24px;font-weight:700;line-height:1.1;margin-top:2px">' + val +
    ' <span style="font-size:12px;font-weight:600;color:' + color + '">' + note + '</span></div></div>';
}

function refresh() {
  const base = baseScore();
  const temp = temporalScore(base);
  const env = environmentalScore();
  const anyT = ['E', 'RL', 'RC'].some(k => S[k] !== 'X');
  const anyE = anyT || ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'].some(k => S[k] !== 'X');
  const overall = anyE ? env : (anyT ? temp : base);
  const [sevName, sevColor] = severity(overall);

  if (scoreEl) {
    const b = severity(base), t = severity(temp), e = severity(env);
    scoreEl.innerHTML =
      '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">' +
        chip('Base', base.toFixed(1), b[1], b[0]) +
        chip('Temporal', temp.toFixed(1), t[1], t[0]) +
        chip('Environmental', env.toFixed(1), e[1], e[0]) +
      '</div>' +
      '<div style="display:flex;align-items:center;gap:10px;font-size:13px">' +
        '<span style="color:var(--faint)">Overall</span>' +
        '<span style="font-weight:700;font-size:16px">' + overall.toFixed(1) + '</span>' +
        '<span style="background:' + sevColor + ';color:#fff;font-weight:700;font-size:11px;padding:2px 9px;border-radius:999px;text-transform:uppercase;letter-spacing:.4px">' + sevName + '</span>' +
      '</div>';
  }
  if (vecEl) vecEl.textContent = vector();
  if (vecInput && document.activeElement !== vecInput) vecInput.value = vector();
}

function reflectButtons(root) {
  root.querySelectorAll('[data-m]').forEach(btn => {
    const on = S[btn.getAttribute('data-m')] === btn.getAttribute('data-v');
    btn.classList.toggle('cvss-sel', on);
  });
}

function group(id, label, opts) {
  let b = '<div style="margin-bottom:11px"><div style="font-size:11px;color:var(--faint);margin-bottom:4px">' +
    hizn.esc(label) + ' <span style="opacity:.6">(' + id + ')</span></div><div class="cvss-row">';
  for (const [val, name] of opts) {
    const sel = S[id] === val ? ' cvss-sel' : '';
    b += '<button class="cvss-opt' + sel + '" data-m="' + id + '" data-v="' + val + '">' + hizn.esc(name) + '</button>';
  }
  return b + '</div></div>';
}

function section(title, defs) {
  return '<div style="margin:16px 0 4px;font-size:12px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.5px">' +
    title + '</div>' + defs.map(d => group(d[0], d[1], d[2])).join('');
}

hizn.registerTab({
  id: 'cvss',
  title: 'CVSS 3.1',
  icon: '⚖',
  render(container) {
    container.style.padding = '16px 18px';
    container.style.overflow = 'auto';
    container.innerHTML =
      '<style>' +
      '.cvss-row{display:flex;flex-wrap:wrap;gap:6px}' +
      '.cvss-opt{font-size:11px;padding:4px 10px;border-radius:6px;cursor:pointer;' +
        'background:var(--panel,rgba(127,127,127,.1));color:var(--muted,inherit);' +
        'border:1px solid var(--border,rgba(127,127,127,.3))}' +
      '.cvss-opt:hover{border-color:var(--accent)}' +
      '.cvss-sel{background:var(--accent);color:#fff;border-color:var(--accent);font-weight:600}' +
      '</style>' +
      '<h3 style="margin:0 0 4px;font-size:13px;color:var(--faint);text-transform:uppercase;letter-spacing:.5px">CVSS v3.1 Calculator</h3>' +
      '<div style="color:var(--faint);font-size:12px;margin-bottom:12px">Base, Temporal and Environmental scores per the FIRST.org v3.1 spec. Added by the <b>CVSS 3.1 Calculator</b> plugin.</div>' +
      '<div style="display:flex;gap:6px;margin-bottom:12px">' +
        '<input id="cvssVecIn" placeholder="Paste a CVSS:3.1 vector…" ' +
          'style="flex:1;font-family:var(--mono);font-size:12px;padding:6px 9px;border-radius:6px;' +
          'background:var(--panel,rgba(127,127,127,.08));color:inherit;border:1px solid var(--border,rgba(127,127,127,.3))">' +
        '<button id="cvssApply" class="btn" style="font-size:11px;padding:4px 11px">Apply</button>' +
        '<button id="cvssReset" class="btn" style="font-size:11px;padding:4px 11px">Reset</button>' +
      '</div>' +
      '<div id="cvssScore"></div>' +
      '<div style="margin:12px 0 4px;font-size:11px;color:var(--faint)">Vector string <button id="cvssCopy" class="btn" style="font-size:10px;padding:1px 8px;margin-left:6px">⎘ Copy</button></div>' +
      '<code id="cvssVec" style="display:block;font-family:var(--mono);font-size:12px;word-break:break-all;background:var(--panel,rgba(127,127,127,.08));border:1px solid var(--border,rgba(127,127,127,.25));border-radius:6px;padding:8px 10px"></code>' +
      '<div id="cvssMetrics">' +
        section('Base Score', BASE) +
        section('Temporal Score', TEMPORAL) +
        section('Environmental — Security Requirements', ENV_REQ) +
        section('Environmental — Modified Base', ENV_MOD) +
      '</div>';

    scoreEl = container.querySelector('#cvssScore');
    vecEl = container.querySelector('#cvssVec');
    vecInput = container.querySelector('#cvssVecIn');
    const metrics = container.querySelector('#cvssMetrics');

    // Pick a metric value (event delegation).
    metrics.addEventListener('click', e => {
      const btn = e.target.closest('[data-m]');
      if (!btn) return;
      S[btn.getAttribute('data-m')] = btn.getAttribute('data-v');
      reflectButtons(metrics);
      refresh();
    });

    container.querySelector('#cvssApply').addEventListener('click', () => {
      applyVector(vecInput.value, metrics);
    });
    vecInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') applyVector(vecInput.value, metrics);
    });
    container.querySelector('#cvssReset').addEventListener('click', () => {
      resetState();
      reflectButtons(metrics);
      refresh();
    });
    container.querySelector('#cvssCopy').addEventListener('click', () => {
      navigator.clipboard.writeText(vector()).then(
        () => hizn.banner('CVSS vector copied.'),
        () => hizn.banner('Copy failed.'),
      );
    });

    refresh();
  },
});

function applyVector(str, root) {
  if (!str || !/CVSS:3\.1/i.test(str)) { hizn.banner('Not a CVSS:3.1 vector string.'); return; }
  const valid = {};
  for (const [id, , opts] of ALL) valid[id] = new Set(opts.map(o => o[0]));
  resetState(); // a pasted vector replaces the state; unspecified metrics → defaults
  let n = 0;
  for (const part of str.trim().split('/')) {
    const [k, v] = part.split(':');
    if (k === 'CVSS') continue;
    if (valid[k] && valid[k].has(v)) { S[k] = v; n++; }
  }
  if (!n) { hizn.banner('No recognised metrics in that vector.'); return; }
  reflectButtons(root);
  refresh();
  hizn.banner('Loaded vector (' + n + ' metrics).');
}
