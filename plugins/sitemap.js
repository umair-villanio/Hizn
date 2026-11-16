// @name        Site Map
// @description Live target map of hosts & endpoints seen in traffic, plus a "copy as fetch()" button. Sample extension plugin.
// @version     1.0.0
// @author      hizn
// @kind        extension

// Extension plugins run once at load and receive the `hizn` API. They can add
// tabs, buttons, menu items, hook live traffic, call Hizn's API, and store
// state — unlike message plugins, which transform a single intercepted message.

const seen = new Map(); // host -> Set("METHOD /path")
let listEl = null;

// 1) A whole new tab in the left rail.
hizn.registerTab({
  id: 'sitemap',
  title: 'Site Map',
  icon: '◳',
  render(container) {
    container.style.padding = '16px 18px';
    container.style.overflow = 'auto';
    container.innerHTML =
      '<h3 style="margin:0 0 4px;font-size:13px;color:var(--faint);text-transform:uppercase;letter-spacing:.5px">Site map — unique endpoints seen</h3>' +
      '<div style="color:var(--faint);font-size:12px;margin-bottom:12px">Grows live as traffic is captured. Added by the <b>Site Map</b> sample plugin.</div>' +
      '<div id="xtSitemapList"></div>';
    listEl = container.querySelector('#xtSitemapList');
    draw();
  },
});

// 2) React to every captured request, live.
hizn.onFlow(function (f) {
  if (!f || !f.host) return;
  if (!seen.has(f.host)) seen.set(f.host, new Set());
  seen.get(f.host).add((f.method || 'GET') + ' ' + (f.path || '/'));
  draw();
});

function draw() {
  if (!listEl) return;
  if (!seen.size) {
    listEl.innerHTML = '<div style="color:var(--faint)">No traffic yet — capture some requests and they will appear here.</div>';
    return;
  }
  let html = '';
  for (const [host, paths] of [...seen.entries()].sort()) {
    html += '<div style="margin-bottom:12px">' +
      '<div style="font-weight:650;color:var(--accent)">' + hizn.esc(host) +
      ' <span style="color:var(--faint);font-weight:400">(' + paths.size + ')</span></div>' +
      '<div style="font-family:var(--mono);font-size:12px;color:var(--muted);padding-left:12px;margin-top:3px">' +
      [...paths].sort().map(p => hizn.esc(p)).join('<br>') + '</div></div>';
  }
  listEl.innerHTML = html;
}

// 3) An extra button in the HTTP-history detail pane.
hizn.registerButton({
  location: 'history-detail',
  label: '⎘ Copy as fetch()',
  title: 'Copy the selected request as a JavaScript fetch() call',
  onClick(flow) {
    if (!flow) { hizn.banner('Select a request in HTTP history first.'); return; }
    const headers = {};
    for (const [k, v] of Object.entries(flow.requestHeaders || {})) {
      if (/^(content-length|host)$/i.test(k)) continue;
      headers[k] = Array.isArray(v) ? v.join(', ') : String(v);
    }
    const opts = { method: flow.method || 'GET', headers };
    if (flow.requestBody) opts.body = flow.requestBody;
    const code = 'fetch(' + JSON.stringify(flow.url) + ', ' + JSON.stringify(opts, null, 2) + ');';
    navigator.clipboard.writeText(code).then(
      () => hizn.banner('Copied request as fetch().'),
      () => hizn.banner('Copy failed.'),
    );
  },
});
