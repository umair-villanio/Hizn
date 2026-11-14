// @name        JWT Decoder
// @description Finds & decodes JWTs in headers and body
// @version     1.0.0
// @author      hizn

const out = [];
const scan = (ctx.body || '') + '\n' + Object.values(ctx.headers || {}).join('\n');
const re = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
const seen = new Set();
let m;
const b64 = (s) => {
    try { return decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/')))); }
    catch { return '(undecodable)'; }
};
const pretty = (s) => {
    try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; }
};
while ((m = re.exec(scan))) {
    const tok = m[0];
    if (seen.has(tok)) continue;
    seen.add(tok);
    const [h, p, sig] = tok.split('.');
    out.push(
        '<div class="jwt-seg"><div class="h">Header</div><pre class="jwt-head">' + pretty(b64(h)) + '</pre>'
        + '<div class="h">Payload</div><pre class="jwt-payload">' + pretty(b64(p)) + '</pre>'
        + '<div class="h">Signature</div><pre class="jwt-sig">' + (sig || '(none)') + '</pre></div>'
    );
}
return out.length ? out.join('') : '<pre>No JWT found in this message.</pre>';
