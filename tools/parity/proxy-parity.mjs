#!/usr/bin/env node
// Proxy parity harness: run the Node backend and the Rust backend side by side,
// send identical traffic through both proxies, and compare
//   - what the client received (status, reason, headers, body hash),
//   - what the origin received (method, path, raw headers, body hash),
//   - the captured flow (minus ids and timestamps).
//
// Usage:
//   node tools/parity/proxy-parity.mjs --node <droidmitm checkout> --rust <hizn.exe> [--only a,b]
//
// Needs `openssl` on PATH and an OpenSSL-based curl (Git for Windows' curl;
// override with CURL=...). Uses only Node built-ins.
//
// SPDX-License-Identifier: AGPL-3.0-only

import { spawn, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import zlib from 'node:zlib';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const NODE_DIR = args.node;
const RUST_EXE = args.rust;
const ONLY = args.only ? new Set(args.only.split(',')) : null;
if (!NODE_DIR || !RUST_EXE) {
  console.error('usage: proxy-parity.mjs --node <droidmitm dir> --rust <hizn.exe> [--only a,b]');
  process.exit(2);
}
const CURL = process.env.CURL || ['C:/Program Files/Git/mingw64/bin/curl.exe', '/usr/bin/curl'].find((p) => fs.existsSync(p)) || 'curl';
const HIZN_CA = path.join(os.homedir(), '.hizn', 'ca-cert.pem');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'hizn-parity-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16);

// ------------------------------------------------------------------ certs
function openssl(...a) { execFileSync('openssl', a, { cwd: TMP, stdio: 'pipe' }); }
function makeCerts() {
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '2', '-subj', '/CN=Hizn Parity Test CA');
  openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=localhost');
  fs.writeFileSync(path.join(TMP, 'ext.cnf'),
    'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'leaf.crt', '-days', '2', '-extfile', 'ext.cnf');
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'bad.key', '-out', 'bad.crt', '-days', '2', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1');
  const r = (f) => fs.readFileSync(path.join(TMP, f));
  return { ca: r('ca.crt'), leafKey: r('leaf.key'), leafCert: r('leaf.crt'), badKey: r('bad.key'), badCert: r('bad.crt') };
}

// ----------------------------------------------------------------- origin
let originLog = [];
const BIG = Buffer.concat(Array.from({ length: 2048 }, (_, i) => crypto.createHash('sha512').update(String(i)).digest()).flatMap((d) => [d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d]));
const TEXT50K = Buffer.from('The quick brown fox jumps over the lazy dog. '.repeat(1200));

function originHandler(req, res) {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    originLog.push({ method: req.method, url: req.url, rawHeaders: pairs(req.rawHeaders), bodySha: sha(body), bodyLen: body.length });
    const p = req.url.split('?')[0];
    switch (p) {
      case '/plain': res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('hello parity\n');
      case '/json': res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ ok: true, url: req.url }));
      case '/echo': res.writeHead(200, { 'Content-Type': req.headers['content-type'] || 'application/octet-stream' }); return res.end(body);
      case '/chunked': {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        let i = 0; const t = setInterval(() => { res.write(`chunk ${i}\n`); if (++i === 3) { clearInterval(t); res.end(); } }, 20);
        return;
      }
      case '/gzip': res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Encoding': 'gzip' }); return res.end(zlib.gzipSync(TEXT50K));
      case '/br': res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Encoding': 'br' }); return res.end(zlib.brotliCompressSync(TEXT50K));
      case '/big': res.writeHead(200, { 'Content-Type': 'application/octet-stream' }); return res.end(BIG);
      case '/utf8': res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(Buffer.concat([Buffer.from('héllo 日本 🎉\n'), Buffer.from([0xff, 0xfe, 0x41])]));
      case '/204': res.writeHead(204); return res.end();
      case '/redirect': res.writeHead(302, { Location: '/plain' }); return res.end();
      case '/headers':
        res.statusMessage = 'Custom Reason';
        res.setHeader('Set-Cookie', ['a=1; Path=/', 'b=2; Path=/']);
        res.setHeader('X-Dup', ['one', 'two']);
        res.setHeader('X-Mixed-Case', 'Value');
        res.setHeader('Content-Type', 'text/plain');
        res.writeHead(200);
        return res.end('headers\n');
      case '/404': res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('nope\n');
      case '/slow-stream': {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        let i = 0; const t = setInterval(() => { if (res.destroyed) return clearInterval(t); res.write('.'); if (++i === 15) { clearInterval(t); res.end(); } }, 200);
        return;
      }
      default: res.writeHead(500); return res.end('unknown path ' + p);
    }
  });
}

// Minimal WebSocket echo (text frames), enough to exercise the passthrough.
function wsUpgrade(req, socket) {
  originLog.push({ method: req.method, url: req.url, rawHeaders: pairs(req.rawHeaders), bodySha: sha(Buffer.alloc(0)), bodyLen: 0 });
  const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  const proto = req.headers['sec-websocket-protocol'] ? `Sec-WebSocket-Protocol: ${req.headers['sec-websocket-protocol'].split(',')[0].trim()}\r\n` : '';
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n${proto}\r\n`);
  let buf = Buffer.alloc(0);
  socket.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      const f = parseFrame(buf); if (!f) break; buf = buf.subarray(f.length);
      if (f.opcode === 8) { socket.end(frame(8, f.payload, false)); return; }
      if (f.opcode === 1) socket.write(frame(1, f.payload, false));
    }
  });
  socket.on('error', () => {});
}

function parseFrame(b) {
  if (b.length < 2) return null;
  const opcode = b[0] & 0x0f; const masked = (b[1] & 0x80) !== 0; let len = b[1] & 0x7f; let off = 2;
  if (len === 126) { if (b.length < 4) return null; len = b.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (b.length < 10) return null; len = Number(b.readBigUInt64BE(2)); off = 10; }
  const maskOff = off; if (masked) off += 4;
  if (b.length < off + len) return null;
  let payload = Buffer.from(b.subarray(off, off + len));
  if (masked) for (let i = 0; i < len; i++) payload[i] ^= b[maskOff + (i % 4)];
  return { opcode, payload, length: off + len };
}
function frame(opcode, payload, mask) {
  const len = payload.length; const head = [0x80 | opcode];
  if (len < 126) head.push((mask ? 0x80 : 0) | len); else head.push((mask ? 0x80 : 0) | 126, len >> 8, len & 255);
  if (!mask) return Buffer.concat([Buffer.from(head), payload]);
  const key = crypto.randomBytes(4); const out = Buffer.from(payload); for (let i = 0; i < len; i++) out[i] ^= key[i % 4];
  return Buffer.concat([Buffer.from(head), key, out]);
}
const pairs = (raw) => { const out = []; for (let i = 0; i < raw.length; i += 2) out.push([raw[i], raw[i + 1]]); return out; };
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));

// --------------------------------------------------------------- backends
async function freePort() { const s = net.createServer(); const p = await listen(s); await new Promise((r) => s.close(r)); return p; }
async function waitHttp(url, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { const r = await fetch(url); if (r.ok) return; } catch {} await sleep(200); }
  throw new Error('timeout waiting for ' + url);
}
async function startBackend(name, cmd, cmdArgs, env, cwd) {
  const apiPort = await freePort();
  const child = spawn(cmd, cmdArgs, { cwd, env: { ...process.env, ...env, DROIDMITM_PORT: String(apiPort) }, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = ''; child.stdout.on('data', (d) => (log += d)); child.stderr.on('data', (d) => (log += d));
  const api = `http://127.0.0.1:${apiPort}/api`;
  try { await waitHttp(api + '/status'); } catch (e) { child.kill(); throw new Error(`${name} backend failed to start:\n${log}`); }
  const proxyPort = await freePort();
  const r = await (await fetch(api + '/proxy/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port: proxyPort }) })).json();
  if (!r.running) throw new Error(`${name} proxy failed to start: ${JSON.stringify(r)}`);
  return { name, api, proxyPort, child, log: () => log };
}
const post = (api, p, body) => fetch(api + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json());

// ----------------------------------------------------------------- client
function curl(backend, scenario) {
  const out = path.join(TMP, `${backend.name}-${scenario.name}.body`);
  const hdr = path.join(TMP, `${backend.name}-${scenario.name}.hdr`);
  for (const f of [out, hdr]) fs.rmSync(f, { force: true });
  const a = ['-s', '-o', out, '-D', hdr, '--cacert', HIZN_CA, '--max-time', String(scenario.maxTime ?? 10), '-H', `X-Parity: ${scenario.name}`];
  if (!scenario.direct) a.push('-x', `http://127.0.0.1:${backend.proxyPort}`);
  a.push(...(scenario.curl || []));
  a.push(typeof scenario.url === 'function' ? scenario.url(backend) : scenario.url);
  return new Promise((resolve) => {
    const c = spawn(CURL, a, { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = ''; c.stderr.on('data', (d) => (err += d));
    c.on('close', (code) => {
      const head = fs.existsSync(hdr) ? fs.readFileSync(hdr, 'latin1') : '';
      const blocks = head.split(/\r?\n\r?\n/).filter((b) => /^HTTP\//.test(b));
      const last = blocks.at(-1) || ''; // skip "200 Connection established" etc.
      const [statusLine, ...lines] = last.split(/\r?\n/);
      const m = /^HTTP\/[\d.]+ (\d+) ?(.*)$/.exec(statusLine || '');
      const headers = lines.filter(Boolean).map((l) => { const i = l.indexOf(':'); return [l.slice(0, i).toLowerCase(), l.slice(i + 1).trim()]; });
      let body = fs.existsSync(out) ? fs.readFileSync(out) : Buffer.alloc(0);
      // With -I the "body" is the header dump; drop the volatile Date line.
      if ((scenario.curl || []).includes('-I')) body = Buffer.from(body.toString('latin1').replace(/^date:.*\r?\n/im, ''), 'latin1');
      // The proxy's own port appears in loop responses; it differs per backend.
      body = Buffer.from(body.toString('latin1').replaceAll(String(backend.proxyPort), '<proxy-port>'), 'latin1');
      resolve({ curlExit: code, status: m ? Number(m[1]) : null, reason: m ? m[2] : null, headers, bodySha: sha(body), bodyLen: body.length });
    });
  });
}

// WebSocket client through the proxy (ws:// via absolute-form, wss:// via CONNECT).
function wsClient(backend, { secure, host, port }) {
  return new Promise((resolve) => {
    const result = { status: null, protocol: null, echo: null };
    const sock = net.connect(backend.proxyPort, '127.0.0.1');
    const done = () => { try { sock.destroy(); } catch {} resolve(result); };
    sock.setTimeout(5000, done); sock.on('error', done);
    const key = crypto.randomBytes(16).toString('base64');
    const handshake = (target) => `GET ${target} HTTP/1.1\r\nHost: ${host}:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: parity.v1, other\r\nX-Parity: ${secure ? 'wss' : 'ws'}\r\n\r\n`;
    const talk = (stream) => {
      let buf = Buffer.alloc(0); let upgraded = false;
      stream.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        if (!upgraded) {
          const i = buf.indexOf('\r\n\r\n'); if (i < 0) return;
          const head = buf.subarray(0, i).toString('latin1'); buf = buf.subarray(i + 4);
          result.status = Number(/^HTTP\/1\.1 (\d+)/.exec(head)?.[1]);
          result.protocol = /sec-websocket-protocol: *(.+)/i.exec(head)?.[1]?.trim() ?? null;
          upgraded = true; stream.write(frame(1, Buffer.from('hello through hizn'), true));
        }
        const f = parseFrame(buf);
        if (f && f.opcode === 1) { result.echo = f.payload.toString(); buf = buf.subarray(f.length); stream.write(frame(8, Buffer.from([0x03, 0xe8]), true)); setTimeout(done, 300); }
      });
      stream.on('error', done);
    };
    if (!secure) {
      // Real clients (OkHttp, browsers) send plain ws:// through a proxy as an
      // absolute-form http:// upgrade request.
      sock.on('connect', () => { talk(sock); sock.write(handshake(`http://${host}:${port}/ws`)); });
    } else {
      sock.on('connect', () => sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
      sock.once('data', () => {
        const t = tls.connect({ socket: sock, servername: host, ca: fs.readFileSync(HIZN_CA), ALPNProtocols: ['http/1.1'] }, () => { talk(t); t.write(handshake('/ws')); });
        t.on('error', done);
      });
    }
  });
}

// HTTP/2-only client (gRPC-style: offers only h2) through a CONNECT tunnel.
function h2Client(backend, { host, port, path: reqPath, token }) {
  return new Promise((resolve) => {
    const sock = net.connect(backend.proxyPort, '127.0.0.1', () => sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    sock.on('error', (e) => resolve({ error: e.message }));
    sock.once('data', () => {
      const t = tls.connect({ socket: sock, servername: host, ca: fs.readFileSync(HIZN_CA), ALPNProtocols: ['h2'] });
      t.on('error', (e) => resolve({ error: e.message }));
      t.once('secureConnect', () => {
        const client = http2.connect(`https://${host}:${port}`, { createConnection: () => t });
        client.on('error', (e) => resolve({ error: e.message }));
        const req = client.request({ ':path': reqPath, 'x-parity': token });
        let status = null; const chunks = [];
        req.on('response', (h) => { status = h[':status']; });
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => { client.close(); resolve({ alpn: t.alpnProtocol, status, bodySha: sha(Buffer.concat(chunks)) }); });
        req.on('error', (e) => resolve({ error: e.message }));
        req.end();
      });
    });
  });
}

// ---------------------------------------------------------------- compare
const STRIP_FLOW = new Set(['id', 'startedAt', 'completedAt']);
// Hop/transport headers that legitimately vary by connection handling.
const STRIP_CLIENT_HDR = new Set(['date', 'connection', 'keep-alive', 'proxy-connection']);
// Values that differ on every run (time, per-connection randomness).
const VOLATILE_HDR = new Set(['date', 'sec-websocket-key', 'sec-websocket-accept']);

// Differences that are expected, each with the reason. A scenario passes when
// every difference it shows is listed here.
const KNOWN = {
  'https-ip': [[/./, "Node's leaf cert has no IP SAN, so clients reject HTTPS-by-IP; Rust's includes it (improvement)"]],
  'client-abort': [[/^client\./, 'Node buffers each whole response before sending any of it; Rust streams (improvement: SSE / long responses work)']],
  'ws': [
    [/flow\.(wsMessages|wsCloseCode)/, 'WebSocket frame history is Phase 3'],
    [/sec-websocket-protocol|origin: .*Sec-WebSocket-Protocol/i, 'Node forwards only the first offered subprotocol; Rust passes the header through unchanged (improvement)'],
  ],
  'tls-untrusted-origin': [[/responseBody|bodySha|bodyLen|responseBodySize/, 'TLS failure wording differs (OpenSSL vs rustls)']],
};
KNOWN.wss = KNOWN.ws;
KNOWN['h2-only'] = [[/^origin: .*\["Connection","keep-alive"\]/, 'Node adds "Connection: keep-alive" when converting HTTP/2 to HTTP/1.1; Rust omits it, since a connection header would break HTTP/2-capable origins']];
// Error replies: Node sends no headers and closes; Rust adds content-length.
for (const k of ['refused', 'dns-fail', 'tls-untrusted-origin', 'loop']) {
  (KNOWN[k] ||= []).push([/^client\.headers/, 'error reply framing: Node is close-delimited, Rust sends content-length (same body)']);
}

/** Replace the given port numbers (as numbers or inside strings) with labels. */
function normalizePorts(v, map) {
  if (typeof v === 'number' && map[v]) return map[v];
  if (typeof v === 'string') { for (const [port, label] of Object.entries(map)) v = v.replaceAll(port, label); return v; }
  if (Array.isArray(v)) return v.map((x) => normalizePorts(x, map));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, normalizePorts(x, map)]));
  return v;
}

function scrub(v) {
  if (Array.isArray(v)) {
    // raw header pairs
    if (v.every((p) => Array.isArray(p) && p.length === 2 && typeof p[0] === 'string')) {
      return v.map(([k, val]) => [k, VOLATILE_HDR.has(k.toLowerCase()) ? '<volatile>' : val]);
    }
    return v.map(scrub);
  }
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, val] of Object.entries(v)) o[k] = VOLATILE_HDR.has(k) ? '<volatile>' : scrub(val);
    return o;
  }
  return v;
}
function diff(a, b, at = '') {
  if (JSON.stringify(a) === JSON.stringify(b)) return [];
  if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])];
    const order = JSON.stringify(Object.keys(a)) !== JSON.stringify(Object.keys(b)) && keys.every((k) => k in a && k in b)
      ? [`${at || '.'}: key order node=${Object.keys(a)} rust=${Object.keys(b)}`] : [];
    return [...order, ...keys.flatMap((k) => diff(a[k], b[k], `${at}.${k}`))];
  }
  const show = (v) => { const s = JSON.stringify(v); return s && s.length > 160 ? s.slice(0, 160) + '…' : s; };
  return [`${at || '.'}: node=${show(a)} rust=${show(b)}`];
}
function normFlow(f) {
  if (!f) return null;
  const o = {}; for (const [k, v] of Object.entries(scrub(f))) if (!STRIP_FLOW.has(k)) o[k] = v;
  if (o.responseBody && o.responseBody.length > 200) o.responseBody = `<${o.responseBody.length} chars sha ${sha(Buffer.from(o.responseBody))}>`;
  if (o.requestBody && o.requestBody.length > 200) o.requestBody = `<${o.requestBody.length} chars sha ${sha(Buffer.from(o.requestBody))}>`;
  return o;
}
const normClient = (c) => ({ ...c, headers: c.headers.filter(([k]) => !STRIP_CLIENT_HDR.has(k)) });

async function flowFor(backend, token) {
  const flows = (await (await fetch(backend.api + '/flows')).json()).filter((f) => f.requestHeaders?.['x-parity'] === token);
  // Prefer the flow that got an outcome (Node records a second, dangling flow
  // for a loop).
  const flow = flows.filter((f) => f.statusCode || f.error).at(-1) ?? flows.at(-1) ?? null;
  // Each backend listens on its own proxy port, which shows up in loop flows.
  return flow && normalizePorts(flow, { [backend.proxyPort]: '<proxy-port>' });
}

// --------------------------------------------------------------------- run
async function main() {
  console.log('temp dir:', TMP);
  const certs = makeCerts();
  const caFile = path.join(TMP, 'ca.crt');
  const httpPort = await listen(http.createServer(originHandler).on('upgrade', wsUpgrade));
  const httpsPort = await listen(https.createServer({ key: certs.leafKey, cert: certs.leafCert }, originHandler).on('upgrade', wsUpgrade));
  const badPort = await listen(https.createServer({ key: certs.badKey, cert: certs.badCert }, originHandler));
  const closedPort = await freePort();

  // Upstream (Burp stand-in): tunnels CONNECT, forwards absolute-form HTTP.
  let upstreamLog = [];
  const upstream = http.createServer((req, res) => {
    upstreamLog.push(`${req.method} ${req.url}`);
    const u = new URL(req.url);
    const fwd = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method: req.method, headers: req.headers }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    fwd.on('error', () => { res.writeHead(502); res.end(); }); req.pipe(fwd);
  }).on('connect', (req, sock, head) => {
    upstreamLog.push(`CONNECT ${req.url}`);
    const [h, p] = req.url.split(':'); const s = net.connect(Number(p), h, () => { sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); s.write(head); s.pipe(sock); sock.pipe(s); });
    s.on('error', () => sock.destroy()); sock.on('error', () => s.destroy());
  });
  const upstreamPort = await listen(upstream);

  const bigUpload = path.join(TMP, 'upload-1mb.bin'); fs.writeFileSync(bigUpload, BIG.subarray(0, 1024 * 1024));
  const H = `http://127.0.0.1:${httpPort}`; const S = `https://localhost:${httpsPort}`;
  const scenarios = [
    { name: 'http-get', url: `${H}/plain` },
    { name: 'https-get', url: `${S}/plain` },
    { name: 'https-ip', url: `https://127.0.0.1:${httpsPort}/plain` },
    { name: 'query', url: `${S}/json?x=1&y=two%20words` },
    { name: 'post-json', url: `${S}/echo`, curl: ['-X', 'POST', '-H', 'Content-Type: application/json', '--data-binary', '{"a":1,"b":"é"}'] },
    { name: 'put-1mb', url: `${S}/echo`, curl: ['-X', 'PUT', '-H', 'Content-Type: application/octet-stream', '--data-binary', '@' + bigUpload] },
    { name: 'chunked', url: `${S}/chunked` },
    { name: 'gzip', url: `${S}/gzip` },
    { name: 'brotli', url: `${S}/br` },
    { name: 'big-2mb', url: `${S}/big` },
    { name: 'utf8', url: `${S}/utf8` },
    { name: 'no-content', url: `${S}/204` },
    { name: 'head', url: `${S}/plain`, curl: ['-I'] },
    { name: 'redirect', url: `${S}/redirect` },
    { name: 'resp-headers', url: `${S}/headers` },
    { name: 'req-dup-headers', url: `${S}/plain`, curl: ['-H', 'X-Req: a', '-H', 'X-Req: b', '-H', 'Cookie: c=1', '-H', 'Cookie: d=2', '-H', 'X-Case-Test: Keep'] },
    { name: 'not-found', url: `${S}/404` },
    { name: 'tunnel-plain-http', url: `${H}/plain`, curl: ['--proxytunnel'] },
    { name: 'refused', url: `http://127.0.0.1:${closedPort}/x` },
    { name: 'dns-fail', url: 'http://hizn-parity-nonexistent.invalid/x' },
    { name: 'tls-untrusted-origin', url: `https://localhost:${badPort}/plain` },
    { name: 'client-abort', url: `${S}/slow-stream`, maxTime: 1, settle: 3500 },
    { name: 'loop', url: (b) => `http://127.0.0.1:${b.proxyPort}/loop`, direct: true },
  ].filter((s) => !ONLY || ONLY.has(s.name));

  const env = { NODE_EXTRA_CA_CERTS: caFile, HIZN_EXTRA_CA_CERTS: caFile };
  const nodeB = await startBackend('node', process.execPath, [path.join(NODE_DIR, 'dist', 'index.js')], env, NODE_DIR);
  const rustB = await startBackend('rust', RUST_EXE, [], env, path.dirname(RUST_EXE));
  console.log(`node api ${nodeB.api} proxy :${nodeB.proxyPort} | rust api ${rustB.api} proxy :${rustB.proxyPort}\n`);

  const results = [];
  const record = (name, node, rust) => {
    const lines = [
      ...diff(normClient(node.client), normClient(rust.client), 'client'),
      ...diff(scrub(node.origin), scrub(rust.origin), 'origin'),
      ...diff(normFlow(node.flow), normFlow(rust.flow), 'flow'),
      ...(node.extra || rust.extra ? diff(node.extra, rust.extra, 'extra') : []),
    ];
    const known = [], unknown = [];
    for (const l of lines) {
      const hit = (KNOWN[name] || []).find(([re]) => re.test(l));
      (hit ? known : unknown).push(hit ? `${l}\n      ↳ known: ${hit[1]}` : l);
    }
    if (process.env.DUMP === name) console.log(JSON.stringify({ node, rust }, null, 1));
    results.push({ name, ok: unknown.length === 0, known: known.length });
    console.log(`${unknown.length ? 'DIFF ' : known.length ? 'SAME*' : 'SAME '} ${name}`);
    for (const l of unknown) console.log('  ' + l);
    if (process.env.SHOW_KNOWN) for (const l of known) console.log('  ' + l);
  };

  for (const s of scenarios) {
    const run = {};
    for (const b of [nodeB, rustB]) {
      originLog = [];
      const client = await curl(b, s);
      await sleep(s.settle ?? 350);
      run[b.name] = { client, origin: originLog.map(({ method, url, rawHeaders, bodySha, bodyLen }) => ({ method, url, rawHeaders, bodySha, bodyLen })), flow: await flowFor(b, s.name) };
    }
    record(s.name, run.node, run.rust);
  }

  // WebSockets.
  for (const [name, secure, port] of [['ws', false, httpPort], ['wss', true, httpsPort]]) {
    if (ONLY && !ONLY.has(name)) continue;
    const run = {};
    for (const b of [nodeB, rustB]) {
      originLog = [];
      const ws = await wsClient(b, { secure, host: secure ? 'localhost' : '127.0.0.1', port });
      await sleep(500);
      run[b.name] = { client: { ...ws, headers: [] }, origin: originLog.map(({ method, url, rawHeaders }) => ({ method, url, rawHeaders })), flow: await flowFor(b, name) };
    }
    record(name, run.node, run.rust);
  }

  // HTTP/2-only client against an HTTP/1.1-only origin.
  if (!ONLY || ONLY.has('h2-only')) {
    const run = {};
    for (const b of [nodeB, rustB]) {
      originLog = [];
      const client = await h2Client(b, { host: 'localhost', port: httpsPort, path: '/plain?h2=1', token: 'h2-only' });
      await sleep(350);
      run[b.name] = { client: { ...client, headers: [] }, origin: originLog.map(({ method, url, rawHeaders, bodySha }) => ({ method, url, rawHeaders, bodySha })), flow: await flowFor(b, 'h2-only') };
    }
    record('h2-only', run.node, run.rust);
  }

  // Upstream (Burp) chaining.
  if (!ONLY || ONLY.has('upstream')) {
    for (const b of [nodeB, rustB]) await post(b.api, '/upstream', { enabled: true, host: '127.0.0.1', port: upstreamPort });
    for (const s of [{ name: 'chain-http', url: `${H}/plain` }, { name: 'chain-https', url: `${S}/plain` }]) {
      const run = {};
      for (const b of [nodeB, rustB]) {
        originLog = []; upstreamLog = [];
        const client = await curl(b, s); await sleep(350);
        run[b.name] = { client, origin: originLog.map(({ method, url, bodySha }) => ({ method, url, bodySha })), flow: await flowFor(b, s.name), extra: { upstreamSaw: upstreamLog } };
      }
      record(s.name, run.node, run.rust);
    }
    for (const b of [nodeB, rustB]) await post(b.api, '/upstream', { enabled: false, host: '127.0.0.1', port: 8080 });
  }

  // REST API + WebSocket hello parity (same calls against both backends).
  if (!ONLY || ONLY.has('api')) {
    // Blocks the port on all interfaces (dual-stack), so it's in use for both.
    const blocker = net.createServer();
    const busyPort = await new Promise((r) => blocker.listen(0, () => r(blocker.address().port)));
    const call = async (b, method, p, body) => {
      const r = await fetch(b.api + p, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
      const text = await r.text();
      let json; try { json = JSON.parse(text); } catch { json = { raw: sha(Buffer.from(text)) }; }
      return { status: r.status, type: (r.headers.get('content-type') || '').split(';')[0], body: json };
    };
    const hello = (b) => new Promise((resolve) => {
      const got = []; const ws = new WebSocket(b.api.replace('http', 'ws').replace('/api', '/ws'));
      ws.onmessage = (e) => { const m = JSON.parse(e.data); got.push(m.type === 'flow-snapshot' ? `flow-snapshot(${m.flows.length})` : m.type); };
      setTimeout(() => { ws.close(); resolve(got); }, 800);
    });
    const steps = [
      ['upstream on', 'POST', '/upstream', { enabled: true, host: '10.0.0.5', port: 8081 }],
      ['upstream off', 'POST', '/upstream', { enabled: false, host: '127.0.0.1', port: 8080 }],
      ['import', 'POST', '/flows/import', { flows: [{ id: 'a', x: 1 }, { id: '', x: 2 }, { x: 3 }, { id: 'b', y: 'é' }, null] }],
      ['flows after import', 'GET', '/flows'],
      ['hello'],
      ['clear', 'POST', '/flows/clear'],
      ['flows after clear', 'GET', '/flows'],
      ['stop', 'POST', '/proxy/stop'],
      ['status stopped', 'GET', '/status'],
      ['stop again', 'POST', '/proxy/stop'],
      ['start busy port', 'POST', '/proxy/start', { port: busyPort }],
      ['status after failed start', 'GET', '/status'],
      ['start default (still busy)', 'POST', '/proxy/start', {}],
      ['start own port', 'POST', '/proxy/start', (b) => ({ port: b.proxyPort })],
      ['start while running', 'POST', '/proxy/start', { port: 1 }],
      ['ca', 'GET', '/ca'],
      ['not json body', 'POST', '/flows/import'],
    ];
    for (const [label, method, p, body] of steps) {
      const run = {};
      for (const b of [nodeB, rustB]) {
        const r = label === 'hello' ? { body: await hello(b) } : await call(b, method, p, typeof body === 'function' ? body(b) : body);
        // Ports differ per backend: normalize the ones we chose.
        run[b.name] = { client: { headers: [] }, origin: [], flow: null, extra: normalizePorts(r, { [b.proxyPort]: '<proxy-port>', [busyPort]: '<busy-port>' }) };
      }
      record(`api: ${label}`, run.node, run.rust);
    }
    blocker.close();
  }

  const failed = results.filter((r) => !r.ok);
  const withKnown = results.filter((r) => r.ok && r.known);
  console.log(`\n${results.length - failed.length}/${results.length} match` +
    (withKnown.length ? ` (${withKnown.length} with only known, explained differences: ${withKnown.map((r) => r.name).join(', ')} — SHOW_KNOWN=1 to list)` : '') +
    (failed.length ? `\nUNEXPLAINED differences in: ${failed.map((r) => r.name).join(', ')}` : ''));
  for (const b of [nodeB, rustB]) b.child.kill();
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
