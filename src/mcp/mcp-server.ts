/**
 * hizn-mcp — a Model Context Protocol (MCP) server for Hizn.
 *
 * Exposes Hizn's capabilities as MCP tools so any MCP-compatible client can
 * query and (optionally) drive the running Hizn instance: read the captured
 * HTTP history, inspect scope and devices, scan APKs, resend requests, run
 * Intruder, and resolve held intercepts.
 *
 * Transport: newline-delimited JSON-RPC 2.0 over stdio (no dependencies).
 * It talks to Hizn's local REST API, so Hizn must be running.
 *
 * Config (environment):
 *   HIZN_API_URL   base URL of the Hizn API      (default http://127.0.0.1:4000)
 *   HIZN_MCP_ACTIVE  set to 1/true to also expose the "active" tools that send
 *                    traffic or change state (off by default: read-only only).
 *
 * stdout carries the protocol — never write anything else there; logs go to
 * stderr.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import * as http from 'http';
import * as fs from 'fs/promises';
import * as path from 'path';
import { URL } from 'url';

const API_BASE = process.env['HIZN_API_URL'] || 'http://127.0.0.1:4000';
const ACTIVE_ON = /^(1|true|yes|on)$/i.test(process.env['HIZN_MCP_ACTIVE'] || '');
const SERVER_INFO = { name: 'hizn', version: '0.2.0' };

const log = (...a: unknown[]) => process.stderr.write('[hizn-mcp] ' + a.map(String).join(' ') + '\n');

/* --------------------------------------------------------- API client ---- */

interface ApiOpts { method?: string; body?: unknown; raw?: Buffer; rawName?: string; }

function apiRequest(apiPath: string, opts: ApiOpts = {}): Promise<any> {
    const url = new URL(apiPath.replace(/^\//, ''), API_BASE.replace(/\/?$/, '/') + 'api/');
    const isRaw = !!opts.raw;
    const payload = isRaw ? opts.raw! : opts.body != null ? Buffer.from(JSON.stringify(opts.body)) : undefined;
    return new Promise((resolve, reject) => {
        const req = http.request(
            {
                hostname: url.hostname, port: url.port || 80, path: url.pathname + url.search,
                method: opts.method || (payload ? 'POST' : 'GET'),
                headers: payload
                    ? { 'Content-Type': isRaw ? 'application/octet-stream' : 'application/json', 'Content-Length': payload.length }
                    : {},
                timeout: 120000,
            },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c) => chunks.push(Buffer.from(c)));
                res.on('end', () => {
                    const text = Buffer.concat(chunks).toString('utf8');
                    let data: any; try { data = JSON.parse(text); } catch { data = text; }
                    if ((res.statusCode || 0) >= 400) reject(new Error(data?.error || `HTTP ${res.statusCode}`));
                    else resolve(data);
                });
            },
        );
        req.on('error', (e) => reject(new Error(`Cannot reach Hizn at ${API_BASE} — is it running? (${e.message})`)));
        req.on('timeout', () => { req.destroy(); reject(new Error('Request to Hizn timed out')); });
        if (payload) req.write(payload);
        req.end();
    });
}

/* --------------------------------------------------------------- tools ---- */

type ToolHandler = (args: any) => Promise<unknown>;
interface Tool { name: string; description: string; inputSchema: any; active?: boolean; handler: ToolHandler; }

const obj = (props: Record<string, any>, required: string[] = []) => ({ type: 'object', properties: props, required });
const S = { str: { type: 'string' }, num: { type: 'number' }, bool: { type: 'boolean' }, strs: { type: 'array', items: { type: 'string' } } };

const TOOLS: Tool[] = [
    // ---- read-only ----
    {
        name: 'hizn_status', description: 'Get Hizn proxy status (running, port, upstream, intercept config).',
        inputSchema: obj({}), handler: () => apiRequest('/status'),
    },
    {
        name: 'list_flows', description: 'List captured HTTP flows (most recent last). Returns a compact summary.',
        inputSchema: obj({ limit: { ...S.num, description: 'Max flows to return (default 50).' }, filter: { ...S.str, description: 'Case-insensitive substring over method/host/path.' } }),
        handler: async (a) => {
            const flows: any[] = await apiRequest('/flows');
            const f = (a?.filter || '').toLowerCase();
            const rows = flows
                .filter((x) => !f || `${x.method} ${x.host} ${x.path}`.toLowerCase().includes(f))
                .slice(-(Number(a?.limit) || 50))
                .map((x) => ({ id: x.id, method: x.method, status: x.statusCode, host: x.host, path: x.path, size: x.responseBodySize }));
            return { count: rows.length, flows: rows };
        },
    },
    {
        name: 'get_flow', description: 'Get one captured flow in full (headers + captured bodies) by its id.',
        inputSchema: obj({ id: { ...S.str, description: 'Flow id from list_flows.' } }, ['id']),
        handler: async (a) => {
            const flows: any[] = await apiRequest('/flows');
            const flow = flows.find((x) => x.id === a?.id);
            if (!flow) throw new Error('No flow with id ' + a?.id);
            return flow;
        },
    },
    {
        name: 'list_devices', description: 'List ADB devices Hizn can see, with model/root/emulator info.',
        inputSchema: obj({}), handler: () => apiRequest('/devices'),
    },
    {
        name: 'get_scope', description: 'Get the current target scope (interception is limited to these hosts).',
        inputSchema: obj({}), handler: () => apiRequest('/scope'),
    },
    {
        name: 'get_intercept', description: 'Get the interception config and any currently-held requests/responses.',
        inputSchema: obj({}), handler: () => apiRequest('/intercept'),
    },
    {
        name: 'list_device_apps', description: 'List installed (third-party) app package names on a device.',
        inputSchema: obj({ serial: { ...S.str, description: 'Device serial from list_devices.' } }, ['serial']),
        handler: (a) => apiRequest('/analyzer/packages?serial=' + encodeURIComponent(a.serial)),
    },
    {
        name: 'scan_apk', description: 'Static-scan an APK and return the report (permissions, exported components, signing certificate, manifest analysis, hardcoded secrets, URLs). Provide a local file "path", OR "serial" + "package" to pull it off a device.',
        inputSchema: obj({
            path: { ...S.str, description: 'Local .apk file path.' },
            serial: { ...S.str, description: 'Device serial (with package).' },
            package: { ...S.str, description: 'Installed package name to pull + scan.' },
        }),
        handler: async (a) => {
            let report: any;
            if (a?.path) {
                const buf = await fs.readFile(a.path);
                report = await apiRequest('/analyzer/scan?name=' + encodeURIComponent(path.basename(a.path)), { raw: buf });
            } else if (a?.serial && a?.package) {
                report = await apiRequest('/analyzer/scan-device', { body: { serial: a.serial, package: a.package } });
            } else {
                throw new Error('Provide "path", or "serial" + "package".');
            }
            // Trim the heaviest arrays for a readable summary.
            return { ...report, urls: (report.urls || []).slice(0, 60), components: undefined, componentsCount: (report.components || []).length };
        },
    },
    // ---- active (state-changing / traffic-sending) ----
    {
        name: 'start_proxy', description: 'Start the interception proxy.', active: true,
        inputSchema: obj({ port: { ...S.num, description: 'Listener port (optional).' } }),
        handler: (a) => apiRequest('/proxy/start', { body: { port: a?.port } }),
    },
    {
        name: 'stop_proxy', description: 'Stop the interception proxy.', active: true,
        inputSchema: obj({}), handler: () => apiRequest('/proxy/stop', { body: {} }),
    },
    {
        name: 'send_request', description: 'Send an HTTP(S) request and return the raw response (like Repeater).', active: true,
        inputSchema: obj({
            method: { ...S.str }, url: { ...S.str }, headers: { type: 'object', description: 'Header name→value map.' },
            body: { ...S.str }, insecure: { ...S.bool, description: 'Skip TLS verification.' },
        }, ['url']),
        handler: (a) => apiRequest('/repeater/send', { body: { method: a.method, url: a.url, headers: a.headers, body: a.body, insecure: a.insecure } }),
    },
    {
        name: 'start_intruder', description: 'Launch an Intruder attack. Mark payload positions in url/headers/body with § markers. Results stream in Hizn; this returns the plan (poll Hizn UI for rows).', active: true,
        inputSchema: obj({
            url: { ...S.str, description: 'Target URL, may contain §…§ positions.' },
            method: { ...S.str }, headers: { type: 'object' }, body: { ...S.str },
            attackType: { ...S.str, enum: ['sniper', 'batteringram'] },
            payloads: { ...S.strs, description: 'Payload list.' },
            urlEncode: { ...S.bool }, insecure: { ...S.bool },
        }, ['url', 'payloads']),
        handler: (a) => apiRequest('/intruder/start', { body: a }),
    },
    {
        name: 'stop_intruder', description: 'Stop the running Intruder attack.', active: true,
        inputSchema: obj({}), handler: () => apiRequest('/intruder/stop', { body: {} }),
    },
    {
        name: 'set_scope', description: 'Set the target scope (limit interception to these hosts).', active: true,
        inputSchema: obj({ enabled: { ...S.bool }, hosts: { ...S.strs, description: 'Host patterns (substring or *wildcard).' } }, ['enabled']),
        handler: (a) => apiRequest('/scope', { body: { enabled: a.enabled, hosts: a.hosts } }),
    },
    {
        name: 'resolve_intercept', description: 'Forward or drop a held request/response (optionally edited). Use get_intercept for the id.', active: true,
        inputSchema: obj({
            id: { ...S.str }, action: { ...S.str, enum: ['forward', 'drop'] },
            headers: { type: 'object' }, body: { ...S.str }, bodyEdited: { ...S.bool },
            method: { ...S.str }, url: { ...S.str }, statusCode: { ...S.num }, interceptResponse: { ...S.bool },
        }, ['id', 'action']),
        handler: (a) => apiRequest('/intercept/resolve', { body: a }),
    },
];

function availableTools(): Tool[] { return TOOLS.filter((t) => ACTIVE_ON || !t.active); }

/* --------------------------------------------------------- JSON-RPC ------ */

function send(msg: unknown): void { process.stdout.write(JSON.stringify(msg) + '\n'); }
function reply(id: any, result: unknown): void { send({ jsonrpc: '2.0', id, result }); }
function replyError(id: any, code: number, message: string): void { send({ jsonrpc: '2.0', id, error: { code, message } }); }

async function handle(msg: any): Promise<void> {
    const { id, method, params } = msg || {};
    // Notifications (no id) get no response.
    if (method === 'notifications/initialized' || method === 'notifications/cancelled') return;

    if (method === 'initialize') {
        reply(id, {
            protocolVersion: params?.protocolVersion || '2024-11-05',
            capabilities: { tools: {} },
            serverInfo: SERVER_INFO,
        });
        return;
    }
    if (method === 'ping') { reply(id, {}); return; }
    if (method === 'tools/list') {
        reply(id, { tools: availableTools().map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) });
        return;
    }
    if (method === 'tools/call') {
        const name = params?.name;
        const tool = availableTools().find((t) => t.name === name);
        if (!tool) {
            const gated = TOOLS.some((t) => t.name === name && t.active);
            const text = gated
                ? `Tool "${name}" is an active tool and is disabled. Start the server with HIZN_MCP_ACTIVE=1 to enable traffic-sending / state-changing tools.`
                : `Unknown tool: ${name}`;
            reply(id, { content: [{ type: 'text', text }], isError: true });
            return;
        }
        try {
            const result = await tool.handler(params?.arguments || {});
            const text = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
            reply(id, { content: [{ type: 'text', text: text.slice(0, 100000) }] });
        } catch (e: any) {
            reply(id, { content: [{ type: 'text', text: 'Error: ' + (e?.message || String(e)) }], isError: true });
        }
        return;
    }
    if (id !== undefined) replyError(id, -32601, 'Method not found: ' + method);
}

/* ------------------------------------------------------------- stdio ----- */

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
    buffer += chunk;
    let nl: number;
    while ((nl = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        let msg: any; try { msg = JSON.parse(line); } catch { log('bad JSON line'); continue; }
        handle(msg).catch((e) => log('handler error', e?.message));
    }
});
process.stdin.on('end', () => process.exit(0));

log(`ready · API ${API_BASE} · ${availableTools().length} tools · active=${ACTIVE_ON ? 'on' : 'off'}`);
