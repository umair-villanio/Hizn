/**
 * ProxyService — the interception engine.
 *
 * Wraps mockttp (the open-source MITM library that also powers HTTP Toolkit).
 * Responsibilities:
 *   - Generate / hold a root CA used to decrypt TLS.
 *   - Run a local HTTP(S) proxy that intercepts and records traffic.
 *   - Optionally chain upstream to another proxy (e.g. Burp Suite) so flows
 *     go:  device -> hizn -> Burp -> internet.
 *   - Emit a simplified "flow" event stream for the UI.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { EventEmitter } from 'events';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import * as mockttp from 'mockttp';

export interface CA {
    key: string;  // PEM
    cert: string; // PEM
}

export interface UpstreamConfig {
    /** When set, all traffic is forwarded through this proxy (e.g. Burp). */
    enabled: boolean;
    host: string;
    port: number;
}

export interface Flow {
    id: string;
    method: string;
    protocol: string;
    host: string;
    path: string;
    url: string;
    requestHeaders: Record<string, string | string[] | undefined>;
    statusCode?: number;
    statusMessage?: string;
    responseHeaders?: Record<string, string | string[] | undefined>;
    requestBodySize?: number;
    responseBodySize?: number;
    /** Captured body text (capped), for the detail pane and exports. */
    requestBody?: string;
    responseBody?: string;
    startedAt: number;
    completedAt?: number;
    error?: string;
    /** WebSocket flow marker + state (set only for ws:// / wss:// flows). */
    ws?: boolean;
    wsState?: 'connecting' | 'open' | 'closed';
    wsCloseCode?: number;
}

/** A single WebSocket frame, as relayed to the UI history. */
export interface WsMessage {
    /** Owning flow id (the websocket stream id). */
    id: string;
    /** From the app's point of view: outgoing = client→server, incoming = server→client. */
    dir: 'outgoing' | 'incoming';
    /** Decoded text (capped). Empty for binary frames with no printable text. */
    text: string;
    isBinary: boolean;
    size: number;
    truncated: boolean;
    at: number;
}

/** Burp-style interception: hold traffic until the user forwards or drops it. */
export interface InterceptConfig {
    enabled: boolean;
    /** Hold requests on the way out. */
    requests: boolean;
    /** Hold responses on the way back. */
    responses: boolean;
}

/** A paused request or response awaiting the user's decision. */
export interface InterceptItem {
    id: string;            // unique intercept id (flowId, or flowId:res)
    flowId: string;        // the owning flow
    kind: 'request' | 'response';
    method?: string;
    url?: string;
    host?: string;
    path?: string;
    statusCode?: number;
    statusMessage?: string;
    headers: Record<string, string | string[] | undefined>;
    body: string;          // decoded text (may be empty for binary)
    bodyTruncated?: boolean;
    startedAt: number;
}

/** What the user decided for a held item. */
export interface InterceptDecision {
    action: 'forward' | 'drop';
    headers?: Record<string, string | string[] | undefined>;
    body?: string;
    bodyEdited?: boolean;
    method?: string;
    url?: string;
    statusCode?: number;
    statusMessage?: string;
    /** For a request: also hold the response to this specific request. */
    interceptResponse?: boolean;
}

interface PendingIntercept {
    item: InterceptItem;
    resolve: (decision: InterceptDecision) => void;
}

/** A Burp-style auto-rewrite rule applied to all traffic. */
export interface MatchReplaceRule {
    id: string;
    enabled: boolean;
    part: 'request-url' | 'request-header' | 'request-body'
        | 'response-header' | 'response-body';
    match: string;
    replace: string;
    /** Treat `match` as a regex (default) or a literal string. */
    regex?: boolean;
    comment?: string;
}

/** Target scope — limit interception to specific hosts (Burp-style). */
export interface ScopeConfig {
    enabled: boolean;
    /** Host patterns; substring, or wildcard like *.example.com. Empty = all. */
    hosts: string[];
}

export interface ProxyStatus {
    running: boolean;
    port: number;
    upstream: UpstreamConfig;
    intercept: InterceptConfig;
    caFingerprint?: string;
}

const DEFAULT_PROXY_PORT = 8000;

/** Cap body text sent to the UI so a huge download can't flood the socket. */
const MAX_INTERCEPT_BODY = 512 * 1024;

/** Cap each WebSocket frame relayed to the UI (frames can be very chatty). */
const MAX_WS_MSG = 64 * 1024;

export class ProxyService extends EventEmitter {
    private server?: mockttp.Mockttp;
    private ca?: CA;
    private port = DEFAULT_PROXY_PORT;
    private upstream: UpstreamConfig = {
        enabled: false,
        host: '127.0.0.1',
        port: 8080, // Burp's default listener
    };
    private intercept: InterceptConfig = {
        enabled: false,
        requests: true,
        // Off by default — responses are only held when the user asks to
        // intercept the response to a *specific* request (Burp-style), or
        // turns this global switch on explicitly.
        responses: false,
    };
    /** Currently-held items keyed by intercept id. */
    private pending = new Map<string, PendingIntercept>();
    /** Flow ids whose response the user chose to intercept (per-request). */
    private responseWatch = new Set<string>();
    /** Auto match & replace rules applied to all traffic. */
    private rules: MatchReplaceRule[] = [];
    /** Target scope — gates interception to specific hosts. */
    private scope: ScopeConfig = { enabled: false, hosts: [] };
    /** flowId → request host, so responses can be scope-matched. */
    private flowHosts = new Map<string, string>();

    /**
     * Return the root CA in PEM form, persisting it so it survives restarts.
     *
     * The CA is written to ~/.hizn once and reused on every later launch. This
     * is essential: if we minted a fresh CA each run, the certificate the user
     * imported into Firefox / their device would keep a matching *name* but a
     * different key, and the client would reject every leaf with
     * SEC_ERROR_BAD_SIGNATURE. A stable CA means "import once, trust forever"
     * (exactly how Burp's CA works).
     */
    private readonly caDir = path.join(os.homedir(), '.hizn');
    private readonly caKeyPath = path.join(this.caDir, 'ca-key.pem');
    private readonly caCertPath = path.join(this.caDir, 'ca-cert.pem');

    async getCA(): Promise<CA> {
        if (this.ca) return this.ca;

        // 1. Reuse a previously-persisted CA if one exists.
        try {
            const [key, cert] = await Promise.all([
                fs.readFile(this.caKeyPath, 'utf8'),
                fs.readFile(this.caCertPath, 'utf8'),
            ]);
            if (key.includes('PRIVATE KEY') && cert.includes('CERTIFICATE')) {
                this.ca = { key, cert };
                return this.ca;
            }
        } catch { /* no stored CA yet — generate and persist one below */ }

        // 2. First run (or unreadable store): generate once, then save.
        const generated = await mockttp.generateCACertificate({
            subject: {
                commonName: 'hizn CA - interception only',
                organizationName: 'hizn',
                countryName: 'XX',
            },
            bits: 2048,
        });
        this.ca = { key: generated.key, cert: generated.cert };
        try {
            await fs.mkdir(this.caDir, { recursive: true });
            // The private key is sensitive — keep it owner-only where supported.
            await fs.writeFile(this.caKeyPath, generated.key, { encoding: 'utf8', mode: 0o600 });
            await fs.writeFile(this.caCertPath, generated.cert, { encoding: 'utf8', mode: 0o644 });
        } catch { /* non-fatal: fall back to an in-memory-only CA this run */ }
        return this.ca;
    }

    getUpstream(): UpstreamConfig {
        return { ...this.upstream };
    }

    /**
     * Update the upstream (Burp) configuration. If the proxy is already
     * running, the rules are rebuilt so the change takes effect immediately.
     */
    async setUpstream(config: Partial<UpstreamConfig>): Promise<void> {
        this.upstream = { ...this.upstream, ...config };
        if (this.server) {
            await this.applyRules();
        }
        this.emit('upstream-changed', this.getUpstream());
    }

    isRunning(): boolean {
        return !!this.server;
    }

    getPort(): number {
        return this.port;
    }

    async getStatus(): Promise<ProxyStatus> {
        return {
            running: this.isRunning(),
            port: this.port,
            upstream: this.getUpstream(),
            intercept: this.getInterceptConfig(),
            caFingerprint: this.ca ? await this.caFingerprint() : undefined,
        };
    }

    // ---------------------------------------------------------------- Intercept

    getInterceptConfig(): InterceptConfig {
        return { ...this.intercept };
    }

    /** Snapshot of all currently-held items (for a newly-connected UI). */
    listPending(): InterceptItem[] {
        return [...this.pending.values()].map((p) => p.item);
    }

    /**
     * Toggle Burp-style interception. Turning a kind OFF releases every item of
     * that kind that is currently held, forwarded unchanged — just like
     * flipping Burp's "Intercept is on" switch back off.
     */
    setInterceptConfig(config: Partial<InterceptConfig>): InterceptConfig {
        const prev = this.intercept;
        this.intercept = { ...prev, ...config };

        const nowOff = (kind: 'request' | 'response') =>
            !this.intercept.enabled ||
            (kind === 'request' && !this.intercept.requests) ||
            (kind === 'response' && !this.intercept.responses);

        for (const p of [...this.pending.values()]) {
            if (nowOff(p.item.kind)) p.resolve({ action: 'forward' });
        }
        this.emit('intercept-config', this.getInterceptConfig());
        return this.getInterceptConfig();
    }

    /** Apply the user's Forward/Drop decision to a held item. */
    resolveIntercept(id: string, decision: InterceptDecision): boolean {
        const p = this.pending.get(id);
        if (!p) return false;
        p.resolve(decision);
        return true;
    }

    /** Release everything (e.g. on stop) so no socket hangs forever. */
    private releaseAllPending(): void {
        for (const p of [...this.pending.values()]) p.resolve({ action: 'forward' });
        this.pending.clear();
        this.responseWatch.clear();
    }

    // ---------------------------------------------------------- Match & Replace

    getRules(): MatchReplaceRule[] {
        return this.rules.map((r) => ({ ...r }));
    }

    setRules(rules: MatchReplaceRule[]): MatchReplaceRule[] {
        this.rules = Array.isArray(rules) ? rules.filter((r) => r && r.part && r.match != null) : [];
        this.emit('rules-changed', this.getRules());
        return this.getRules();
    }

    private hasRule(part: MatchReplaceRule['part']): boolean {
        return this.rules.some((r) => r.enabled && r.part === part);
    }

    // ------------------------------------------------------------------ Scope

    getScope(): ScopeConfig {
        return { enabled: this.scope.enabled, hosts: [...this.scope.hosts] };
    }

    setScope(scope: Partial<ScopeConfig>): ScopeConfig {
        if (typeof scope.enabled === 'boolean') this.scope.enabled = scope.enabled;
        if (Array.isArray(scope.hosts)) {
            this.scope.hosts = scope.hosts.map((h) => String(h).trim()).filter(Boolean);
        }
        this.emit('scope-changed', this.getScope());
        return this.getScope();
    }

    private hostMatches(host: string, pattern: string): boolean {
        const h = (host || '').toLowerCase();
        const noPort = h.replace(/:\d+$/, '');
        const p = pattern.toLowerCase();
        if (p.includes('*')) {
            const re = new RegExp('^' + p.replace(/[.]/g, '\\.').replace(/\*/g, '.*') + '$');
            return re.test(h) || re.test(noPort);
        }
        return h.includes(p) || noPort.includes(p);
    }

    /** Is a host in scope? When scope is off or has no hosts, everything is. */
    private inScope(host: string): boolean {
        if (!this.scope.enabled || this.scope.hosts.length === 0) return true;
        return this.scope.hosts.some((p) => this.hostMatches(host, p));
    }

    /** Apply one rule's match→replace to a string. */
    private doReplace(input: string, rule: MatchReplaceRule): string {
        try {
            if (rule.regex === false) return input.split(rule.match).join(rule.replace);
            return input.replace(new RegExp(rule.match, 'g'), rule.replace);
        } catch {
            return input; // invalid regex → leave untouched
        }
    }

    private serializeHeaders(h: Record<string, any>): string {
        const lines: string[] = [];
        for (const [k, v] of Object.entries(h ?? {})) {
            (Array.isArray(v) ? v : [v]).forEach((val) => {
                if (val !== undefined) lines.push(`${k}: ${val}`);
            });
        }
        return lines.join('\n');
    }

    private parseHeaders(text: string): Record<string, string | string[]> {
        const h: Record<string, string | string[]> = {};
        for (const line of text.split('\n')) {
            const i = line.indexOf(':');
            if (i < 0) continue;
            const k = line.slice(0, i).trim();
            const val = line.slice(i + 1).trim();
            if (!k) continue;
            if (h[k] === undefined) h[k] = val;
            else h[k] = ([] as string[]).concat(h[k] as any, val);
        }
        return h;
    }

    /** Run all enabled header rules of `part` over a header set. */
    private applyHeaderRules(headers: Record<string, any>, part: MatchReplaceRule['part']) {
        let text = this.serializeHeaders(headers);
        let changed = false;
        for (const r of this.rules) {
            if (!r.enabled || r.part !== part) continue;
            const next = this.doReplace(text, r);
            if (next !== text) { text = next; changed = true; }
        }
        return { headers: changed ? this.parseHeaders(text) : headers, changed };
    }

    private async bodyText(body: any): Promise<{ text: string; truncated: boolean }> {
        try {
            const full = (await body?.getText?.()) ?? '';
            if (full.length > MAX_INTERCEPT_BODY) {
                return { text: full.slice(0, MAX_INTERCEPT_BODY), truncated: true };
            }
            return { text: full, truncated: false };
        } catch {
            return { text: '', truncated: false };
        }
    }

    /** Register a held item, emit it to the UI, and await the decision. */
    private holdFor(item: InterceptItem): Promise<InterceptDecision> {
        return new Promise<InterceptDecision>((resolve) => {
            this.pending.set(item.id, { item, resolve });
            this.emit('intercept', item);
        }).then((decision) => {
            this.pending.delete(item.id);
            this.emit('intercept-closed', { id: item.id });
            return decision;
        });
    }

    private async caFingerprint(): Promise<string | undefined> {
        if (!this.ca) return undefined;
        // A short, human-comparable identifier for the active CA.
        const { createHash } = await import('crypto');
        const body = this.ca.cert
            .replace(/-----[^-]+-----/g, '')
            .replace(/\s+/g, '');
        const der = Buffer.from(body, 'base64');
        return createHash('sha256').update(der).digest('hex').slice(0, 16);
    }

    /** Start the intercepting proxy. Safe to call when already running. */
    async start(port = DEFAULT_PROXY_PORT): Promise<ProxyStatus> {
        if (this.server) return this.getStatus();

        this.port = port;
        const ca = await this.getCA();

        this.server = mockttp.getLocal({
            https: { key: ca.key, cert: ca.cert },
            // Keep going even if a single upstream connection fails.
            recordTraffic: false,
        });

        this.wireEvents(this.server);
        try {
            await this.server.start(port);
            await this.applyRules();
        } catch (e) {
            // A failed bind (e.g. EADDRINUSE) must not poison state —
            // drop the server so a retry is possible.
            await this.server.stop().catch(() => {});
            this.server = undefined;
            throw e;
        }

        this.emit('status', await this.getStatus());
        return this.getStatus();
    }

    async stop(): Promise<void> {
        if (!this.server) return;
        this.releaseAllPending();
        await this.server.stop();
        this.server = undefined;
        this.emit('status', await this.getStatus());
    }

    /**
     * (Re)build the passthrough rules. A single catch-all rule forwards every
     * request, transparently decrypting TLS, optionally via the upstream proxy.
     */
    private async applyRules(): Promise<void> {
        if (!this.server) return;
        await this.server.reset(); // clears rules but keeps the server + port

        this.wireEvents(this.server); // reset() drops listeners added via rules only; keep server events

        const passThroughOptions: any = {
            beforeRequest: (req: any) => this.onBeforeRequest(req),
            beforeResponse: (res: any) => this.onBeforeResponse(res),
        };
        if (this.upstream.enabled) {
            passThroughOptions.proxyConfig = {
                proxyUrl: `http://${this.upstream.host}:${this.upstream.port}`,
            };
        }

        await this.server.forAnyRequest().thenPassThrough(passThroughOptions);
        // WebSockets are forwarded plainly, but every frame is still observed
        // and streamed to the UI history (see the ws* subscriptions in wireEvents).
        await this.server.forAnyWebSocket().thenPassThrough(
            this.upstream.enabled
                ? { proxyConfig: { proxyUrl: `http://${this.upstream.host}:${this.upstream.port}` } }
                : {},
        );
    }

    /**
     * mockttp hook: runs before a request is forwarded (to Burp/internet). When
     * interception is on we hold it and hand the user Forward/Drop control.
     */
    private async onBeforeRequest(req: any): Promise<any> {
        const host = (req.headers?.['host'] as string) ?? (() => { try { return new URL(req.url).host; } catch { return ''; } })();
        this.flowHosts.set(req.id, host);
        const holding = this.intercept.enabled && this.intercept.requests && this.inScope(host);
        const bodyRules = this.hasRule('request-body');
        if (!holding && !this.hasRule('request-url') && !this.hasRule('request-header') && !bodyRules) {
            return undefined; // nothing to do
        }

        const binfo = (holding || bodyRules) ? await this.bodyText(req.body) : { text: undefined as any, truncated: false };

        // 1. Auto match & replace (so intercept shows the rewritten message).
        let url = req.url, headers = req.headers, body = binfo.text;
        let uChanged = false, hChanged = false, bChanged = false;
        for (const r of this.rules) {
            if (r.enabled && r.part === 'request-url') {
                const n = this.doReplace(url, r); if (n !== url) { url = n; uChanged = true; }
            }
        }
        if (this.hasRule('request-header')) {
            const res = this.applyHeaderRules(headers, 'request-header');
            if (res.changed) { headers = res.headers; hChanged = true; }
        }
        if (bodyRules && body != null) {
            for (const r of this.rules) {
                if (r.enabled && r.part === 'request-body') {
                    const n = this.doReplace(body, r); if (n !== body) { body = n; bChanged = true; }
                }
            }
        }

        // 2. Intercept (optional) — holds and shows the rewritten message.
        if (holding) {
            const decision = await this.holdFor({
                id: req.id, flowId: req.id, kind: 'request',
                method: req.method, url,
                host: (headers?.['host'] as string) ?? (() => { try { return new URL(url).host; } catch { return ''; } })(),
                path: req.path, headers, body: body ?? '',
                bodyTruncated: binfo.truncated, startedAt: Date.now(),
            });
            if (decision.action === 'drop') return { response: 'close' };
            if (decision.interceptResponse) this.responseWatch.add(req.id);

            const mod: any = {};
            if (decision.headers) mod.headers = decision.headers; else if (hChanged) mod.headers = headers;
            if (decision.method) mod.method = decision.method;
            if (decision.url) mod.url = decision.url; else if (uChanged) mod.url = url;
            if (decision.bodyEdited) mod.body = decision.body ?? ''; else if (bChanged) mod.body = body;
            return Object.keys(mod).length ? mod : undefined;
        }

        // 3. No intercept — just apply the rewrite.
        const mod: any = {};
        if (uChanged) mod.url = url;
        if (hChanged) mod.headers = headers;
        if (bChanged) mod.body = body;
        return Object.keys(mod).length ? mod : undefined;
    }

    /**
     * mockttp hook: runs after the response comes back (from Burp/internet) and
     * before it reaches the device — this is where "stop the response" happens.
     */
    private async onBeforeResponse(res: any): Promise<any> {
        const host = this.flowHosts.get(res.id) ?? '';
        this.flowHosts.delete(res.id);
        const watched = this.responseWatch.delete(res.id);
        // Per-request "intercept response" bypasses scope; global holding respects it.
        const holding = watched || (this.intercept.enabled && this.intercept.responses && this.inScope(host));
        const bodyRules = this.hasRule('response-body');
        if (!holding && !this.hasRule('response-header') && !bodyRules) return undefined;

        const binfo = (holding || bodyRules) ? await this.bodyText(res.body) : { text: undefined as any, truncated: false };

        // 1. Auto match & replace on the response.
        let headers = res.headers, body = binfo.text;
        let hChanged = false, bChanged = false;
        if (this.hasRule('response-header')) {
            const r = this.applyHeaderRules(headers, 'response-header');
            if (r.changed) { headers = r.headers; hChanged = true; }
        }
        if (bodyRules && body != null) {
            for (const r of this.rules) {
                if (r.enabled && r.part === 'response-body') {
                    const n = this.doReplace(body, r); if (n !== body) { body = n; bChanged = true; }
                }
            }
        }

        // 2. Intercept (optional).
        if (holding) {
            const decision = await this.holdFor({
                id: `${res.id}:res`, flowId: res.id, kind: 'response',
                statusCode: res.statusCode, statusMessage: res.statusMessage,
                headers, body: body ?? '', bodyTruncated: binfo.truncated, startedAt: Date.now(),
            });
            if (decision.action === 'drop') return 'close';

            const mod: any = {};
            if (decision.statusCode) mod.statusCode = Number(decision.statusCode);
            if (decision.statusMessage) mod.statusMessage = decision.statusMessage;
            if (decision.headers) mod.headers = decision.headers; else if (hChanged) mod.headers = headers;
            if (decision.bodyEdited) mod.body = decision.body ?? ''; else if (bChanged) mod.body = body;
            return Object.keys(mod).length ? mod : undefined;
        }

        // 3. No intercept — apply rewrite only.
        const mod: any = {};
        if (hChanged) mod.headers = headers;
        if (bChanged) mod.body = body;
        return Object.keys(mod).length ? mod : undefined;
    }

    /** Decode a WebSocket frame payload to capped text for the UI. */
    private capWsContent(content: Uint8Array): { text: string; size: number; truncated: boolean } {
        const size = content.byteLength;
        const slice = size > MAX_WS_MSG ? content.subarray(0, MAX_WS_MSG) : content;
        return { text: Buffer.from(slice).toString('utf8'), size, truncated: size > MAX_WS_MSG };
    }

    /** Decode a body buffer to capped text for the UI / exports. */
    private capBody(buffer?: Buffer): string | undefined {
        if (!buffer || !buffer.length) return undefined;
        const slice = buffer.length > MAX_INTERCEPT_BODY ? buffer.subarray(0, MAX_INTERCEPT_BODY) : buffer;
        return slice.toString('utf8');
    }

    /** Subscribe to mockttp traffic events and re-emit simplified flows. */
    private wireEvents(server: mockttp.Mockttp): void {
        server.on('request', (req) => {
            const flow: Flow = {
                id: req.id,
                method: req.method,
                protocol: req.protocol,
                host: req.headers['host'] as string ?? new URL(req.url).host,
                path: req.path,
                url: req.url,
                requestHeaders: req.headers,
                requestBodySize: req.body?.buffer?.length,
                requestBody: this.capBody(req.body?.buffer),
                startedAt: Date.now(),
            };
            this.emit('flow', flow);
        });

        server.on('response', (res) => {
            this.emit('flow-update', {
                id: res.id,
                statusCode: res.statusCode,
                statusMessage: res.statusMessage,
                responseHeaders: res.headers,
                responseBodySize: res.body?.buffer?.length,
                responseBody: this.capBody(res.body?.buffer),
                completedAt: Date.now(),
            });
        });

        server.on('abort', (req) => {
            this.flowHosts.delete(req.id);
            this.emit('flow-update', { id: req.id, error: 'aborted', completedAt: Date.now() });
        });

        // ---- WebSocket history: upgrade, accept, every frame, and close. ----
        server.on('websocket-request', (req) => {
            let host = req.headers['host'] as string | undefined;
            let path = (req as any).path as string | undefined;
            if (!host || !path) {
                try { const u = new URL(req.url); host = host ?? u.host; path = path ?? (u.pathname + u.search); }
                catch { /* keep what we have */ }
            }
            const secure = req.url.startsWith('wss:');
            const flow: Flow = {
                id: req.id,
                method: secure ? 'WSS' : 'WS',
                protocol: secure ? 'wss' : 'ws',
                host: host ?? '',
                path: path ?? '',
                url: req.url,
                requestHeaders: req.headers,
                startedAt: Date.now(),
                ws: true,
                wsState: 'connecting',
            };
            this.emit('flow', flow);
        });

        server.on('websocket-accepted', (res) => {
            this.emit('flow-update', {
                id: res.id,
                statusCode: res.statusCode,
                statusMessage: res.statusMessage,
                responseHeaders: res.headers,
                ws: true,
                wsState: 'open',
            });
        });

        // mockttp direction: 'received' = received from the client (app → server),
        // 'sent' = sent by mockttp to the client (server → app).
        server.on('websocket-message-received', (msg) => {
            const c = this.capWsContent(msg.content);
            this.emit('ws-message', {
                id: msg.streamId, dir: 'outgoing',
                text: c.text, isBinary: msg.isBinary, size: c.size, truncated: c.truncated,
                at: Date.now(),
            } as WsMessage);
        });
        server.on('websocket-message-sent', (msg) => {
            const c = this.capWsContent(msg.content);
            this.emit('ws-message', {
                id: msg.streamId, dir: 'incoming',
                text: c.text, isBinary: msg.isBinary, size: c.size, truncated: c.truncated,
                at: Date.now(),
            } as WsMessage);
        });

        server.on('websocket-close', (close) => {
            this.flowHosts.delete(close.streamId);
            this.emit('flow-update', {
                id: close.streamId, ws: true, wsState: 'closed',
                wsCloseCode: close.closeCode, completedAt: Date.now(),
            });
        });
    }
}
