/**
 * API server — REST + WebSocket bridge between the backend services and the UI.
 *
 * REST endpoints drive setup/teardown; the WebSocket streams live flows and
 * setup-step progress to the UI.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import express from 'express';
import * as http from 'http';
import * as path from 'path';
import { WebSocketServer, WebSocket } from 'ws';
import { ProxyService } from '../proxy/proxy-service';
import { AdbService } from '../devices/adb-service';
import { FridaService } from '../frida/frida-service';
import { DesktopService } from '../desktop/desktop-service';
import { RepeaterService } from '../repeater/repeater-service';
import { IntruderService } from '../intruder/intruder-service';
import { AnalyzerService } from '../analyzer/analyzer-service';
import { PluginService } from '../plugins/plugin-service';
import { Orchestrator, SetupStep } from '../orchestrator';

export interface ApiServerOptions {
    port: number;
    uiDir: string;
}

export class ApiServer {
    private app = express();
    private server = http.createServer(this.app);
    private wss = new WebSocketServer({ server: this.server, path: '/ws' });
    private clients = new Set<WebSocket>();

    private proxy = new ProxyService();
    private adb = new AdbService();
    private frida = new FridaService(this.adb);
    private desktop = new DesktopService();
    private repeater = new RepeaterService();
    private intruder = new IntruderService();
    private analyzer = new AnalyzerService();
    private plugins = new PluginService();
    /** Serials hizn has actively routed (one-click connected). */
    private connected = new Set<string>();
    /** Server-side flow log so history survives UI reconnects. */
    private flows = new Map<string, any>();
    private static readonly MAX_FLOWS = 5000;
    private orchestrator = new Orchestrator(
        this.proxy,
        this.adb,
        this.frida,
        (step) => this.broadcast({ type: 'setup-step', step }),
    );

    constructor(private opts: ApiServerOptions) {
        this.app.use(express.json());
        this.wireProxyEvents();
        this.wireIntruderEvents();
        this.wireWebsocket();
        this.routes();
        this.app.use(express.static(opts.uiDir));
    }

    private broadcast(msg: unknown): void {
        const data = JSON.stringify(msg);
        for (const ws of this.clients) {
            if (ws.readyState === WebSocket.OPEN) ws.send(data);
        }
    }

    private markConnected(serial?: string): void {
        if (!serial) return;
        this.connected.add(serial);
        this.broadcast({ type: 'connections', connected: [...this.connected] });
    }

    private markDisconnected(serial?: string): void {
        if (!serial) return;
        this.connected.delete(serial);
        this.broadcast({ type: 'connections', connected: [...this.connected] });
    }

    private wireProxyEvents(): void {
        this.proxy.on('flow', (flow) => {
            this.flows.set(flow.id, flow);
            // Cap the store: drop the oldest when over the limit.
            if (this.flows.size > ApiServer.MAX_FLOWS) {
                const oldest = this.flows.keys().next().value;
                if (oldest !== undefined) this.flows.delete(oldest);
            }
            this.broadcast({ type: 'flow', flow });
        });
        this.proxy.on('flow-update', (update) => {
            const existing = this.flows.get(update.id);
            if (existing) Object.assign(existing, update);
            this.broadcast({ type: 'flow-update', update });
        });
        this.proxy.on('status', (status) => this.broadcast({ type: 'proxy-status', status }));
        this.proxy.on('upstream-changed', (upstream) => this.broadcast({ type: 'upstream', upstream }));
        // Burp-style interception.
        this.proxy.on('intercept', (item) => this.broadcast({ type: 'intercept', item }));
        this.proxy.on('intercept-closed', (ref) => this.broadcast({ type: 'intercept-closed', ref }));
        this.proxy.on('intercept-config', (config) => this.broadcast({ type: 'intercept-config', config }));
        this.proxy.on('scope-changed', (scope) => this.broadcast({ type: 'scope', scope }));
    }

    private wireIntruderEvents(): void {
        this.intruder.on('start', (info) => this.broadcast({ type: 'intruder-start', info }));
        this.intruder.on('row', (row) => this.broadcast({ type: 'intruder-row', row }));
        this.intruder.on('done', (summary) => this.broadcast({ type: 'intruder-done', summary }));
    }

    private wireWebsocket(): void {
        this.wss.on('connection', (ws) => {
            this.clients.add(ws);
            ws.on('close', () => this.clients.delete(ws));
            // Send a hello snapshot on connect: status + any held items.
            this.proxy.getStatus().then((status) =>
                ws.send(JSON.stringify({ type: 'proxy-status', status })),
            );
            ws.send(JSON.stringify({ type: 'intercept-config', config: this.proxy.getInterceptConfig() }));
            ws.send(JSON.stringify({ type: 'connections', connected: [...this.connected] }));
            ws.send(JSON.stringify({ type: 'scope', scope: this.proxy.getScope() }));
            ws.send(JSON.stringify({ type: 'flow-snapshot', flows: [...this.flows.values()] }));
            for (const item of this.proxy.listPending()) {
                ws.send(JSON.stringify({ type: 'intercept', item }));
            }
        });
    }

    private routes(): void {
        const api = express.Router();

        api.get('/devices', async (_req, res) => {
            res.json(await this.adb.listDevices());
        });

        api.get('/status', async (_req, res) => {
            res.json(await this.proxy.getStatus());
        });

        api.get('/ca', async (_req, res) => {
            const ca = await this.proxy.getCA();
            res.type('application/x-pem-file').send(ca.cert);
        });

        api.post('/proxy/start', async (req, res) => {
            const port = Number(req.body?.port) || this.proxy.getPort();
            try {
                res.json(await this.proxy.start(port));
            } catch (e: any) {
                res.status(500).json({ error: e.message });
            }
        });

        api.post('/proxy/stop', async (_req, res) => {
            await this.proxy.stop();
            res.json({ ok: true });
        });

        api.post('/upstream', async (req, res) => {
            await this.proxy.setUpstream({
                enabled: !!req.body?.enabled,
                host: req.body?.host,
                port: req.body?.port ? Number(req.body.port) : undefined,
            });
            res.json(this.proxy.getUpstream());
        });

        // ---- Burp-style interception ----
        api.get('/intercept', (_req, res) => {
            res.json({ config: this.proxy.getInterceptConfig(), pending: this.proxy.listPending() });
        });

        api.post('/intercept/config', (req, res) => {
            const cfg = this.proxy.setInterceptConfig({
                enabled: req.body?.enabled,
                requests: req.body?.requests,
                responses: req.body?.responses,
            });
            res.json(cfg);
        });

        // Forward (optionally modified) or drop a held request/response.
        api.post('/intercept/resolve', (req, res) => {
            const id = req.body?.id;
            if (!id) return res.status(400).json({ error: 'Missing id' });
            const ok = this.proxy.resolveIntercept(id, {
                action: req.body?.action === 'drop' ? 'drop' : 'forward',
                headers: req.body?.headers,
                body: req.body?.body,
                bodyEdited: !!req.body?.bodyEdited,
                method: req.body?.method,
                url: req.body?.url,
                statusCode: req.body?.statusCode,
                statusMessage: req.body?.statusMessage,
                interceptResponse: !!req.body?.interceptResponse,
            });
            if (!ok) return res.status(404).json({ error: 'No such held item (already resolved?)' });
            res.json({ ok: true });
        });

        // Connected-device tracking.
        api.get('/connections', (_req, res) => res.json({ connected: [...this.connected] }));

        // The one-click button.
        api.post('/connect', async (req, res) => {
            try {
                const result = await this.orchestrator.runOneClick({
                    serial: req.body?.serial,
                    fridaTarget: req.body?.fridaTarget || undefined,
                    hostIp: req.body?.hostIp || undefined,
                });
                this.markConnected(result.device.serial);
                res.json(result);
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });

        api.post('/disconnect', async (req, res) => {
            await this.orchestrator.disconnect(req.body?.serial);
            this.markDisconnected(req.body?.serial);
            res.json({ ok: true });
        });

        // One-click: find the Genymotion VM and capture ALL its traffic
        // (system-wide proxy + system-store CA, no per-app Frida).
        api.post('/connect/genymotion', async (req, res) => {
            try {
                // Optionally attach a VM by IP first (e.g. "192.168.56.101:5555").
                if (req.body?.ip) {
                    try { await this.adb.connectTcp(req.body.ip); } catch { /* may already be attached */ }
                }
                const device = await this.adb.findGenymotion();
                if (!device) {
                    return res.status(404).json({
                        error: 'No Genymotion/emulator detected. Start the VM and make sure its ADB is enabled.',
                    });
                }
                const result = await this.orchestrator.runOneClick({
                    serial: device.serial,
                    emulator: true,
                    hostIp: req.body?.hostIp || undefined,
                    // No fridaTarget → system-wide capture of all apps.
                });
                this.markConnected(result.device.serial);
                res.json(result);
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });

        // Download + push + start frida-server for a device (rooted).
        api.post('/frida/provision', async (req, res) => {
            try {
                const serial = req.body?.serial;
                const devices = await this.adb.listDevices();
                const device = devices.find((d) => d.serial === serial);
                if (!device) return res.status(404).json({ error: 'Device not found' });
                if (!device.abi) return res.status(400).json({ error: 'Unknown device ABI' });
                const result = await this.frida.provisionServer(
                    serial,
                    device.abi,
                    req.body?.version || 'latest',
                );
                res.json(result);
            } catch (e: any) {
                res.status(500).json({ error: e.message });
            }
        });

        // ---- Desktop browser capture (Firefox) ----
        api.get('/desktop/info', async (_req, res) => {
            const info = this.desktop.info(this.proxy.getPort());
            res.json({
                ...info,
                firefoxFound: !!info.firefoxPath,
                caImported: await this.desktop.caImported(),
                certutilFound: !!(await this.desktop.findNssCertutil()),
            });
        });

        // Auto-import the CA into the Firefox profile (scoped; needs NSS certutil).
        api.post('/desktop/import-ca', async (_req, res) => {
            try {
                const ca = await this.proxy.getCA();
                const result = await this.desktop.autoImportCA(ca.cert);
                res.json(result);
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });

        // Launch a Firefox instance wired to hizn (starts the proxy first).
        api.post('/desktop/firefox', async (_req, res) => {
            try {
                if (!this.proxy.isRunning()) await this.proxy.start(this.proxy.getPort());
                const ca = await this.proxy.getCA();
                const result = await this.desktop.launchFirefox(this.proxy.getPort(), ca.cert);
                res.json(result);
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });

        // ---- Match & Replace rules ----
        api.get('/rules', (_req, res) => res.json(this.proxy.getRules()));
        api.post('/rules', (req, res) => {
            const rules = this.proxy.setRules(Array.isArray(req.body?.rules) ? req.body.rules : []);
            res.json(rules);
        });

        // ---- Flow log (server-side history) ----
        api.get('/flows', (_req, res) => res.json([...this.flows.values()]));
        api.post('/flows/clear', (_req, res) => {
            this.flows.clear();
            this.broadcast({ type: 'flows-cleared' });
            res.json({ ok: true });
        });
        // Load a saved session: replace the store and push it to all clients.
        api.post('/flows/import', (req, res) => {
            const incoming = Array.isArray(req.body?.flows) ? req.body.flows : [];
            this.flows.clear();
            for (const f of incoming) if (f && f.id) this.flows.set(f.id, f);
            this.broadcast({ type: 'flow-snapshot', flows: [...this.flows.values()] });
            res.json({ ok: true, count: this.flows.size });
        });

        // ---- Target scope ----
        api.get('/scope', (_req, res) => res.json(this.proxy.getScope()));
        api.post('/scope', (req, res) => {
            res.json(this.proxy.setScope({ enabled: req.body?.enabled, hosts: req.body?.hosts }));
        });

        // ---- Intruder (automated request fuzzing) ----
        const normPayloads = (p: unknown): string[] => {
            if (Array.isArray(p)) return p.map((x) => String(x));
            if (typeof p === 'string') return p.split('\n').map((x) => x.replace(/\r$/, ''));
            return [];
        };
        api.post('/intruder/start', (req, res) => {
            if (this.intruder.isRunning()) {
                return res.status(409).json({ error: 'An attack is already running' });
            }
            const template = {
                method: req.body?.method,
                url: String(req.body?.url ?? ''),
                headers: req.body?.headers,
                body: req.body?.body,
                insecure: !!req.body?.insecure,
            };
            // Keep empty strings: Null payloads intentionally send the request
            // unchanged. The client builds the final list, so we only reject an
            // empty array, not empty entries.
            const payloads = normPayloads(req.body?.payloads);
            const attackType = req.body?.attackType === 'batteringram' ? 'batteringram' : 'sniper';
            const positions = this.intruder.countPositions(template);
            if (!template.url) return res.status(400).json({ error: 'A URL is required' });
            if (positions === 0) {
                return res.status(400).json({ error: 'No payload positions — wrap a value in § markers, e.g. §FUZZ§' });
            }
            if (payloads.length === 0) return res.status(400).json({ error: 'No payloads provided' });
            // Fire-and-forget: progress + results stream over the WebSocket.
            this.intruder
                .run({ template, attackType, payloads, urlEncode: !!req.body?.urlEncode })
                .catch((e: any) => this.broadcast({ type: 'intruder-done', summary: { total: 0, completed: 0, cancelled: false, error: e.message } }));
            res.json({ ok: true, positions, attackType });
        });
        api.post('/intruder/stop', (_req, res) => {
            this.intruder.stop();
            res.json({ ok: true });
        });

        // ---- Repeater (re-send an edited request) ----
        api.post('/repeater/send', async (req, res) => {
            try {
                const result = await this.repeater.send({
                    method: req.body?.method,
                    url: req.body?.url,
                    headers: req.body?.headers,
                    body: req.body?.body,
                    insecure: !!req.body?.insecure,
                });
                res.json(result);
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });

        // ---- Static APK analyzer (upload the .apk as the raw body) ----
        api.post('/analyzer/scan', express.raw({ type: () => true, limit: '600mb' }), async (req, res) => {
            try {
                const buf = req.body;
                if (!Buffer.isBuffer(buf) || buf.length === 0) {
                    return res.status(400).json({ error: 'Empty upload — POST the .apk as the raw request body.' });
                }
                const name = typeof req.query.name === 'string' ? req.query.name : undefined;
                res.json(await this.analyzer.analyze(buf, name));
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });

        // ---- Plugins (file-backed, Burp-style installable) ----
        api.get('/plugins', async (_req, res) => {
            res.json({ plugins: await this.plugins.list(), dirs: this.plugins.dirs() });
        });
        api.post('/plugins', async (req, res) => {
            try {
                const { name, desc, author, source } = req.body ?? {};
                if (!name || !source) {
                    res.status(400).json({ error: 'name and source are required' });
                    return;
                }
                res.json(await this.plugins.install({ name, desc, author, source }));
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });
        api.post('/plugins/toggle', async (req, res) => {
            await this.plugins.setEnabled(req.body?.id, !!req.body?.enabled);
            res.json({ ok: true });
        });
        api.delete('/plugins/:origin/:file', async (req, res) => {
            try {
                await this.plugins.remove(`${req.params.origin}/${req.params.file}`);
                res.json({ ok: true });
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });

        this.app.use('/api', api);
    }

    async start(): Promise<void> {
        await new Promise<void>((resolve) =>
            this.server.listen(this.opts.port, '127.0.0.1', resolve),
        );
        // eslint-disable-next-line no-console
        console.log(`hizn API + UI → http://127.0.0.1:${this.opts.port}`);
    }
}
