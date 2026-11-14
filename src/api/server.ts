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
    private orchestrator = new Orchestrator(
        this.proxy,
        this.adb,
        this.frida,
        (step) => this.broadcast({ type: 'setup-step', step }),
    );

    constructor(private opts: ApiServerOptions) {
        this.app.use(express.json());
        this.wireProxyEvents();
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

    private wireProxyEvents(): void {
        this.proxy.on('flow', (flow) => this.broadcast({ type: 'flow', flow }));
        this.proxy.on('flow-update', (update) => this.broadcast({ type: 'flow-update', update }));
        this.proxy.on('status', (status) => this.broadcast({ type: 'proxy-status', status }));
        this.proxy.on('upstream-changed', (upstream) => this.broadcast({ type: 'upstream', upstream }));
    }

    private wireWebsocket(): void {
        this.wss.on('connection', (ws) => {
            this.clients.add(ws);
            ws.on('close', () => this.clients.delete(ws));
            // Send a hello snapshot on connect.
            this.proxy.getStatus().then((status) =>
                ws.send(JSON.stringify({ type: 'proxy-status', status })),
            );
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

        // The one-click button.
        api.post('/connect', async (req, res) => {
            try {
                const result = await this.orchestrator.runOneClick({
                    serial: req.body?.serial,
                    fridaTarget: req.body?.fridaTarget || undefined,
                    hostIp: req.body?.hostIp || undefined,
                });
                res.json(result);
            } catch (e: any) {
                res.status(400).json({ error: e.message });
            }
        });

        api.post('/disconnect', async (req, res) => {
            await this.orchestrator.disconnect(req.body?.serial);
            res.json({ ok: true });
        });

        this.app.use('/api', api);
    }

    async start(): Promise<void> {
        await new Promise<void>((resolve) =>
            this.server.listen(this.opts.port, '127.0.0.1', resolve),
        );
        // eslint-disable-next-line no-console
        console.log(`droidmitm API + UI → http://127.0.0.1:${this.opts.port}`);
    }
}
