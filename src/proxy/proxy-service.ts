/**
 * ProxyService — the interception engine.
 *
 * Wraps mockttp (the open-source MITM library that also powers HTTP Toolkit).
 * Responsibilities:
 *   - Generate / hold a root CA used to decrypt TLS.
 *   - Run a local HTTP(S) proxy that intercepts and records traffic.
 *   - Optionally chain upstream to another proxy (e.g. Burp Suite) so flows
 *     go:  device -> droidmitm -> Burp -> internet.
 *   - Emit a simplified "flow" event stream for the UI.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { EventEmitter } from 'events';
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
    startedAt: number;
    completedAt?: number;
    error?: string;
}

export interface ProxyStatus {
    running: boolean;
    port: number;
    upstream: UpstreamConfig;
    caFingerprint?: string;
}

const DEFAULT_PROXY_PORT = 8000;

export class ProxyService extends EventEmitter {
    private server?: mockttp.Mockttp;
    private ca?: CA;
    private port = DEFAULT_PROXY_PORT;
    private upstream: UpstreamConfig = {
        enabled: false,
        host: '127.0.0.1',
        port: 8080, // Burp's default listener
    };

    /** Generate (once) and return the root CA in PEM form. */
    async getCA(): Promise<CA> {
        if (!this.ca) {
            const generated = await mockttp.generateCACertificate({
                subject: {
                    commonName: 'droidmitm CA - interception only',
                    organizationName: 'droidmitm',
                    countryName: 'XX',
                },
                bits: 2048,
            });
            this.ca = { key: generated.key, cert: generated.cert };
        }
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
            caFingerprint: this.ca ? await this.caFingerprint() : undefined,
        };
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

        const passThroughOptions: any = {};
        if (this.upstream.enabled) {
            passThroughOptions.proxyConfig = {
                proxyUrl: `http://${this.upstream.host}:${this.upstream.port}`,
            };
        }

        await this.server.forAnyRequest().thenPassThrough(passThroughOptions);
        await this.server
            .forAnyWebSocket()
            .thenPassThrough(passThroughOptions);
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
                completedAt: Date.now(),
            });
        });

        server.on('abort', (req) => {
            this.emit('flow-update', { id: req.id, error: 'aborted', completedAt: Date.now() });
        });
    }
}
