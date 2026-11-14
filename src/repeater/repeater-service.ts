/**
 * RepeaterService — re-send an arbitrary HTTP(S) request and return the raw
 * response, like Burp's Repeater. The request is sent directly to the target
 * (optionally via the hizn proxy / Burp upstream), nothing is auto-
 * followed, and headers/body are sent as given so you can tamper freely.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';

export interface RepeaterRequest {
    method?: string;
    url: string;
    headers?: Record<string, string | string[] | undefined>;
    body?: string;
    /** Route through a proxy, e.g. the hizn listener or Burp. */
    proxy?: { host: string; port: number };
    /** Skip TLS verification (handy for self-signed test servers). */
    insecure?: boolean;
    timeoutMs?: number;
}

export interface RepeaterResponse {
    statusCode?: number;
    statusMessage?: string;
    headers?: Record<string, string | string[] | undefined>;
    body?: string;
    bodySize?: number;
    durationMs?: number;
    error?: string;
}

export class RepeaterService {
    async send(reqSpec: RepeaterRequest): Promise<RepeaterResponse> {
        let target: URL;
        try {
            target = new URL(reqSpec.url);
        } catch {
            return { error: 'Invalid URL: ' + reqSpec.url };
        }
        const isHttps = target.protocol === 'https:';
        const lib = isHttps ? https : http;

        // Normalise headers; drop hop-by-hop ones we must recompute.
        const headers: Record<string, string | string[]> = {};
        for (const [k, v] of Object.entries(reqSpec.headers ?? {})) {
            if (v === undefined) continue;
            if (/^(content-length|connection)$/i.test(k)) continue;
            headers[k] = v as string | string[];
        }
        const body = reqSpec.body != null && reqSpec.body !== '' ? Buffer.from(reqSpec.body) : undefined;
        if (body) headers['content-length'] = String(body.length);
        if (!Object.keys(headers).some((h) => h.toLowerCase() === 'host')) {
            headers['host'] = target.host;
        }

        const options: http.RequestOptions = {
            method: (reqSpec.method ?? 'GET').toUpperCase(),
            headers,
            timeout: reqSpec.timeoutMs ?? 20000,
        };

        if (reqSpec.proxy && !isHttps) {
            // Plain HTTP through a proxy: connect to proxy, use absolute URL.
            options.host = reqSpec.proxy.host;
            options.port = reqSpec.proxy.port;
            options.path = reqSpec.url;
        } else {
            options.host = target.hostname;
            options.port = target.port || (isHttps ? 443 : 80);
            options.path = target.pathname + target.search;
            if (isHttps) (options as https.RequestOptions).rejectUnauthorized = !reqSpec.insecure;
        }

        const started = Date.now();
        return new Promise<RepeaterResponse>((resolve) => {
            const r = lib.request(options, (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c) => chunks.push(Buffer.from(c)));
                res.on('end', () => {
                    const buf = Buffer.concat(chunks);
                    resolve({
                        statusCode: res.statusCode,
                        statusMessage: res.statusMessage,
                        headers: res.headers,
                        body: buf.toString('utf8'),
                        bodySize: buf.length,
                        durationMs: Date.now() - started,
                    });
                });
            });
            r.on('error', (e) => resolve({ error: e.message, durationMs: Date.now() - started }));
            r.on('timeout', () => { r.destroy(); resolve({ error: 'Request timed out', durationMs: Date.now() - started }); });
            if (body) r.write(body);
            r.end();
        });
    }
}
