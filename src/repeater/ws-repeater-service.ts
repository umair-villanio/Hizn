/**
 * WsRepeaterService — Burp-style WebSocket repeater.
 *
 * Opens a live WebSocket connection straight to a target (ws:// or wss://),
 * lets the user fire arbitrary frames at it, and streams every frame — sent
 * and received — back to the UI. Each repeater session is independent of the
 * interception proxy, exactly like Burp's WebSocket repeater: you craft and
 * replay frames by hand against the server.
 *
 * Events (all carry the session `id`):
 *   'open'    { id, url }
 *   'message' { id, dir:'outgoing'|'incoming', text, isBinary, size, at }
 *   'close'   { id, code, reason, at }
 *   'error'   { id, message, at }
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';
import WebSocket from 'ws';

export interface WsOpenOptions {
    url: string;
    headers?: Record<string, string | string[] | undefined>;
    /** Skip TLS verification (handy for self-signed test servers). */
    insecure?: boolean;
    handshakeTimeoutMs?: number;
}

export interface WsFrameEvent {
    id: string;
    dir: 'outgoing' | 'incoming';
    text: string;
    isBinary: boolean;
    size: number;
    at: number;
}

/** Cap each frame relayed to the UI. */
const MAX_WS_FRAME = 256 * 1024;
/** Guard against runaway session count. */
const MAX_SESSIONS = 32;

export class WsRepeaterService extends EventEmitter {
    private sessions = new Map<string, WebSocket>();

    /** Open a new WebSocket session; returns its id once the socket is created. */
    open(opts: WsOpenOptions): { id: string } {
        let target: URL;
        try {
            target = new URL(opts.url);
        } catch {
            throw new Error('Invalid URL: ' + opts.url);
        }
        if (target.protocol !== 'ws:' && target.protocol !== 'wss:') {
            throw new Error('URL must start with ws:// or wss://');
        }
        if (this.sessions.size >= MAX_SESSIONS) {
            throw new Error('Too many open WebSocket sessions — close one first');
        }

        const id = randomUUID();
        const headers: Record<string, string | string[]> = {};
        for (const [k, v] of Object.entries(opts.headers ?? {})) {
            if (v === undefined) continue;
            // ws sets these itself; a user-supplied copy breaks the handshake.
            if (/^(connection|upgrade|sec-websocket-key|sec-websocket-version|host)$/i.test(k)) continue;
            headers[k] = v as string | string[];
        }

        const ws = new WebSocket(opts.url, {
            headers,
            rejectUnauthorized: !opts.insecure,
            handshakeTimeout: opts.handshakeTimeoutMs ?? 20000,
        });
        this.sessions.set(id, ws);

        ws.on('open', () => this.emit('open', { id, url: opts.url }));

        ws.on('message', (data: WebSocket.RawData, isBinary: boolean) => {
            const buf = Buffer.isBuffer(data)
                ? data
                : Array.isArray(data)
                    ? Buffer.concat(data)
                    : Buffer.from(data as ArrayBuffer);
            const size = buf.length;
            const slice = size > MAX_WS_FRAME ? buf.subarray(0, MAX_WS_FRAME) : buf;
            this.emit('message', {
                id, dir: 'incoming',
                text: isBinary ? slice.toString('base64') : slice.toString('utf8'),
                isBinary, size, at: Date.now(),
            } as WsFrameEvent);
        });

        ws.on('close', (code: number, reason: Buffer) => {
            this.sessions.delete(id);
            this.emit('close', { id, code, reason: reason?.toString('utf8') || '', at: Date.now() });
        });

        ws.on('error', (err: Error) => {
            this.emit('error', { id, message: err.message, at: Date.now() });
        });

        return { id };
    }

    /** Send a frame on an open session. `isBinary` treats `data` as base64. */
    send(id: string, data: string, isBinary = false): void {
        const ws = this.sessions.get(id);
        if (!ws) throw new Error('No such WebSocket session: ' + id);
        if (ws.readyState !== WebSocket.OPEN) throw new Error('WebSocket is not open');
        const payload: Buffer | string = isBinary ? Buffer.from(data, 'base64') : data;
        ws.send(payload, { binary: isBinary }, (err) => {
            if (err) { this.emit('error', { id, message: err.message, at: Date.now() }); return; }
            const size = Buffer.byteLength(isBinary ? (payload as Buffer) : (payload as string));
            this.emit('message', {
                id, dir: 'outgoing', text: data, isBinary, size, at: Date.now(),
            } as WsFrameEvent);
        });
    }

    /** Close a session (default code 1000 — normal closure). */
    close(id: string, code = 1000, reason = ''): void {
        const ws = this.sessions.get(id);
        if (!ws) return;
        try { ws.close(code, reason); } catch { /* already gone */ }
    }

    /** Close every session (e.g. on shutdown). */
    closeAll(): void {
        for (const id of [...this.sessions.keys()]) this.close(id);
    }
}
