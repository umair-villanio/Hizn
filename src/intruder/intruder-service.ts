/**
 * IntruderService — automated request fuzzing, like Burp's Intruder.
 *
 * You give it a request template with payload positions marked by § markers
 * (e.g.  GET /user?id=§1§  →  the "1" is a position) and a list of payloads.
 * It fires one request per payload combination, sends them through the shared
 * RepeaterService (direct to target, nothing auto-followed) and streams a
 * result row per request: payload, status, response length and timing.
 *
 * Attack types:
 *   - sniper        one payload set, one position at a time
 *                   (positions × payloads requests)
 *   - batteringram  the same payload placed in every position at once
 *                   (payloads requests)
 *
 * A single attack runs at a time; stop() cancels the one in flight.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { EventEmitter } from 'events';
import { RepeaterService } from '../repeater/repeater-service';

export interface IntruderTemplate {
    method?: string;
    /** May contain §…§ payload positions. */
    url: string;
    /** Header values may contain §…§ payload positions. */
    headers?: Record<string, string | string[] | undefined>;
    /** May contain §…§ payload positions. */
    body?: string;
    insecure?: boolean;
}

export interface IntruderConfig {
    template: IntruderTemplate;
    attackType: 'sniper' | 'batteringram';
    payloads: string[];
    /** URL-encode each payload before placing it. */
    urlEncode?: boolean;
}

export interface IntruderRow {
    index: number;
    /** 0-based position the payload was placed in (sniper only). */
    position?: number;
    payload: string;
    statusCode?: number;
    statusMessage?: string;
    /** Response body length in bytes. */
    length?: number;
    durationMs?: number;
    error?: string;
}

export interface IntruderSummary {
    total: number;
    completed: number;
    cancelled: boolean;
    error?: string;
}

/** Hard ceiling so a fat payload list can't spawn an unbounded attack. */
const MAX_REQUESTS = 5000;

const MARKER = /§([\s\S]*?)§/g;

export class IntruderService extends EventEmitter {
    private repeater = new RepeaterService();
    private running = false;
    private cancel = false;

    isRunning(): boolean {
        return this.running;
    }

    /** Cancel the attack currently in flight (if any). */
    stop(): void {
        if (this.running) this.cancel = true;
    }

    /** Count §…§ payload positions across the url, header values and body. */
    countPositions(t: IntruderTemplate): number {
        let n = 0;
        const scan = (s?: string) => { if (s) n += (s.match(MARKER) || []).length; };
        scan(t.url);
        for (const v of Object.values(t.headers ?? {})) {
            (Array.isArray(v) ? v : [v]).forEach((x) => scan(x as string | undefined));
        }
        scan(t.body);
        return n;
    }

    /**
     * Build a concrete request from the template. `pick(index, inner)` decides
     * each position: return a replacement string, or null to keep the marked
     * text (markers stripped) unchanged.
     */
    private build(
        t: IntruderTemplate,
        pick: (index: number, inner: string) => string | null,
    ) {
        let idx = 0;
        const fill = (s?: string): string | undefined => {
            if (s == null) return s;
            return s.replace(MARKER, (_m, inner: string) => {
                const r = pick(idx, inner);
                idx++;
                return r == null ? inner : r;
            });
        };
        const headers: Record<string, string | string[] | undefined> = {};
        for (const [k, v] of Object.entries(t.headers ?? {})) {
            headers[k] = Array.isArray(v) ? v.map((x) => fill(x as string) as string) : fill(v as string);
        }
        return {
            method: t.method,
            url: fill(t.url) as string,
            headers,
            body: fill(t.body),
            insecure: t.insecure,
        };
    }

    /**
     * Run the attack. Emits 'start' {total}, a 'row' per response and 'done'
     * with the summary. Resolves once finished or cancelled.
     */
    async run(cfg: IntruderConfig): Promise<IntruderSummary> {
        if (this.running) throw new Error('An attack is already running');

        const payloads = (cfg.payloads ?? []).filter((p) => p != null);
        const positions = this.countPositions(cfg.template);
        if (positions === 0) {
            throw new Error('No payload positions — wrap a value in § markers, e.g. §FUZZ§');
        }
        if (payloads.length === 0) throw new Error('No payloads provided');

        const enc = (p: string) => (cfg.urlEncode ? encodeURIComponent(p) : p);

        // Expand the attack into a flat job list.
        type Job = { position?: number; payload: string; pick: (i: number) => string | null };
        const jobs: Job[] = [];
        if (cfg.attackType === 'batteringram') {
            for (const p of payloads) jobs.push({ payload: p, pick: () => enc(p) });
        } else {
            // sniper: each position gets every payload in turn; others untouched.
            for (let pos = 0; pos < positions; pos++) {
                for (const p of payloads) {
                    jobs.push({ position: pos, payload: p, pick: (i) => (i === pos ? enc(p) : null) });
                }
            }
        }

        const total = Math.min(jobs.length, MAX_REQUESTS);
        this.running = true;
        this.cancel = false;
        this.emit('start', { total, attackType: cfg.attackType, positions });

        let completed = 0;
        try {
            for (let n = 0; n < total; n++) {
                if (this.cancel) break;
                const job = jobs[n];
                const resp = await this.repeater.send(this.build(cfg.template, job.pick));
                const row: IntruderRow = {
                    index: n,
                    position: job.position,
                    payload: job.payload,
                    statusCode: resp.statusCode,
                    statusMessage: resp.statusMessage,
                    length: resp.bodySize,
                    durationMs: resp.durationMs,
                    error: resp.error,
                };
                completed++;
                this.emit('row', row);
            }
        } finally {
            const summary: IntruderSummary = { total, completed, cancelled: this.cancel };
            this.running = false;
            this.cancel = false;
            this.emit('done', summary);
        }
        return { total, completed, cancelled: false };
    }
}
