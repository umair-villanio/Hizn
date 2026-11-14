/**
 * FridaService — CA injection + certificate-unpinning via Frida.
 *
 * This is the robust path to decrypting app TLS on modern Android, where
 * user-installed CAs are ignored and many apps pin certificates. We build a
 * config prelude (our CA + proxy address) and concatenate it with the
 * httptoolkit frida-interception-and-unpinning scripts (AGPL-3.0), then inject
 * the whole bundle into the target app via frida-js.
 *
 * Reused scripts: https://github.com/httptoolkit/frida-interception-and-unpinning
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as FridaJs from 'frida-js';
import { AdbService } from '../devices/adb-service';

/** Where the adapted frida scripts live inside this project. */
const SCRIPT_DIR = path.resolve(__dirname, '../../scripts/frida');

/** frida-server's default listen port on the device. */
const FRIDA_DEFAULT_PORT = 27042;

/** Order matters — config first, then hooks, matching upstream's loader. */
const SCRIPT_FILES = [
    'native-connect-hook.js',
    'native-tls-hook.js',
    'android/android-proxy-override.js',
    'android/android-system-certificate-injection.js',
    'android/android-certificate-unpinning.js',
    'android/android-certificate-unpinning-fallback.js',
];

export interface FridaInjectOptions {
    serial: string;
    caPem: string;
    proxyHost: string;
    proxyPort: number;
    /** App to spawn/attach to, e.g. "com.android.chrome". */
    target: string;
    /** Spawn the app fresh (true) or attach to a running one (false). */
    spawn?: boolean;
    debug?: boolean;
    /** frida-server port on the device (default 27042). */
    fridaPort?: number;
}

export class FridaService {
    /**
     * Live Frida sessions keyed `serial:pid`. Sessions must stay alive —
     * disconnecting the FridaSession unloads every injected script.
     */
    private sessions = new Map<string, FridaJs.FridaSession>();

    constructor(private adb: AdbService) {}

    /** Build the config.js prelude with the live CA + proxy values injected. */
    private buildConfig(opts: FridaInjectOptions): string {
        const pem = opts.caPem.trim();
        return `
/* droidmitm runtime config — generated */
const CERT_PEM = \`${pem}\`;
const PROXY_HOST = ${JSON.stringify(opts.proxyHost)};
const PROXY_PORT = ${opts.proxyPort};
const DEBUG_MODE = ${opts.debug ? 'true' : 'false'};
const IGNORED_NON_HTTP_PORTS = [];
const BLOCK_HTTP3 = true;
const PROXY_SUPPORTS_SOCKS5 = false;
`;
    }

    /** Concatenate config + all hook scripts into one injectable payload. */
    private async buildPayload(opts: FridaInjectOptions): Promise<string> {
        const parts: string[] = [this.buildConfig(opts)];
        for (const file of SCRIPT_FILES) {
            const full = path.join(SCRIPT_DIR, file);
            try {
                parts.push(await fs.readFile(full, 'utf8'));
            } catch {
                // Script not present yet — skip so partial setups still run.
            }
        }
        return parts.join('\n\n');
    }

    /**
     * Inject into the target app. Requires frida-server running on the device
     * (rooted) OR a gadget-embedded build. Returns the target pid.
     */
    async inject(opts: FridaInjectOptions): Promise<{ pid: number }> {
        const payload = await this.buildPayload(opts);

        // frida-js speaks the frida-core DBus protocol over any Duplex —
        // here an ADB tunnel to the on-device frida-server.
        const stream = await this.adb.openTcp(opts.serial, opts.fridaPort ?? FRIDA_DEFAULT_PORT);
        const frida = await FridaJs.connect({ stream });

        let pid: number;
        if (opts.spawn !== false) {
            // Spawn paused → load script → resume, so hooks land before
            // the app's TLS/pinning code runs.
            const spawned = await frida.spawnPaused(opts.target, undefined);
            pid = spawned.pid;
            await (await spawned.session.createScript(payload)).loadScript();
            await spawned.session.resume();
        } else {
            const processes = await frida.enumerateProcesses();
            const proc = processes.find(
                (p) => p.name === opts.target || String(p.pid) === opts.target
            );
            if (!proc || proc.pid == null) {
                await frida.disconnect().catch(() => {});
                throw new Error(`Process not found: ${opts.target}`);
            }
            pid = proc.pid;
            const { session } = await frida.attachToProcess(pid);
            await (await session.createScript(payload)).loadScript();
        }

        this.sessions.set(`${opts.serial}:${pid}`, frida);
        return { pid };
    }

    /** Drop a session (unloads injected scripts in that process). */
    async detach(serial: string, pid: number): Promise<void> {
        const frida = this.sessions.get(`${serial}:${pid}`);
        this.sessions.delete(`${serial}:${pid}`);
        await frida?.disconnect();
    }
}
