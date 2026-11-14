/**
 * Orchestrator — the "one-click" flow.
 *
 * Given a connected device, it performs the full interception setup and
 * reports each step so the UI can show progress:
 *
 *   1. Ensure the proxy is running (optionally chained to Burp).
 *   2. Work out the host IP the device should reach.
 *   3. Install / stage the CA (system store if rooted, else manual).
 *   4. Point the device at us (global proxy + adb reverse fallback).
 *   5. If Frida is available, inject CA + unpinning into a target app.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { networkInterfaces } from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { ProxyService } from './proxy/proxy-service';
import { AdbService, DeviceInfo } from './devices/adb-service';
import { FridaService } from './frida/frida-service';

const execFileAsync = promisify(execFile);

export interface SetupStep {
    key: string;
    label: string;
    status: 'pending' | 'running' | 'ok' | 'warn' | 'error';
    detail?: string;
}

export interface SetupOptions {
    serial: string;
    /** Optional app to Frida-inject into (e.g. "com.android.chrome"). */
    fridaTarget?: string;
    /** Override auto-detected host IP (useful on multi-NIC machines). */
    hostIp?: string;
}

export interface SetupResult {
    steps: SetupStep[];
    device: DeviceInfo;
    hostIp: string;
    caInstall: 'system' | 'user-manual' | 'frida';
    proxyPort: number;
}

export class Orchestrator {
    constructor(
        private proxy: ProxyService,
        private adb: AdbService,
        private frida: FridaService,
        private onStep?: (step: SetupStep) => void,
    ) {}

    /** Pick the LAN IP most likely reachable from the device. */
    detectHostIp(): string {
        const ifaces = networkInterfaces();
        const candidates: string[] = [];
        for (const name of Object.keys(ifaces)) {
            for (const net of ifaces[name] ?? []) {
                if (net.family === 'IPv4' && !net.internal) {
                    candidates.push(net.address);
                }
            }
        }
        // Prefer common private LAN ranges.
        return (
            candidates.find((ip) => ip.startsWith('192.168.')) ??
            candidates.find((ip) => ip.startsWith('10.')) ??
            candidates.find((ip) => /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) ??
            candidates[0] ??
            '127.0.0.1'
        );
    }

    /** Compute Android's subject_hash_old for the CA (needs host openssl). */
    private async androidCertHash(caPem: string): Promise<string | undefined> {
        try {
            const { stdout } = await execFileAsync(
                'openssl',
                ['x509', '-inform', 'PEM', '-subject_hash_old', '-noout'],
                { input: caPem } as any,
            );
            return stdout.toString().trim().split('\n')[0];
        } catch {
            return undefined; // openssl unavailable → skip system-store install
        }
    }

    private step(step: SetupStep): SetupStep {
        this.onStep?.(step);
        return step;
    }

    async runOneClick(opts: SetupOptions): Promise<SetupResult> {
        const steps: SetupStep[] = [];
        const push = (s: SetupStep) => { steps.push(s); this.step(s); return s; };

        // 1. Device check
        const devStep = push({ key: 'device', label: 'Detect device', status: 'running' });
        const devices = await this.adb.listDevices();
        const device = devices.find((d) => d.serial === opts.serial);
        if (!device) {
            devStep.status = 'error';
            devStep.detail = 'Device not found';
            this.step(devStep);
            throw new Error('Device not found: ' + opts.serial);
        }
        devStep.status = 'ok';
        devStep.detail = `${device.model ?? device.serial} · Android ${device.androidVersion ?? '?'} · ${device.rooted ? 'rooted' : 'non-root'}`;
        this.step(devStep);

        // 2. Proxy up
        const proxyStep = push({ key: 'proxy', label: 'Start proxy engine', status: 'running' });
        const status = await this.proxy.start(this.proxy.getPort());
        proxyStep.status = 'ok';
        proxyStep.detail = status.upstream.enabled
            ? `Listening :${status.port} → Burp ${status.upstream.host}:${status.upstream.port}`
            : `Listening :${status.port}`;
        this.step(proxyStep);

        // 3. Host IP
        const ipStep = push({ key: 'ip', label: 'Resolve host address', status: 'running' });
        const hostIp = opts.hostIp ?? this.detectHostIp();
        ipStep.status = 'ok';
        ipStep.detail = hostIp;
        this.step(ipStep);

        const ca = await this.proxy.getCA();
        let caInstall: SetupResult['caInstall'] = 'user-manual';

        // 4. CA install
        const caStep = push({ key: 'ca', label: 'Install CA certificate', status: 'running' });
        if (device.rooted) {
            const hash = await this.androidCertHash(ca.cert);
            if (hash) {
                const used = await this.adb.installCA(opts.serial, ca.cert, hash, true);
                caInstall = used;
                caStep.status = 'ok';
                caStep.detail = 'Installed into system trust store';
            } else {
                await this.adb.installCA(opts.serial, ca.cert, '0', false);
                caStep.status = 'warn';
                caStep.detail = 'openssl missing — PEM staged at /sdcard/Download/droidmitm-ca.crt';
            }
        } else {
            await this.adb.installCA(opts.serial, ca.cert, '0', false);
            caStep.status = 'warn';
            caStep.detail = 'Non-rooted — install droidmitm-ca.crt from Settings, or use Frida';
        }
        this.step(caStep);

        // 5. Point device at us
        const routeStep = push({ key: 'route', label: 'Route device traffic', status: 'running' });
        try {
            await this.adb.setGlobalProxy(opts.serial, hostIp, this.proxy.getPort());
            // Reverse tunnel as a USB fallback (device localhost:PORT → host).
            await this.adb.reverse(opts.serial, this.proxy.getPort(), this.proxy.getPort());
            routeStep.status = 'ok';
            routeStep.detail = `global http_proxy = ${hostIp}:${this.proxy.getPort()} (+adb reverse)`;
        } catch (e: any) {
            routeStep.status = 'warn';
            routeStep.detail = 'Could not set proxy automatically: ' + e.message;
        }
        this.step(routeStep);

        // 6. Frida (optional)
        if (opts.fridaTarget) {
            const fStep = push({ key: 'frida', label: `Frida inject → ${opts.fridaTarget}`, status: 'running' });
            if (!device.fridaRunning) {
                fStep.status = 'warn';
                fStep.detail = 'frida-server not detected on device';
            } else {
                try {
                    const { pid } = await this.frida.inject({
                        serial: opts.serial,
                        caPem: ca.cert,
                        proxyHost: hostIp,
                        proxyPort: this.proxy.getPort(),
                        target: opts.fridaTarget,
                        spawn: true,
                    });
                    caInstall = 'frida';
                    fStep.status = 'ok';
                    fStep.detail = `Injected (pid ${pid}) — CA + unpinning active`;
                } catch (e: any) {
                    fStep.status = 'error';
                    fStep.detail = e.message;
                }
            }
            this.step(fStep);
        }

        return {
            steps,
            device,
            hostIp,
            caInstall,
            proxyPort: this.proxy.getPort(),
        };
    }

    /** Undo device-side changes (proxy + reverse). CA is left in place. */
    async disconnect(serial: string): Promise<void> {
        try { await this.adb.clearGlobalProxy(serial); } catch { /* ignore */ }
        try { await this.adb.removeReverse(serial, this.proxy.getPort()); } catch { /* ignore */ }
    }
}
