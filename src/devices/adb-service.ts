/**
 * AdbService — device automation over ADB.
 *
 * This is what makes interception "one click": given a connected device we can
 * detect it, point its traffic at our proxy, push the CA, open a reverse
 * tunnel, and detect whether frida-server / root is available.
 *
 * Uses @devicefarmer/adbkit (a maintained fork of adbkit).
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import Adb from '@devicefarmer/adbkit';
import { Readable, Duplex } from 'stream';

export interface DeviceInfo {
    serial: string;
    type: string;          // 'device' | 'emulator' | 'offline' | ...
    model?: string;
    androidVersion?: string;
    sdk?: number;
    abi?: string;
    rooted: boolean;
    fridaRunning: boolean;
}

export class AdbService {
    private client = Adb.createClient();

    /** List currently attached devices with enriched metadata. */
    async listDevices(): Promise<DeviceInfo[]> {
        const devices = await this.client.listDevices();
        const infos: DeviceInfo[] = [];
        for (const d of devices) {
            infos.push(await this.describe(d.id, d.type));
        }
        return infos;
    }

    private async describe(serial: string, type: string): Promise<DeviceInfo> {
        const base: DeviceInfo = { serial, type, rooted: false, fridaRunning: false };
        if (type !== 'device' && type !== 'emulator') return base;

        try {
            base.model = (await this.getProp(serial, 'ro.product.model'))?.trim();
            base.androidVersion = (await this.getProp(serial, 'ro.build.version.release'))?.trim();
            const sdk = await this.getProp(serial, 'ro.build.version.sdk');
            base.sdk = sdk ? parseInt(sdk.trim(), 10) : undefined;
            base.abi = (await this.getProp(serial, 'ro.product.cpu.abi'))?.trim();
            base.rooted = await this.isRooted(serial);
            base.fridaRunning = await this.isFridaRunning(serial);
        } catch {
            // Device may have gone away mid-probe; return what we have.
        }
        return base;
    }

    private async getProp(serial: string, prop: string): Promise<string | undefined> {
        return this.shell(serial, `getprop ${prop}`);
    }

    /** Run a shell command and return stdout as a string. */
    async shell(serial: string, command: string): Promise<string> {
        const device = this.client.getDevice(serial);
        const stream = await device.shell(command);
        const output = await Adb.util.readAll(stream);
        return output.toString();
    }

    /**
     * Open a Duplex stream through ADB to a TCP port on the device
     * (e.g. frida-server's DBus socket). Same mechanism HTTP Toolkit
     * uses for its Frida session.
     */
    async openTcp(serial: string, port: number): Promise<Duplex> {
        const device = this.client.getDevice(serial);
        return device.openTcp(port);
    }

    /** Best-effort root check (does `su` exist and work?). */
    async isRooted(serial: string): Promise<boolean> {
        try {
            const out = await this.shell(serial, 'su -c id 2>/dev/null || id');
            return /uid=0\(root\)/.test(out);
        } catch {
            return false;
        }
    }

    /** Is a frida-server process listening on the device? */
    async isFridaRunning(serial: string): Promise<boolean> {
        try {
            const out = await this.shell(serial, 'ps -A 2>/dev/null | grep -i frida');
            return /frida/i.test(out);
        } catch {
            return false;
        }
    }

    /**
     * Point the device's global HTTP proxy at the host running droidmitm.
     * Apps that honour the system proxy will now flow through us.
     */
    async setGlobalProxy(serial: string, host: string, port: number): Promise<void> {
        await this.shell(serial, `settings put global http_proxy ${host}:${port}`);
    }

    /** Remove the global HTTP proxy. */
    async clearGlobalProxy(serial: string): Promise<void> {
        await this.shell(serial, 'settings put global http_proxy :0');
        await this.shell(serial, 'settings delete global http_proxy');
    }

    async getGlobalProxy(serial: string): Promise<string> {
        return (await this.shell(serial, 'settings get global http_proxy')).trim();
    }

    /**
     * adb reverse: make the device's localhost:<port> reach the host's proxy.
     * Useful when Wi-Fi proxy isn't an option (USB-only, or VPN apps).
     */
    async reverse(serial: string, remotePort: number, localPort: number): Promise<void> {
        const device = this.client.getDevice(serial);
        await device.reverse(`tcp:${remotePort}`, `tcp:${localPort}`);
    }

    async removeReverse(serial: string, remotePort: number): Promise<void> {
        const device = this.client.getDevice(serial);
        try {
            await device.reverse(`tcp:${remotePort}`, `tcp:0`);
        } catch {
            // Some adbkit versions expose removeReverse; ignore if unsupported.
        }
    }

    /** Push a file (e.g. the CA PEM) to the device. */
    async pushFile(serial: string, localOrBuffer: string | Buffer, remotePath: string): Promise<void> {
        const device = this.client.getDevice(serial);
        const source = Buffer.isBuffer(localOrBuffer)
            ? Readable.from(localOrBuffer)
            : localOrBuffer;
        const transfer = await device.push(source as any, remotePath);
        await new Promise<void>((resolve, reject) => {
            transfer.on('end', () => resolve());
            transfer.on('error', reject);
        });
    }

    /**
     * Install the CA into the device trust store.
     *
     *  - Rooted: copy into the system CA store (/system/etc/security/cacerts),
     *    named <subject_hash_old>.0, so ALL apps trust it.
     *  - Non-rooted: push the PEM to /sdcard so the user can install it from
     *    Settings, and return guidance (handled by the caller).
     *
     * Returns the strategy actually used.
     */
    async installCA(
        serial: string,
        caPem: string,
        androidHash: string,
        rooted: boolean,
    ): Promise<'system' | 'user-manual'> {
        const tmp = `/data/local/tmp/droidmitm-ca.pem`;
        await this.pushFile(serial, Buffer.from(caPem), tmp);

        if (rooted) {
            const target = `/system/etc/security/cacerts/${androidHash}.0`;
            // Remount system rw, copy cert, fix perms, remount ro.
            const script = [
                'su -c "mount -o rw,remount /system 2>/dev/null || mount -o rw,remount /"',
                `su -c "cp ${tmp} ${target}"`,
                `su -c "chmod 644 ${target}"`,
                `su -c "chown root:root ${target}"`,
                // Android 14+ moves the store to an APEX overlay; also try that path.
                `su -c "cp ${tmp} /apex/com.android.conscrypt/cacerts/${androidHash}.0 2>/dev/null || true"`,
            ].join(' && ');
            await this.shell(serial, script);
            return 'system';
        }

        // Non-rooted: leave the PEM on /sdcard for manual install.
        await this.pushFile(serial, Buffer.from(caPem), '/sdcard/Download/droidmitm-ca.crt');
        return 'user-manual';
    }
}
