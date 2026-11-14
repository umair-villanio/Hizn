/**
 * DesktopService — capture desktop browser traffic (Firefox first).
 *
 * Firefox is the easiest desktop target: it keeps its own certificate store and
 * accepts a throwaway profile, so we can launch a pre-wired instance pointed at
 * hizn's proxy without touching the user's main browser or OS settings.
 *
 * We use a *stable* profile dir (not a temp one) so the one-time CA import the
 * user does the first time persists across launches.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { spawn, execFile } from 'child_process';
import { existsSync } from 'fs';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface DesktopInfo {
    firefoxPath?: string;
    profileDir: string;
    caPath: string;
    proxyPort: number;
}

export class DesktopService {
    /** Stable, per-user profile so an imported CA sticks between launches. */
    private readonly baseDir = path.join(os.homedir(), '.hizn');
    private readonly profileDir = path.join(this.baseDir, 'firefox-profile');
    private readonly caPath = path.join(this.profileDir, 'hizn-ca.pem');

    /** Locate the Firefox binary across platforms, or undefined if missing. */
    detectFirefox(): string | undefined {
        const candidates: string[] = [];
        if (process.platform === 'win32') {
            const pf = process.env['ProgramFiles'] ?? 'C:\\Program Files';
            const pf86 = process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';
            candidates.push(
                path.join(pf, 'Mozilla Firefox', 'firefox.exe'),
                path.join(pf86, 'Mozilla Firefox', 'firefox.exe'),
                path.join(process.env['LOCALAPPDATA'] ?? '', 'Mozilla Firefox', 'firefox.exe'),
            );
        } else if (process.platform === 'darwin') {
            candidates.push(
                '/Applications/Firefox.app/Contents/MacOS/firefox',
                path.join(os.homedir(), 'Applications/Firefox.app/Contents/MacOS/firefox'),
            );
        } else {
            candidates.push(
                '/usr/bin/firefox', '/usr/local/bin/firefox', '/snap/bin/firefox',
                '/usr/bin/firefox-esr',
            );
        }
        return candidates.find((p) => p && existsSync(p));
    }

    info(proxyPort: number): DesktopInfo {
        return {
            firefoxPath: this.detectFirefox(),
            profileDir: this.profileDir,
            caPath: this.caPath,
            proxyPort,
        };
    }

    /**
     * Write (or refresh) the interception profile: proxy prefs + staged CA.
     * The user.js is applied on every start, so changing the proxy port just
     * works on the next launch.
     */
    private async writeProfile(proxyPort: number, caPem: string): Promise<void> {
        await fs.mkdir(this.profileDir, { recursive: true });
        await fs.writeFile(this.caPath, caPem, 'utf8');

        const prefs = [
            '// hizn Firefox interception profile — generated, safe to delete',
            'user_pref("network.proxy.type", 1);',
            `user_pref("network.proxy.http", "127.0.0.1");`,
            `user_pref("network.proxy.http_port", ${proxyPort});`,
            `user_pref("network.proxy.ssl", "127.0.0.1");`,
            `user_pref("network.proxy.ssl_port", ${proxyPort});`,
            'user_pref("network.proxy.share_proxy_settings", true);',
            'user_pref("network.proxy.socks_remote_dns", true);',
            'user_pref("network.proxy.allow_hijacking_localhost", true);',
            'user_pref("network.proxy.no_proxies_on", "");',
            // Pick up a CA added to the OS store (optional convenience).
            'user_pref("security.enterprise_roots.enabled", true);',
            // Make the throwaway profile quiet and fast.
            'user_pref("browser.shell.checkDefaultBrowser", false);',
            'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
            'user_pref("datareporting.healthreport.uploadEnabled", false);',
            'user_pref("trailhead.firstrun.didSeeAboutWelcome", true);',
            'user_pref("browser.aboutwelcome.enabled", false);',
            'user_pref("doh-rollout.disable-heuristics", true);',
            'user_pref("network.trr.mode", 5);', // disable DoH so proxy sees DNS intent
            '',
        ].join('\n');
        await fs.writeFile(path.join(this.profileDir, 'user.js'), prefs, 'utf8');
    }

    /**
     * Locate a *real* NSS certutil (the one that manages Firefox's cert9.db) —
     * NOT Windows' unrelated System32\certutil.exe. Returns the path, or
     * undefined if none is usable.
     */
    async findNssCertutil(): Promise<string | undefined> {
        const names = process.platform === 'win32' ? ['certutil.exe'] : ['certutil'];
        const candidates: string[] = [];
        // PATH entries (skip Windows system dirs — that's the wrong certutil).
        for (const dir of (process.env['PATH'] ?? '').split(path.delimiter)) {
            if (!dir) continue;
            if (/\\windows\\(system32|syswow64)/i.test(dir)) continue;
            for (const n of names) candidates.push(path.join(dir, n));
        }
        // Common NSS-tools install spots.
        const ff = this.detectFirefox();
        if (ff) candidates.push(path.join(path.dirname(ff), 'certutil.exe'));
        candidates.push(
            'C:\\tools\\nss\\bin\\certutil.exe',
            'C:\\ProgramData\\chocolatey\\lib\\nss\\tools\\bin\\certutil.exe',
            '/usr/bin/certutil', '/usr/local/bin/certutil', '/opt/homebrew/bin/certutil',
        );

        for (const cand of candidates) {
            if (!existsSync(cand)) continue;
            if (/\\windows\\(system32|syswow64)/i.test(cand)) continue;
            try {
                const { stdout, stderr } = await execFileAsync(cand, ['-?']).catch((e: any) => ({
                    stdout: e?.stdout ?? '', stderr: e?.stderr ?? '',
                }));
                const out = `${stdout}${stderr}`.toLowerCase();
                if (/certdir|certificate database|nickname/.test(out)) return cand;
            } catch { /* not this one */ }
        }
        return undefined;
    }

    /**
     * Auto-trust the CA by importing it into THIS profile's NSS cert store
     * (cert9.db). Scoped to the hizn Firefox profile only — the user's
     * normal Firefox and the OS trust store are untouched. No-op (reports why)
     * if an NSS certutil isn't available.
     */
    async autoImportCA(caPem: string): Promise<{ imported: boolean; method?: string; reason?: string }> {
        const certutil = await this.findNssCertutil();
        if (!certutil) return { imported: false, reason: 'NSS certutil not found' };

        await fs.mkdir(this.profileDir, { recursive: true });
        await fs.writeFile(this.caPath, caPem, 'utf8');
        const db = `sql:${this.profileDir}`;

        // Create an empty cert DB if the profile has never been launched.
        if (!existsSync(path.join(this.profileDir, 'cert9.db'))) {
            const pwFile = path.join(this.profileDir, '.nsspw');
            await fs.writeFile(pwFile, '', 'utf8').catch(() => {});
            await execFileAsync(certutil, ['-N', '-d', db, '-f', pwFile]).catch(() => {});
        }
        // Replace any prior copy, then add trusted as a CA for TLS.
        await execFileAsync(certutil, ['-D', '-n', 'hizn CA', '-d', db]).catch(() => {});
        await execFileAsync(certutil, ['-A', '-n', 'hizn CA', '-t', 'CT,c,c', '-i', this.caPath, '-d', db]);
        return { imported: true, method: 'certutil' };
    }

    /** Whether the CA has already been imported into this profile's cert store. */
    async caImported(): Promise<boolean> {
        // cert9.db gains an entry once the user imports; as a heuristic we just
        // check the db exists (created after first run) — the UI still shows the
        // one-time import steps until the user confirms.
        return existsSync(path.join(this.profileDir, 'cert9.db'));
    }

    /**
     * Launch Firefox on the interception profile. Returns the profile path so
     * the UI can guide the one-time CA import. Throws if Firefox isn't found.
     */
    async launchFirefox(
        proxyPort: number,
        caPem: string,
    ): Promise<DesktopInfo & { launched: boolean; caTrusted: 'certutil' | 'manual'; certutilFound: boolean }> {
        const firefoxPath = this.detectFirefox();
        if (!firefoxPath) {
            throw new Error('Firefox not found. Install it, or set the proxy manually (127.0.0.1:' + proxyPort + ').');
        }
        await this.writeProfile(proxyPort, caPem);

        // Try to auto-trust the CA in this profile (scoped, no OS changes).
        let caTrusted: 'certutil' | 'manual' = 'manual';
        const result = await this.autoImportCA(caPem).catch(() => ({ imported: false } as any));
        if (result.imported) caTrusted = 'certutil';

        // If it still needs a one-time manual import, open Firefox straight to
        // the certificate settings to make it a two-click job.
        const args = ['-no-remote', '-new-instance', '-profile', this.profileDir];
        if (caTrusted === 'manual') args.push('about:preferences#privacy');

        const child = spawn(firefoxPath, args, { detached: true, stdio: 'ignore' });
        child.unref();

        return {
            ...this.info(proxyPort),
            launched: true,
            caTrusted,
            certutilFound: !!(await this.findNssCertutil()),
        };
    }
}
