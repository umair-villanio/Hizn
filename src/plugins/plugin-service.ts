/**
 * PluginService — file-backed plugin store.
 *
 * Plugins are single .js files (see plugins/README.md): a JS function body
 * receiving `ctx` and returning a string (HTML allowed), with metadata in
 * `// @name`/`@description`/`@version`/`@author` header comments.
 *
 * Two directories:
 *   contrib — <repo>/plugins (shipped community plugins, read-only)
 *   user    — ~/.hizn/plugins (user-installed, writable)
 *
 * Enabled state persists in ~/.hizn/plugins.json.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';

export interface PluginInfo {
    /** Stable id: "<origin>/<filename>" — used by toggle/delete. */
    id: string;
    name: string;
    desc: string;
    version?: string;
    author?: string;
    origin: 'contrib' | 'user';
    builtin: boolean; // contrib plugins can't be deleted, only disabled
    enabled: boolean;
    source: string;   // file contents — the transform function body
}

const CONTRIB_DIR = path.resolve(__dirname, '../../plugins');
const USER_DIR = path.join(os.homedir(), '.hizn', 'plugins');
const STATE_FILE = path.join(os.homedir(), '.hizn', 'plugins.json');

function parseManifest(source: string, filename: string) {
    const meta: Record<string, string> = {};
    for (const line of source.split('\n').slice(0, 30)) {
        const m = line.match(/^\s*\/\/\s*@(\w+)\s+(.+?)\s*$/);
        if (!m) break;
        meta[m[1].toLowerCase()] = m[2];
    }
    return {
        name: meta['name'] ?? filename.replace(/\.js$/i, ''),
        desc: meta['description'] ?? meta['desc'] ?? '',
        version: meta['version'],
        author: meta['author'],
    };
}

export class PluginService {
    private async readDir(dir: string, origin: PluginInfo['origin']): Promise<PluginInfo[]> {
        let files: string[];
        try {
            files = (await fs.readdir(dir)).filter((f) => f.endsWith('.js'));
        } catch {
            return []; // dir missing — fine
        }

        const enabledMap = await this.enabledMap();
        const out: PluginInfo[] = [];
        for (const file of files) {
            try {
                const source = await fs.readFile(path.join(dir, file), 'utf8');
                const meta = parseManifest(source, file);
                const id = `${origin}/${file}`;
                out.push({
                    id,
                    ...meta,
                    origin,
                    builtin: origin === 'contrib',
                    enabled: enabledMap[id] ?? true,
                    source,
                });
            } catch { /* unreadable file — skip */ }
        }
        return out;
    }

    private async enabledMap(): Promise<Record<string, boolean>> {
        try {
            return JSON.parse(await fs.readFile(STATE_FILE, 'utf8'));
        } catch {
            return {};
        }
    }

    async list(): Promise<PluginInfo[]> {
        const [contrib, user] = await Promise.all([
            this.readDir(CONTRIB_DIR, 'contrib'),
            this.readDir(USER_DIR, 'user'),
        ]);
        return [...contrib, ...user];
    }

    /** Install a plugin into the user dir. `source` is the function body. */
    async install(opts: { name: string; desc?: string; author?: string; source: string }): Promise<PluginInfo> {
        const slug = opts.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'plugin';
        await fs.mkdir(USER_DIR, { recursive: true });

        let file = `${slug}.js`;
        for (let i = 2; ; i++) {
            try {
                await fs.access(path.join(USER_DIR, file));
                file = `${slug}-${i}.js`;
            } catch { break; }
        }

        const header = [
            `// @name        ${opts.name}`,
            `// @description ${opts.desc ?? ''}`,
            opts.author ? `// @author      ${opts.author}` : null,
            '',
            '',
        ].filter((l): l is string => l !== null).join('\n');

        await fs.writeFile(path.join(USER_DIR, file), header + opts.source.trimStart(), 'utf8');

        const [meta] = [parseManifest(header + opts.source, file)];
        return {
            id: `user/${file}`,
            ...meta,
            origin: 'user',
            builtin: false,
            enabled: true,
            source: header + opts.source.trimStart(),
        };
    }

    /** Remove a user plugin. Contrib plugins are read-only. */
    async remove(id: string): Promise<void> {
        const [origin, file] = id.split('/');
        if (origin !== 'user' || !file || file.includes('..')) {
            throw new Error('Only user-installed plugins can be removed');
        }
        await fs.unlink(path.join(USER_DIR, file));

        const map = await this.enabledMap();
        delete map[id];
        await this.writeEnabledMap(map);
    }

    async setEnabled(id: string, enabled: boolean): Promise<void> {
        const map = await this.enabledMap();
        map[id] = enabled;
        await this.writeEnabledMap(map);
    }

    private async writeEnabledMap(map: Record<string, boolean>): Promise<void> {
        await fs.mkdir(path.dirname(STATE_FILE), { recursive: true });
        await fs.writeFile(STATE_FILE, JSON.stringify(map, null, 2), 'utf8');
    }

    /** Paths the UI can display so users know where to drop files. */
    dirs() {
        return { contrib: CONTRIB_DIR, user: USER_DIR };
    }
}
