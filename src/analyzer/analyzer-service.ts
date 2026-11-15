/**
 * AnalyzerService — static APK analysis (a light, MobSF-style SAST).
 *
 * Pure JS / Node built-ins, no external tools (no jadx/apktool/JVM):
 *   - ZIP reader over the APK (central directory + zlib inflate)
 *   - Binary AndroidManifest.xml (AXML) decoder
 *   - Signing certificate parse + analysis (node-forge + crypto)
 *   - Hardcoded secret / endpoint scan over DEX + resources + assets
 *
 * Produces a structured, scored report: app/version info, permissions,
 * exported components, certificate info + analysis, manifest analysis, and
 * secrets/URLs — the sections a quick security triage needs.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import * as zlib from 'zlib';
import { createHash, X509Certificate } from 'crypto';
// node-forge is already present (mockttp dependency) — used for PKCS#7 + cert.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const forge = require('node-forge');

export type Severity = 'high' | 'medium' | 'low' | 'info';

export interface Finding {
    section: string;
    title: string;
    severity: Severity;
    detail?: string;
}

export interface AnalyzerReport {
    file: { name?: string; sizeBytes: number; sha256: string };
    app: {
        package?: string;
        versionName?: string;
        versionCode?: string;
        minSdk?: string;
        targetSdk?: string;
        compileSdk?: string;
    };
    permissions: { name: string; severity: Severity; info?: string }[];
    customPermissions: { name: string; protectionLevel?: string }[];
    components: { kind: string; name: string; exported: boolean; permission?: string; hasIntentFilter: boolean }[];
    certificate?: {
        subject: string;
        issuer: string;
        serialNumber?: string;
        validFrom?: string;
        validTo?: string;
        signatureAlgorithm?: string;
        publicKeyAlgorithm?: string;
        keySizeBits?: number;
        sha1?: string;
        sha256?: string;
        selfSigned?: boolean;
        signatureScheme?: string;
    };
    manifestFlags: Record<string, string | boolean | undefined>;
    secrets: { type: string; match: string; where: string; severity: Severity }[];
    urls: string[];
    findings: Finding[];
    summary: { high: number; medium: number; low: number; info: number };
    errors?: string[];
}

/* ------------------------------------------------------------------ ZIP ---- */

interface ZipEntry { name: string; method: number; compSize: number; uncompSize: number; localOffset: number; }

/** Minimal ZIP reader: parse the central directory, inflate entries on demand. */
class Zip {
    private entries = new Map<string, ZipEntry>();
    /** Central-directory start offset — also where the APK Signing Block ends. */
    cdOffset = 0;
    constructor(public buf: Buffer) { this.readCentralDirectory(); }

    names(): string[] { return [...this.entries.keys()]; }
    has(name: string): boolean { return this.entries.has(name); }

    private readCentralDirectory(): void {
        const b = this.buf;
        // Find End Of Central Directory (0x06054b50), scanning back from the end.
        let eocd = -1;
        const minPos = Math.max(0, b.length - 65557); // max comment 65535 + 22
        for (let i = b.length - 22; i >= minPos; i--) {
            if (b.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
        }
        if (eocd < 0) throw new Error('Not a ZIP/APK (no end-of-central-directory record)');
        const cdCount = b.readUInt16LE(eocd + 10);
        let off = b.readUInt32LE(eocd + 16);
        this.cdOffset = off;
        for (let n = 0; n < cdCount; n++) {
            if (off + 46 > b.length || b.readUInt32LE(off) !== 0x02014b50) break;
            const method = b.readUInt16LE(off + 10);
            const compSize = b.readUInt32LE(off + 20);
            const uncompSize = b.readUInt32LE(off + 24);
            const nameLen = b.readUInt16LE(off + 28);
            const extraLen = b.readUInt16LE(off + 30);
            const commentLen = b.readUInt16LE(off + 32);
            const localOffset = b.readUInt32LE(off + 42);
            const name = b.toString('utf8', off + 46, off + 46 + nameLen);
            this.entries.set(name, { name, method, compSize, uncompSize, localOffset });
            off += 46 + nameLen + extraLen + commentLen;
        }
    }

    read(name: string): Buffer | undefined {
        const e = this.entries.get(name);
        if (!e) return undefined;
        return this.readEntry(e);
    }

    readEntry(e: ZipEntry): Buffer | undefined {
        const b = this.buf;
        const lo = e.localOffset;
        if (lo + 30 > b.length || b.readUInt32LE(lo) !== 0x04034b50) return undefined;
        const nameLen = b.readUInt16LE(lo + 26);
        const extraLen = b.readUInt16LE(lo + 28);
        const dataStart = lo + 30 + nameLen + extraLen;
        const data = b.subarray(dataStart, dataStart + e.compSize);
        try {
            if (e.method === 0) return Buffer.from(data);
            if (e.method === 8) return zlib.inflateRawSync(data);
        } catch { /* corrupt entry */ }
        return undefined;
    }

    *all(): Generator<{ entry: ZipEntry; read: () => Buffer | undefined }> {
        for (const e of this.entries.values()) yield { entry: e, read: () => this.readEntry(e) };
    }
}

/* ----------------------------------------------------------------- AXML ---- */

interface AxmlNode { name: string; attrs: Record<string, string>; children: AxmlNode[]; }

/** Known android: attribute resource IDs → names (for AXML with empty name strings). */
const ATTR_RES_IDS: Record<number, string> = {
    0x0101021b: 'versionCode', 0x0101021c: 'versionName', 0x0101020c: 'minSdkVersion',
    0x01010270: 'targetSdkVersion', 0x01010003: 'name', 0x01010006: 'permission',
    0x01010010: 'exported', 0x0101000f: 'debuggable', 0x01010280: 'allowBackup',
    0x010104ec: 'usesCleartextTraffic', 0x0101048d: 'usesCleartextTraffic',
    0x010104dd: 'networkSecurityConfig', 0x01010009: 'protectionLevel',
    0x0101055b: 'compileSdkVersion',
};

/** Decode a binary AndroidManifest.xml into a small element tree. */
function parseAxml(buf: Buffer): AxmlNode {
    if (buf.length < 8 || buf.readUInt16LE(0) !== 0x0003) throw new Error('Not a binary AndroidManifest (AXML)');
    let pos = 8; // skip file header
    let strings: string[] = [];
    let resMap: number[] = [];

    const readStringPool = (start: number): number => {
        const size = buf.readUInt32LE(start + 4);
        const count = buf.readUInt32LE(start + 8);
        const flags = buf.readUInt32LE(start + 16);
        const stringsStart = buf.readUInt32LE(start + 20);
        const utf8 = (flags & (1 << 8)) !== 0;
        const offs: number[] = [];
        let p = start + 28;
        for (let i = 0; i < count; i++) { offs.push(buf.readUInt32LE(p)); p += 4; }
        const base = start + stringsStart;
        const out: string[] = [];
        for (let i = 0; i < count; i++) {
            let o = base + offs[i];
            try {
                if (utf8) {
                    // skip char-count (u8/u16 varint), then byte-count, then bytes
                    o += (buf[o] & 0x80) ? 2 : 1;
                    let len = buf[o];
                    if (len & 0x80) { len = ((len & 0x7f) << 8) | buf[o + 1]; o += 2; } else { o += 1; }
                    out.push(buf.toString('utf8', o, o + len));
                } else {
                    let len = buf.readUInt16LE(o); o += 2;
                    if (len & 0x8000) { len = ((len & 0x7fff) << 16) | buf.readUInt16LE(o); o += 2; }
                    out.push(buf.toString('utf16le', o, o + len * 2));
                }
            } catch { out.push(''); }
        }
        return (strings = out, size);
    };

    const str = (i: number): string => (i >= 0 && i < strings.length ? strings[i] : '');
    const attrName = (nameIdx: number): string => {
        const s = str(nameIdx);
        if (s) return s;
        const rid = resMap[nameIdx];
        return rid ? (ATTR_RES_IDS[rid] || '') : '';
    };

    const root: AxmlNode = { name: '#root', attrs: {}, children: [] };
    const stack: AxmlNode[] = [root];

    while (pos + 8 <= buf.length) {
        const type = buf.readUInt16LE(pos);
        const size = buf.readUInt32LE(pos + 4);
        if (size < 8) break;
        if (type === 0x0001) { readStringPool(pos); }
        else if (type === 0x0180) { // resource map
            const n = (size - 8) / 4; resMap = [];
            for (let i = 0; i < n; i++) resMap.push(buf.readUInt32LE(pos + 8 + i * 4));
        } else if (type === 0x0102) { // start element
            const nameIdx = buf.readUInt32LE(pos + 8 + 4); // after lineNo+comment... actually node header
            // ResXMLTree_node: header(8) lineNumber(4) comment(4) then attrExt
            const ext = pos + 8 + 8;
            const name = str(buf.readUInt32LE(ext + 4));
            const attrStart = buf.readUInt16LE(ext + 8);
            const attrCount = buf.readUInt16LE(ext + 12);
            const node: AxmlNode = { name, attrs: {}, children: [] };
            let ap = ext + attrStart;
            for (let i = 0; i < attrCount; i++) {
                const aName = attrName(buf.readUInt32LE(ap + 4));
                const rawValue = buf.readInt32LE(ap + 8);
                const dataType = buf.readUInt8(ap + 8 + 4 + 3);
                const data = buf.readUInt32LE(ap + 8 + 4 + 4);
                let val: string;
                if (rawValue !== -1) val = str(rawValue);
                else if (dataType === 0x12) val = data !== 0 ? 'true' : 'false'; // boolean
                else if (dataType === 0x10) val = String(data | 0);             // int dec
                else if (dataType === 0x11) val = '0x' + data.toString(16);      // int hex
                else if (dataType === 0x03) val = str(data);                     // string
                else if (dataType === 0x01) val = '@' + data.toString(16);       // reference
                else val = String(data);
                if (aName) node.attrs[aName] = val;
                ap += 20;
            }
            stack[stack.length - 1].children.push(node);
            stack.push(node);
            void nameIdx;
        } else if (type === 0x0103) { // end element
            if (stack.length > 1) stack.pop();
        }
        pos += size;
    }
    return root;
}

function findAll(node: AxmlNode, name: string, out: AxmlNode[] = []): AxmlNode[] {
    for (const c of node.children) { if (c.name === name) out.push(c); findAll(c, name, out); }
    return out;
}
function findFirst(node: AxmlNode, name: string): AxmlNode | undefined {
    return findAll(node, name)[0];
}

/* --------------------------------------------------- permissions table ---- */

/** A small map of common Android permissions → severity + note. */
const DANGEROUS = /(READ_SMS|SEND_SMS|RECEIVE_SMS|READ_CONTACTS|WRITE_CONTACTS|RECORD_AUDIO|CAMERA|ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|READ_CALL_LOG|WRITE_CALL_LOG|READ_PHONE_STATE|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|READ_CALENDAR|BODY_SENSORS|GET_ACCOUNTS|CALL_PHONE|PROCESS_OUTGOING_CALLS|QUERY_ALL_PACKAGES)/;
const SIGNATURE_LIKE = /(MANAGE_EXTERNAL_STORAGE|BIND_ACCESSIBILITY_SERVICE|BIND_DEVICE_ADMIN|WRITE_SECURE_SETTINGS|INSTALL_PACKAGES|MOUNT_UNMOUNT_FILESYSTEMS)/;

function permSeverity(name: string): { severity: Severity; info?: string } {
    if (SIGNATURE_LIKE.test(name)) return { severity: 'high', info: 'Powerful/abusable permission' };
    if (DANGEROUS.test(name)) return { severity: 'medium', info: 'Dangerous (runtime) permission' };
    return { severity: 'info' };
}

/* ------------------------------------------------- APK signing block ---- */

/**
 * Extract the first signer certificate (DER) from the APK Signing Block
 * (Signature Scheme v2 / v3), used when there's no v1 META-INF block.
 * Layout: [u64 size][id-value pairs][u64 size]["APK Sig Block 42"], sitting
 * right before the central directory. v2 id 0x7109871a, v3 0xf05368c0.
 */
function certFromSigningBlock(buf: Buffer, cdOffset: number): Buffer | undefined {
    try {
        if (cdOffset < 32) return undefined;
        if (buf.toString('latin1', cdOffset - 16, cdOffset) !== 'APK Sig Block 42') return undefined;
        const blockSize = Number(buf.readBigUInt64LE(cdOffset - 24));
        const blockStart = cdOffset - blockSize - 8;
        if (blockStart < 0) return undefined;
        let p = blockStart + 8;
        const end = cdOffset - 24;
        const want = new Set([0x7109871a, 0xf05368c0]);
        while (p + 12 <= end) {
            const pairLen = Number(buf.readBigUInt64LE(p)); p += 8;
            if (pairLen < 4 || p + pairLen > end + 8) break;
            const id = buf.readUInt32LE(p) >>> 0;
            const valStart = p + 4;
            if (want.has(id)) {
                const cert = firstCertFromScheme(buf, valStart);
                if (cert) return cert;
            }
            p = p + pairLen;
        }
    } catch { /* malformed block */ }
    return undefined;
}

/** Walk signers → first signer → signed data → certificates → first cert DER. */
function firstCertFromScheme(buf: Buffer, start: number): Buffer | undefined {
    let p = start;
    p += 4;                               // signers sequence length
    p += 4;                               // first signer length
    p += 4;                               // signed-data length
    const digestsLen = buf.readUInt32LE(p); p += 4 + digestsLen; // skip digests
    p += 4;                               // certificates sequence length
    const certLen = buf.readUInt32LE(p); p += 4;
    if (certLen <= 0 || p + certLen > buf.length) return undefined;
    return Buffer.from(buf.subarray(p, p + certLen));
}

/** First X.509 cert (DER) out of a v1 PKCS#7 signature block. */
function pkcs7FirstCertDer(pkcs7Der: Buffer): Buffer | undefined {
    try {
        const asn1 = forge.asn1.fromDer(forge.util.createBuffer(pkcs7Der.toString('binary')));
        const msg = forge.pkcs7.messageFromAsn1(asn1);
        const cert = msg.certificates && msg.certificates[0];
        if (!cert) return undefined;
        return Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary');
    } catch { return undefined; }
}

/* -------------------------------------------------------- secret scan ---- */

const SECRET_PATTERNS: { type: string; re: RegExp; severity: Severity }[] = [
    { type: 'Google API key', re: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' },
    { type: 'Firebase app id', re: /1:[0-9]{6,}:android:[0-9a-f]{8,}/g, severity: 'low' },
    { type: 'Firebase URL', re: /https?:\/\/[a-z0-9-]+\.firebaseio\.com/gi, severity: 'medium' },
    { type: 'AWS access key', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g, severity: 'high' },
    { type: 'AWS secret (heuristic)', re: /aws(.{0,20})?(secret|private).{0,20}['"][0-9a-zA-Z/+]{40}['"]/gi, severity: 'high' },
    { type: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, severity: 'high' },
    { type: 'Google OAuth client', re: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g, severity: 'low' },
    { type: 'Slack token', re: /xox[baprs]-[0-9A-Za-z-]{10,48}/g, severity: 'high' },
    { type: 'Slack webhook', re: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]+/g, severity: 'high' },
    { type: 'Stripe key', re: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}/g, severity: 'high' },
    { type: 'Stripe publishable key', re: /\bpk_(?:live|test)_[0-9a-zA-Z]{20,}/g, severity: 'low' },
    { type: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}/g, severity: 'high' },
    { type: 'Twilio SID', re: /\bAC[0-9a-fA-F]{32}\b/g, severity: 'medium' },
    { type: 'SendGrid key', re: /\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}/g, severity: 'high' },
    { type: 'Mapbox token', re: /\b(?:pk|sk)\.eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+/g, severity: 'medium' },
    { type: 'Facebook access token', re: /\bEAACEdEose0cBA[0-9A-Za-z]+/g, severity: 'high' },
    { type: 'JWT', re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, severity: 'medium' },
    { type: 'Basic-auth URL', re: /https?:\/\/[^\/\s:@"']{1,40}:[^\/\s:@"']{1,40}@[A-Za-z0-9.-]+/g, severity: 'high' },
    { type: 'Bearer token', re: /[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}=*/g, severity: 'medium' },
    { type: 'Generic secret assignment', re: /(?:api[_-]?key|secret|passwd|password|token|auth[_-]?token|access[_-]?key|client[_-]?secret)['"\s:=]{1,6}['"][A-Za-z0-9\-_.=/+]{10,80}['"]/gi, severity: 'low' },
];
const URL_RE = /https?:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}/g;

/**
 * High-confidence secret resource / meta-data key names (curated, like MobSF).
 * Deliberately narrow — broad words like "password"/"token" match UI drawables
 * and labels, so they are matched in VALUES (patterns) instead, not by name.
 */
const HIGH_NAME = /(api[_-]?key|apikey|client[_-]?secret|client[_-]?id|secret[_-]?key|access[_-]?key|private[_-]?key|consumer[_-]?(key|secret)|app[_-]?secret|\baws\b|s3[_-]|oauth[_-]?(token|key|secret)|google[_-]?api|google_app_id|gcm_default|fcm_|default_web_client|firebase[_-]|facebook_app|facebook_client|url_facebook|mapbox|sendgrid|twilio|stripe[_-]?(key|secret)|appsflyer|onesignal|mixpanel|braze|crashlytics[._-])/i;
function nameSeverity(name: string): Severity {
    return /(secret|private[_-]?key|access[_-]?key|\baws\b|client[_-]?secret|consumer[_-]?secret)/i.test(name) ? 'high' : 'medium';
}

/** Extract printable ASCII runs from a binary buffer (for DEX string pools). */
function extractStrings(buf: Buffer, min = 6, cap = 4_000_000): string {
    const out: string[] = [];
    let cur: number[] = [];
    const end = Math.min(buf.length, 80 * 1024 * 1024);
    for (let i = 0; i < end && out.length < cap; i++) {
        const c = buf[i];
        if (c >= 0x20 && c < 0x7f) cur.push(c);
        else { if (cur.length >= min) out.push(Buffer.from(cur).toString('latin1')); cur = []; }
    }
    if (cur.length >= min) out.push(Buffer.from(cur).toString('latin1'));
    return out.join('\n');
}

/** Extract printable UTF-16LE runs (ASCII char followed by 0x00). */
function extractUtf16(buf: Buffer, min = 6, cap = 1_000_000): string {
    const out: string[] = [];
    let cur: number[] = [];
    const end = Math.min(buf.length - 1, 40 * 1024 * 1024);
    for (let i = 0; i < end && out.length < cap; i += 2) {
        const c = buf[i], hi = buf[i + 1];
        if (hi === 0 && c >= 0x20 && c < 0x7f) cur.push(c);
        else { if (cur.length >= min) out.push(Buffer.from(cur).toString('latin1')); cur = []; }
    }
    if (cur.length >= min) out.push(Buffer.from(cur).toString('latin1'));
    return out.join('\n');
}

/* ------------------------------------------------- resources.arsc ---- */

/** Decode a RES_STRING_POOL chunk (header at `start`) into its strings. */
function decodeStringPool(buf: Buffer, start: number): string[] {
    const count = buf.readUInt32LE(start + 8);
    const flags = buf.readUInt32LE(start + 16);
    const stringsStart = buf.readUInt32LE(start + 20);
    const utf8 = (flags & (1 << 8)) !== 0;
    const base = start + stringsStart;
    const out: string[] = [];
    for (let i = 0; i < count; i++) {
        let o = base + buf.readUInt32LE(start + 28 + i * 4);
        try {
            if (utf8) {
                o += (buf[o] & 0x80) ? 2 : 1;
                let len = buf[o];
                if (len & 0x80) { len = ((len & 0x7f) << 8) | buf[o + 1]; o += 2; } else { o += 1; }
                out.push(buf.toString('utf8', o, o + len));
            } else {
                let len = buf.readUInt16LE(o); o += 2;
                if (len & 0x8000) { len = ((len & 0x7fff) << 16) | buf.readUInt16LE(o); o += 2; }
                out.push(buf.toString('utf16le', o, o + len * 2));
            }
        } catch { out.push(''); }
    }
    return out;
}

/** Parse resources.arsc → global string values + resolved name→value string resources. */
function parseArsc(buf: Buffer): { values: string[]; named: { name: string; value: string }[] } {
    const res = { values: [] as string[], named: [] as { name: string; value: string }[] };
    try {
        if (buf.readUInt16LE(0) !== 0x0002) return res;
        let pos = buf.readUInt16LE(2); // table headerSize
        if (buf.readUInt16LE(pos) === 0x0001) { res.values = decodeStringPool(buf, pos); pos += buf.readUInt32LE(pos + 4); }
        while (pos + 8 <= buf.length) {
            const type = buf.readUInt16LE(pos);
            const size = buf.readUInt32LE(pos + 4);
            if (size < 8) break;
            if (type === 0x0200) parseArscPackage(buf, pos, size, res);
            pos += size;
        }
    } catch { /* malformed */ }
    return res;
}

function parseArscPackage(buf: Buffer, start: number, size: number, res: { values: string[]; named: { name: string; value: string }[] }): void {
    try {
        const hdrSize = buf.readUInt16LE(start + 2);
        const keyStringsOff = buf.readUInt32LE(start + 276); // id(4)+name(256)+typeStrings(4)+lastPublicType(4)+keyStrings(4)
        const keyNames = keyStringsOff ? decodeStringPool(buf, start + keyStringsOff) : [];
        let p = start + hdrSize;
        const end = start + size;
        while (p + 8 <= end) {
            const t = buf.readUInt16LE(p);
            const sz = buf.readUInt32LE(p + 4);
            if (sz < 8) break;
            if (t === 0x0201) parseArscType(buf, p, sz, keyNames, res);
            p += sz;
        }
    } catch { /* skip package */ }
}

function parseArscType(buf: Buffer, start: number, size: number, keyNames: string[], res: { values: string[]; named: { name: string; value: string }[] }): void {
    try {
        const hdrSize = buf.readUInt16LE(start + 2);
        const entryCount = Math.min(buf.readUInt32LE(start + 12), 200000);
        const entriesStart = buf.readUInt32LE(start + 16);
        const offArr = start + hdrSize;
        const entriesBase = start + entriesStart;
        for (let i = 0; i < entryCount; i++) {
            const off = buf.readUInt32LE(offArr + i * 4);
            if (off === 0xffffffff) continue;
            const e = entriesBase + off;
            if (e + 8 > start + size) continue;
            const flags = buf.readUInt16LE(e + 2);
            const keyIdx = buf.readUInt32LE(e + 4);
            if (flags & 0x0001) continue;        // complex/map entry — no simple value
            const v = e + 8;                      // Res_value follows the 8-byte entry
            if (buf.readUInt8(v + 3) !== 0x03) continue; // TYPE_STRING only
            const name = keyNames[keyIdx] || '';
            const value = res.values[buf.readUInt32LE(v + 4)] || '';
            if (name && value) res.named.push({ name, value });
        }
    } catch { /* skip type */ }
}

/* -------------------------------------------------------- the service ---- */

export class AnalyzerService {
    async analyze(apk: Buffer, fileName?: string): Promise<AnalyzerReport> {
        const errors: string[] = [];
        const report: AnalyzerReport = {
            file: { name: fileName, sizeBytes: apk.length, sha256: createHash('sha256').update(apk).digest('hex') },
            app: {}, permissions: [], customPermissions: [], components: [],
            manifestFlags: {}, secrets: [], urls: [], findings: [],
            summary: { high: 0, medium: 0, low: 0, info: 0 },
        };

        let zip: Zip;
        try { zip = new Zip(apk); } catch (e: any) { report.errors = [e.message]; return report; }

        let metaData: { name: string; value: string }[] = [];

        // ---- Manifest ----
        try {
            const mBuf = zip.read('AndroidManifest.xml');
            if (!mBuf) throw new Error('AndroidManifest.xml not found');
            const root = parseAxml(mBuf);
            const manifest = findFirst(root, 'manifest');
            const application = findFirst(root, 'application');

            report.app.package = manifest?.attrs['package'];
            report.app.versionName = manifest?.attrs['versionName'];
            report.app.versionCode = manifest?.attrs['versionCode'];
            report.app.compileSdk = manifest?.attrs['compileSdkVersion'];
            const usesSdk = findFirst(root, 'uses-sdk');
            report.app.minSdk = usesSdk?.attrs['minSdkVersion'] ?? manifest?.attrs['minSdkVersion'];
            report.app.targetSdk = usesSdk?.attrs['targetSdkVersion'] ?? manifest?.attrs['targetSdkVersion'];

            // Permissions
            for (const p of findAll(root, 'uses-permission')) {
                const name = p.attrs['name']; if (!name) continue;
                const s = permSeverity(name);
                report.permissions.push({ name, severity: s.severity, info: s.info });
            }
            report.permissions.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
            for (const p of findAll(root, 'permission')) {
                if (p.attrs['name']) report.customPermissions.push({ name: p.attrs['name'], protectionLevel: p.attrs['protectionLevel'] });
            }

            // Exported components
            for (const kind of ['activity', 'activity-alias', 'service', 'receiver', 'provider']) {
                for (const c of findAll(root, kind)) {
                    const name = c.attrs['name']; if (!name) continue;
                    const hasIntentFilter = c.children.some((x) => x.name === 'intent-filter');
                    const exportedAttr = c.attrs['exported'];
                    const exported = exportedAttr != null ? exportedAttr === 'true' : hasIntentFilter;
                    report.components.push({ kind, name, exported, permission: c.attrs['permission'], hasIntentFilter });
                }
            }

            // <meta-data> entries — a common home for API keys (Maps, FB, etc.).
            metaData = findAll(root, 'meta-data')
                .map((m) => ({ name: m.attrs['name'] || '', value: m.attrs['value'] || '' }))
                .filter((m) => m.name || m.value);

            // Manifest flags + findings
            const flags = report.manifestFlags;
            const dbg = application?.attrs['debuggable'] === 'true';
            const backup = application?.attrs['allowBackup'];
            const cleartext = application?.attrs['usesCleartextTraffic'];
            const nsc = application?.attrs['networkSecurityConfig'];
            flags['debuggable'] = dbg;
            flags['allowBackup'] = backup == null ? '(default: true ≤ API 30)' : backup;
            flags['usesCleartextTraffic'] = cleartext == null ? '(default)' : cleartext;
            flags['networkSecurityConfig'] = nsc || '(none)';

            if (dbg) add(report, { section: 'Manifest', title: 'App is debuggable', severity: 'high', detail: 'android:debuggable="true" ships a debuggable build — do not release.' });
            if (backup !== 'false') add(report, { section: 'Manifest', title: 'Backups allowed', severity: 'medium', detail: 'android:allowBackup is not false — app data can be extracted via adb backup.' });
            if (cleartext === 'true') add(report, { section: 'Manifest', title: 'Cleartext traffic allowed', severity: 'medium', detail: 'usesCleartextTraffic="true" permits unencrypted HTTP.' });
            const minSdkNum = parseInt(report.app.minSdk || '', 10);
            if (minSdkNum && minSdkNum < 24) add(report, { section: 'Manifest', title: `Low minSdkVersion (${minSdkNum})`, severity: 'low', detail: 'Pre-24 ignores user-added CAs and misses platform security hardening.' });
            // Exported-without-permission findings
            const risky = report.components.filter((c) => c.exported && !c.permission && c.hasIntentFilter);
            for (const c of risky.slice(0, 40)) {
                add(report, { section: 'Manifest', title: `Exported ${c.kind} without permission`, severity: 'medium', detail: c.name });
            }
        } catch (e: any) { errors.push('Manifest: ' + e.message); }

        // ---- Certificate (v1 META-INF, else v2/v3 signing block) ----
        try {
            let certDer: Buffer | undefined;
            let scheme = '';
            const sigName = zip.names().find((n) => /^META-INF\/.*\.(RSA|DSA|EC)$/i.test(n));
            if (sigName) {
                const sig = zip.read(sigName);
                if (sig) { certDer = pkcs7FirstCertDer(sig); scheme = 'v1 (JAR)'; }
            }
            if (!certDer) {
                certDer = certFromSigningBlock(apk, zip.cdOffset);
                if (certDer) scheme = 'v2/v3 (APK Signing Block)';
            }
            if (certDer) this.analyzeCertDer(certDer, scheme, report);
            else errors.push('Certificate: could not extract a signing certificate (v1/v2/v3).');
        } catch (e: any) { errors.push('Certificate: ' + e.message); }

        // ---- Secrets / URLs ----
        try { this.scanSecrets(zip, report, metaData); } catch (e: any) { errors.push('Secrets: ' + e.message); }

        // Tally
        for (const f of report.findings) report.summary[f.severity]++;
        for (const s of report.secrets) report.summary[s.severity]++;
        if (errors.length) report.errors = errors;
        return report;
    }

    private analyzeCertDer(certDer: Buffer, scheme: string, report: AnalyzerReport): void {
        const cert = forge.pki.certificateFromAsn1(
            forge.asn1.fromDer(forge.util.createBuffer(certDer.toString('binary'))),
        );

        // Re-decode DN values from UTF-8 (forge yields raw bytes → fixes mojibake).
        const fixUtf8 = (s: string) => { try { return Buffer.from(s, 'latin1').toString('utf8'); } catch { return s; } };
        const dn = (attrs: any[]) => attrs.map((a) => `${a.shortName || a.name}=${fixUtf8(String(a.value))}`).join(', ');
        const subject = dn(cert.subject.attributes);
        const issuer = dn(cert.issuer.attributes);

        const sha1 = createHash('sha1').update(certDer).digest('hex');
        const sha256 = createHash('sha256').update(certDer).digest('hex');

        const sigOid = cert.signatureOid as string;
        const sigAlg = (forge.pki.oids[sigOid] as string) || sigOid;
        let keyAlg = 'unknown', keyBits: number | undefined;
        try {
            if (cert.publicKey && cert.publicKey.n) { keyAlg = 'RSA'; keyBits = cert.publicKey.n.bitLength(); }
            else { const x = new X509Certificate(certDer); keyAlg = x.publicKey.asymmetricKeyType || 'unknown'; keyBits = (x.publicKey.asymmetricKeyDetails as any)?.modulusLength; }
        } catch { /* best effort */ }

        const selfSigned = subject === issuer;
        report.certificate = {
            subject, issuer, serialNumber: cert.serialNumber,
            validFrom: cert.validity?.notBefore?.toISOString?.(),
            validTo: cert.validity?.notAfter?.toISOString?.(),
            signatureAlgorithm: sigAlg, publicKeyAlgorithm: keyAlg, keySizeBits: keyBits,
            sha1, sha256, selfSigned, signatureScheme: scheme,
        };

        // Certificate analysis
        if (/sha1|md5/i.test(sigAlg)) add(report, { section: 'Certificate', title: `Weak signature algorithm (${sigAlg})`, severity: 'high', detail: 'SHA-1/MD5 signatures are collision-prone; re-sign with SHA-256.' });
        if (keyAlg === 'RSA' && keyBits && keyBits < 2048) add(report, { section: 'Certificate', title: `Weak RSA key (${keyBits}-bit)`, severity: 'high', detail: 'Use a ≥2048-bit RSA (or EC) signing key.' });
        if (/CN=Android Debug/i.test(subject)) add(report, { section: 'Certificate', title: 'Signed with the Android debug certificate', severity: 'high', detail: 'A debug-signed APK must never be released.' });
        const notAfter = cert.validity?.notAfter;
        if (notAfter && notAfter.getTime() < Date.now()) add(report, { section: 'Certificate', title: 'Signing certificate expired', severity: 'medium', detail: 'notAfter ' + notAfter.toISOString() });
    }

    private scanSecrets(zip: Zip, report: AnalyzerReport, metaData: { name: string; value: string }[]): void {
        const urlSet = new Set<string>();
        const seen = new Set<string>();
        let budget = 150 * 1024 * 1024; // scanned-bytes budget

        const addSecret = (type: string, match: string, where: string, severity: Severity) => {
            const m = (match || '').slice(0, 120);
            const key = type + '|' + m;
            if (seen.has(key)) return; seen.add(key);
            if (report.secrets.length < 500) report.secrets.push({ type, match: m, where, severity });
        };

        // Value-pattern + URL scan over a chunk of text.
        const scanText = (text: string, where: string) => {
            if (!text) return;
            for (const p of SECRET_PATTERNS) {
                p.re.lastIndex = 0; let m: RegExpExecArray | null; let hits = 0;
                while ((m = p.re.exec(text)) && hits < 60) { hits++; addSecret(p.type, m[0], where, p.severity); }
            }
            URL_RE.lastIndex = 0; let u: RegExpExecArray | null; let uh = 0;
            while ((u = URL_RE.exec(text)) && uh < 800) {
                uh++;
                const url = u[0].replace(/[).,'"\\]+$/, '');
                if (url.length <= 180 && !/w3\.org|android\.com\/apk|schemas\.android|apache\.org\/xml|purl\.org|ns\.adobe/.test(url)) urlSet.add(url);
            }
        };

        // A named key→value pair (from strings.xml or manifest meta-data).
        const isFilePath = (v: string) => /^res\//i.test(v) || /\.(xml|png|jpe?g|webp|gif|ttf|otf|json|mp3|ogg|ttc)$/i.test(v);
        const isDottedIdent = (v: string) => /^[A-Za-z][A-Za-z0-9_$]*(\.[A-Za-z0-9_$]+)+$/.test(v); // class/package/constant
        const scanNamed = (name: string, value: string, where: string) => {
            if (!value) return;
            if (!isFilePath(value)) scanText(value, where + ':' + name);   // still catch AIza… etc. in the value
            if (!name || isFilePath(value) || isDottedIdent(value)) return;
            if (HIGH_NAME.test(name) && !/\s/.test(value) && value.length >= 4 && value.length <= 256 &&
                !/^[@#?]/.test(value) && !/^(true|false)$/i.test(value)) {
                addSecret('Named: ' + name, value, where, nameSeverity(name));
            }
        };

        // 1. Manifest <meta-data> (Maps/Facebook/etc. API keys live here).
        for (const m of metaData) scanNamed(m.name, m.value, 'manifest');

        // 2. Files: DEX string pools, resources.arsc (decoded), and text/native assets.
        for (const { entry, read } of zip.all()) {
            if (budget <= 0) break;
            const n = entry.name;
            if (/\.(png|jpe?g|webp|gif|bmp|ico|mp3|mp4|m4a|ogg|wav|ttf|otf|woff2?|eot)$/i.test(n)) continue; // skip media
            const buf = read(); if (!buf) continue;
            budget -= buf.length;
            if (n === 'resources.arsc') {
                const { values, named } = parseArsc(buf);
                for (const s of values) scanText(s, 'resources.arsc');
                for (const kv of named) scanNamed(kv.name, kv.value, 'strings');
            } else if (/\.dex$/i.test(n)) {
                scanText(extractStrings(buf), n);
            } else {
                scanText(extractStrings(buf, 5), n);
                if (/\.(xml|arsc)$/i.test(n) || /^res\//.test(n)) scanText(extractUtf16(buf), n);
            }
        }

        // Rank secrets by severity for display.
        report.secrets.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
        report.urls = [...urlSet].sort().slice(0, 500);
    }
}

function sevRank(s: Severity): number { return s === 'high' ? 3 : s === 'medium' ? 2 : s === 'low' ? 1 : 0; }
function add(report: AnalyzerReport, f: Finding): void { report.findings.push(f); }
