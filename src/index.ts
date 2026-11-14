/**
 * droidmitm entry point.
 *
 * Starts the local API + UI server. Open the printed URL in a browser, or let
 * the (future) Electron shell load it.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import * as path from 'path';
import { ApiServer } from './api/server';

const PORT = Number(process.env.DROIDMITM_PORT) || 4000;
const UI_DIR = path.resolve(__dirname, '../ui');

async function main() {
    const server = new ApiServer({ port: PORT, uiDir: UI_DIR });
    await server.start();
}

main().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('Fatal:', err);
    process.exit(1);
});
