/**
 * hizn preload.
 *
 * The UI talks to the backend purely over HTTP + WebSocket on the same origin,
 * so it needs no Node privileges. We expose only a tiny read-only marker the UI
 * can use to tell "running inside the desktop shell" from "opened in a browser".
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

'use strict';

const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('hizn', {
    desktop: true,
    platform: process.platform,
    versions: {
        electron: process.versions.electron,
        chrome: process.versions.chrome,
        node: process.versions.node,
    },
});
