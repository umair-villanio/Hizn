/**
 * hizn Electron main process.
 *
 * Boots the compiled API + UI server in-process on a free loopback port, then
 * opens a desktop window pointed at it. No terminal, no browser tab — just the
 * app. The backend (ADB, mockttp, Frida) runs inside this same Node process.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

'use strict';

const { app, BrowserWindow, Menu, shell, dialog } = require('electron');
const path = require('path');
const net = require('net');

/** Find an available loopback TCP port the server can bind to. */
function findFreePort() {
    return new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.on('error', reject);
        srv.listen(0, '127.0.0.1', () => {
            const { port } = srv.address();
            srv.close(() => resolve(port));
        });
    });
}

let mainWindow = null;
let serverUrl = null;

/** Boot the backend. Returns the base URL the window should load. */
async function startBackend() {
    // Compiled output lives in ../dist relative to this file.
    const { ApiServer } = require(path.join(__dirname, '..', 'dist', 'api', 'server'));
    const uiDir = path.join(__dirname, '..', 'ui');
    const port = await findFreePort();
    const server = new ApiServer({ port, uiDir });
    await server.start();
    return `http://127.0.0.1:${port}`;
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1180,
        height: 820,
        minWidth: 900,
        minHeight: 640,
        backgroundColor: '#0e1116',
        title: 'Hizn',
        autoHideMenuBar: true,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
    });

    // Open external links (docs, GitHub) in the real browser, not in-app.
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        if (/^https?:\/\/127\.0\.0\.1/.test(url)) return { action: 'allow' };
        shell.openExternal(url);
        return { action: 'deny' };
    });

    mainWindow.loadURL(serverUrl);
    mainWindow.on('closed', () => { mainWindow = null; });
}

// Minimal menu: keep the essentials (copy/paste, reload, devtools, quit).
function buildMenu() {
    const isMac = process.platform === 'darwin';
    const template = [
        ...(isMac ? [{ role: 'appMenu' }] : []),
        {
            label: 'File',
            submenu: [isMac ? { role: 'close' } : { role: 'quit' }],
        },
        { role: 'editMenu' },
        {
            label: 'View',
            submenu: [
                { role: 'reload' },
                { role: 'forceReload' },
                { role: 'toggleDevTools' },
                { type: 'separator' },
                { role: 'resetZoom' },
                { role: 'zoomIn' },
                { role: 'zoomOut' },
                { type: 'separator' },
                { role: 'togglefullscreen' },
            ],
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'hizn on GitHub',
                    click: () => shell.openExternal('https://github.com/'),
                },
                {
                    label: 'About',
                    click: () => dialog.showMessageBox(mainWindow, {
                        type: 'info',
                        title: 'About Hizn',
                        message: 'Hizn',
                        detail: 'One-click Android traffic interception with optional Burp chaining.\nAGPL-3.0-only.',
                    }),
                },
            ],
        },
    ];
    Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// Single-instance lock — focus the existing window instead of opening a second.
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
    app.quit();
} else {
    app.on('second-instance', () => {
        if (mainWindow) {
            if (mainWindow.isMinimized()) mainWindow.restore();
            mainWindow.focus();
        }
    });

    app.whenReady().then(async () => {
        try {
            serverUrl = await startBackend();
        } catch (err) {
            dialog.showErrorBox(
                'hizn failed to start',
                'The backend could not start:\n\n' + (err && err.stack ? err.stack : String(err)),
            );
            app.quit();
            return;
        }
        buildMenu();
        createWindow();

        app.on('activate', () => {
            if (BrowserWindow.getAllWindows().length === 0) createWindow();
        });
    });

    app.on('window-all-closed', () => {
        if (process.platform !== 'darwin') app.quit();
    });
}
