# Hizn MCP server

`hizn-mcp` exposes Hizn's capabilities as [Model Context Protocol](https://modelcontextprotocol.io)
tools, so any MCP-compatible client can query and drive a running Hizn instance
— read the captured HTTP history, inspect scope and devices, scan APKs, resend
requests, run Intruder, and resolve held intercepts.

It speaks JSON-RPC 2.0 over **stdio**, has **no dependencies**, and talks to
Hizn's local REST API — so **Hizn must be running** (start the app, or
`npm start`).

## Build

```
npm run build
```

This compiles the server to `dist/mcp/mcp-server.js`.

## Register it with an MCP client

Most MCP clients read a JSON config listing their servers. Add an entry that
runs the compiled server:

```json
{
  "mcpServers": {
    "hizn": {
      "command": "node",
      "args": ["/absolute/path/to/hizn/dist/mcp/mcp-server.js"],
      "env": {
        "HIZN_API_URL": "http://127.0.0.1:4000",
        "HIZN_MCP_ACTIVE": "0"
      }
    }
  }
}
```

You can also run it directly for a quick check: `npm run mcp`.

## Configuration (environment)

| Variable          | Default                  | Meaning                                                        |
| ----------------- | ------------------------ | -------------------------------------------------------------- |
| `HIZN_API_URL`    | `http://127.0.0.1:4000`  | Base URL of the running Hizn API.                              |
| `HIZN_MCP_ACTIVE` | *(off)*                  | Set to `1` to also expose the **active** tools (see below).    |

## Tools

**Read-only** (always available):

- `hizn_status` — proxy status
- `list_flows` / `get_flow` — captured HTTP history
- `list_devices` / `list_device_apps` — ADB devices and installed apps
- `get_scope` — current target scope
- `get_intercept` — interception config + any held items
- `scan_apk` — static APK scan (local path, or pull from a device)

**Active** — only exposed when `HIZN_MCP_ACTIVE=1`, because they send traffic
or change Hizn's state:

- `start_proxy` / `stop_proxy`
- `send_request` — resend an HTTP(S) request (Repeater)
- `start_intruder` / `stop_intruder`
- `set_scope`
- `resolve_intercept` — forward/drop a held request or response

## Safety

The server binds to nothing itself — it only connects **out** to Hizn's local
API over stdio with its parent client. Keep `HIZN_MCP_ACTIVE` off unless you
explicitly want callers to be able to send traffic, launch Intruder, or forward
tampered intercepts. Treat anything a client drives through the active tools as
an action performed on your behalf.
