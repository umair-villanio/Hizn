# Hizn MCP server

`hizn-mcp` exposes Hizn's capabilities as [Model Context Protocol](https://modelcontextprotocol.io)
tools, so any MCP-compatible client can query and drive a running Hizn instance
— read the captured HTTP history, inspect scope and devices, scan APKs, resend
requests, run Intruder, and resolve held intercepts.

It speaks JSON-RPC 2.0 over **stdio**, is a small self-contained binary, and
talks to Hizn's local REST API — so **Hizn must be running** (start the desktop
app, or `cargo run -p hizn-server`).

## Build

```
cargo build --release -p hizn-mcp
```

This produces the `hizn-mcp` binary at `target/release/hizn-mcp`
(`hizn-mcp.exe` on Windows).

## Register it with an MCP client

Most MCP clients read a JSON config listing their servers. Add an entry that
runs the binary:

```json
{
  "mcpServers": {
    "hizn": {
      "command": "/absolute/path/to/target/release/hizn-mcp",
      "env": {
        "HIZN_API_URL": "http://127.0.0.1:4000",
        "HIZN_MCP_ACTIVE": "0"
      }
    }
  }
}
```

On Windows use the full path to `hizn-mcp.exe`. You can also run it directly for
a quick check: `cargo run -p hizn-mcp`.

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
