# Hizn Plugins

Burp-style installable extensions. Drop a `.js` file in a plugins folder and it
shows up in **Plugins → list**. There are two kinds:

- **Message plugins** (default) — enable one to get a tab in the **Intercept**
  panel that renders extra info about the held request/response. It is the body
  of a function that receives `ctx` and returns a string (see below).
- **Extension plugins** — declare `// @kind extension` in the header. These are
  fully flexible: they run once at load, receive a `hizn` API, and can add new
  **rail tabs**, inject **buttons** into existing toolbars, hook **live
  traffic**, call Hizn's API, and store state. See *Extension plugins* below.

## Extension plugins (flexible: tabs / buttons / live hooks)

Add `// @kind extension` to the header. The file runs once and receives `hizn`:

```js
// @name   Site Map
// @kind   extension

hizn.registerTab({ id: 'sitemap', title: 'Site Map', icon: '◳',
  render(container) { container.innerHTML = '<h3>My tab</h3>'; } });

hizn.registerButton({ location: 'history-detail', label: '⎘ Copy as fetch()',
  onClick(flow) { /* flow = the selected request */ } });

hizn.onFlow(f => { /* called on every captured request, live */ });
```

### `hizn` API

| Member | What it does |
| --- | --- |
| `registerTab({id,title,icon,render(el)})` | Adds a left-rail tab + view; `render` fills the view element. |
| `registerButton({location,label,title,onClick(ctx)})` | Adds a button. `location`: `history-detail`, `intercept-actions`, or `repeater`; `ctx` is the current request there. |
| `onFlow(fn)` | Calls `fn(flow)` on every newly captured request. |
| `api(path, opts)` | Calls Hizn's REST API (e.g. `api('/repeater/send', {method:'POST', body})`). |
| `storage.get(k)` / `storage.set(k,v)` | Per-plugin persistent key/value. |
| `banner(msg)` / `switchTo(tabId)` / `esc(s)` | Toast, switch to your tab, HTML-escape. |

Disable or delete the plugin and all its tabs/buttons/hooks are removed
automatically. `sitemap.js` in this folder is a working sample.

---

## Message plugins

## Language

**JavaScript** — one file, one plugin. No build step, no SDK. (The whole stack
is TypeScript/Node, so plugins are plain JS evaluated in the app.)

## Plugin file format

A plugin file is the **body of a function** that receives `ctx` and returns a
string (plain text or HTML). Metadata lives in `// @field` comments at the top:

```js
// @name        Headers Table
// @description Renders all request headers as a table
// @version     1.0.0
// @author      yourname

const rows = Object.entries(ctx.headers || {})
    .map(([k, v]) => `<tr><td><b>${k}</b></td><td>${v}</td></tr>`)
    .join('');
return `<table>${rows}</table>`;
```

Everything after the headers runs as the function body — use `return` to produce
the output shown in the plugin's Intercept tab.

## The `ctx` object

| Field           | Type                | Contents                                        |
|-----------------|---------------------|-------------------------------------------------|
| `ctx.kind`      | `'request'\|'response'` | Which message is being viewed                |
| `ctx.method`    | `string`            | `GET`, `POST`, … (requests)                     |
| `ctx.url`       | `string`            | Full URL                                        |
| `ctx.statusCode`| `number`            | HTTP status (responses)                         |
| `ctx.headers`   | `object`            | Header name → value                             |
| `ctx.body`      | `string`            | Decoded body text (may be large)                |
| `ctx.raw`       | `string`            | The raw message as shown in the editor          |

Return value:

- String containing `<` → injected as HTML (inline `<style>`/classes ok;
  `jwt-seg`, `jwt-head`, `jwt-payload`, `jwt-sig` classes exist for reuse)
- Anything else → shown inside `<pre>` (auto-escaped is NOT applied, so escape
  untrusted body text yourself if you inject it into HTML)

## Install paths

| Location            | Path                            | Notes                          |
|---------------------|---------------------------------|--------------------------------|
| Community plugins   | `<repo>/plugins/`               | Ships with the app — PR here!  |
| User plugins        | `~/.hizn/plugins/`              | Your local installs, writable  |

Or install straight from the app: **Plugins → + Add** → paste code or pick a
`.js` file.

## Contributing

1. Write `<name>.js` in this folder (copy `jwt-decoder.js` as a template)
2. Test it: drop it in `~/.hizn/plugins/`, enable in Plugins, open an Intercept
   item and click its tab
3. PR it — keep plugins self-contained (no network calls, no npm deps)

## Ideas

- GraphQL introspection formatter
- AWS Signature / `Authorization` header analyzer
- Multipart body explorer
- Protobuf/Base64 nested-field decoder
- Security-header linter for responses
