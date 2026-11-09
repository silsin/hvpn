# Share links (`akbar://`)

Users never edit config files. The server prints one **link**; users paste it
into the HVPN app (or scan it as a QR code) and the app connects.

```
akbar://v1/<connection-string>
```

`<connection-string>` is the existing base64url (no padding) encoding of this
JSON, produced by `hvpn-server --init`:

```json
{
  "server": "203.0.113.10",
  "port": 443,
  "pubkey": "<64 hex chars: server X25519 public key>",
  "version": 1,
  "auth_secret": "<64 hex chars: shared secret for connection tokens>",
  "cert_sha256": "<optional, 64 hex chars: SHA-256 of the server's DER certificate>"
}
```

* `cert_sha256` (optional) makes the client **pin** the server certificate, so
  a man-in-the-middle with any other certificate is rejected. Links without it
  still work but the client logs a warning and accepts any certificate.
* The server logs its fingerprint at startup
  (`TLS certificate SHA-256 (for client pinning)`), so an existing deployment
  can add `cert_sha256` to its connection string.

## What the client accepts

All of these import the same server:

| Input | Example |
|---|---|
| Link | `akbar://v1/eyJ…` |
| Link without version | `akbar://eyJ…` |
| Alternate scheme | `hvpn://v1/eyJ…` |
| Bare connection string | `eyJ…` |

Surrounding whitespace and a trailing `/` are ignored. Re-importing a link for
the same `server:port` updates the existing entry instead of duplicating it.

## Where links are used

* **Tray wizard / "Paste" tab / QR scan** – accepts any form above.
* **Command line** – `hvpn-client --link "akbar://v1/…"` saves the server,
  selects it, and connects.
* **Settings → Share link** – shows the link for a saved server.

## Security notes

* The link contains the server's auth secret. **Anyone with the link can use
  the server.** Share it only with people you trust.
* The `server` field is validated as a plain hostname / IP address before use,
  because it is later passed to `route` / `netsh`.
* Server names shown in the UI are rendered as text, never as HTML.
