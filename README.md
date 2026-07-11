# web-fetch-mcp

A feature-rich MCP server exposing a `fetch` tool over the Streamable HTTP
transport. Built on `rmcp` 0.16 + axum + reqwest.

Feature parity with [opencode's built-in webfetch](https://github.com/anomalyco/opencode) plus additional security features.

## Build

Requires **Rust 1.85+**:

```bash
cargo build
```

## Run

```bash
cargo run --release
# -> web-fetch-mcp listening at http://127.0.0.1:8080/mcp
```

Config via env vars:

- `BIND_ADDR` (default `127.0.0.1:8080`)
- `RESPECT_ROBOTS` (default `true`; set `false` to skip robots.txt checks)

## Use with opencode

Add to `opencode.json`:

```json
{
  "mcp": {
    "web-fetch": {
      "type": "remote",
      "url": "http://127.0.0.1:8080/mcp",
      "enabled": true
    }
  }
}
```

Then run the server (`cargo run --release`) and start opencode.

## Tool parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `url` | string | (required) | The URL to fetch. HTTP auto-upgraded to HTTPS. |
| `format` | `"text"` \| `"markdown"` \| `"html"` | `"markdown"` | Output format |
| `max_length` | integer | `5000` | Max characters returned per call |
| `start_index` | integer | `0` | Character offset for pagination |
| `timeout` | integer | `30` | Request timeout in seconds (max 120) |

## Features

- **3 output formats**: markdown (default), plain text, raw HTML
- **Pagination**: `start_index` / `max_length` for large pages
- **SSRF protection**: blocks loopback, private, link-local (169.254.169.254), multicast IPs
- **Redirect re-validation**: SSRF + robots.txt checked on every hop
- **robots.txt compliance**: best-effort prefix-match `Disallow` for `*` user-agent
- **Cloudflare bypass**: retries with honest UA on `cf-mitigated: challenge` 403
- **User-Agent spoofing**: Chrome 143 UA for better compatibility
- **Accept header negotiation**: format-aware with q-value fallbacks
- **Image support**: returns images as base64 data URIs
- **MIME detection**: broad textual MIME support (JSON, XML, JS, YAML, SVG as text)
- **5 MB body cap**: streamed with eager Content-Length check
- **HTTP→HTTPS upgrade**: automatically upgrades insecure requests

## Test it

```bash
# Start the server
cargo run --release &

# Initialize MCP session
curl -i http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": {"name": "curl-test", "version": "0.1"}
    }
  }'

# Grab Mcp-Session-Id header, then call the tool:
curl -i http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Session-Id: <session-id>' \
  -d '{
    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
    "params": {"name": "fetch", "arguments": {"url": "https://example.com", "format": "markdown"}}
  }'
```

## Out of scope

- PDF/binary content extraction (returns "binary, not shown" message)
- Caching / rate limiting per-host
- OAuth or auth on the MCP endpoint (binds to 127.0.0.1 by default)
- Cookie/session persistence across fetch calls
