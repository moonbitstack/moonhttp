name = "moonbitstack/moonhttp"

version = "0.4.0"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonhttp"

license = "Apache-2.0"

keywords = [
  "http",
  "websocket",
  "sse",
  "multipart",
  "mime",
  "protocol",
  "moonbit",
]

description = "moonhttp — the HTTP family for MoonBit: WebSocket framing and its handshake, Server-Sent Events, multipart and URL-encoded bodies, and media types, each a package of its own. Bytes in, events out; no sockets."

preferred_target = "wasm-gc"

import {
  "moonbitstack/mooncrypt@0.3.0",
  "moonbitstack/moonbase@0.4.0",
}
