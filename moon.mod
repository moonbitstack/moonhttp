name = "moonbitstack/moonhttp"

version = "0.7.0"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonhttp"

license = "Apache-2.0"

keywords = [
  "http",
  "http3",
  "websocket",
  "hpack",
  "qpack",
  "protocol",
  "moonbit",
]

description = "moonhttp — the HTTP family for MoonBit: HTTP/3 framing, HPACK and QPACK header compression, WebSocket framing and its handshake, Server-Sent Events, multipart bodies and media types, each a package of its own. Bytes in, events out; no sockets."

preferred_target = "wasm-gc"

import {
  "moonbitstack/moonvar@0.1.0",
  "moonbitstack/mooncrypt@0.3.0",
  "moonbitstack/moonbase@0.4.0",
}
