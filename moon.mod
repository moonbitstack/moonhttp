name = "moonbitstack/moonhttp"

version = "0.12.1"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonhttp"

license = "Apache-2.0"

keywords = [
  "http",
  "url",
  "etag",
  "http3",
  "websocket",
  "hpack",
  "qpack",
  "protocol",
  "moonbit",
]

description = "moonhttp — the HTTP family for MoonBit: URI references and percent coding, conditional requests and entity-tags, range requests, HTTP/1.1, HTTP/2 and HTTP/3 framing, HPACK and QPACK header compression, WebSocket framing and its handshake, Server-Sent Events, cookies, data URLs, multipart bodies and media types, each a package of its own. Bytes in, events out; no sockets."

preferred_target = "wasm-gc"

import {
  "moonbitstack/moonvar@0.2.0",
  "moonbitstack/moondate@0.1.0",
  "moonbitstack/mooncrypt@0.3.1",
  "moonbitstack/moonbase@0.4.0",
}
