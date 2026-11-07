---
name: moonhttp
description: "HTTP/1.1, HTTP/2, HTTP/3, WebSocket, SSE, cookies, forms and cache semantics for MoonBit, as values over bytes with no I/O; use it to read or write the octets of an HTTP message, frame or unframe a WebSocket, decide whether a stored response may be reused, or resolve conditional and range requests."
---

# moonhttp

```bash
moon add moonbitstack/moonhttp
```

Every package is imported on its own: `moonbitstack/moonhttp/http1`,
`http2`, `http3`, `ws`, `pmd`, `sse`, `cookie`, `cache` and the rest. Nothing
here opens a socket, reads a clock or spawns a task — a caller hands octets in
and takes values out, which is why the same code serves a client, a server and a
test.

## Read a message and write the answer

A message arrives as the octets a socket gave you; `request` answers the value
and how many octets it used, so whatever follows in the same read stays yours.

```moonbit
let wire = b"GET /notes/42 HTTP/1.1\r\nHost: example.com\r\n\r\n"
let (request, used) = @http1.request(wire) catch {
  e => abort(e.to_string())
}
assert_eq(request.verb, "GET")
assert_eq(request.target, "/notes/42")
assert_eq(used, 45)

let answer = @http1.Response::of(
  200,
  fields=[@header.Header::of("Content-Type", "text/plain")],
  body=@http1.Sized(2),
)
assert_eq(
  answer.encode(),
  b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\ncontent-length: 2\r\n\r\n",
)
```

## Drive a whole connection

`Conn` is the state machine for one connection at either end: octets in, events
out. It keeps what is left of a partial message, decides when a body ends, and
refuses what RFC 9112 says to refuse.

```moonbit
let conn = @http1.Conn::new(@http1.Server)
conn.receive(wire) catch {
  e => abort(e.to_string())
}
let event = conn.next() catch {
  e => abort(e.to_string())
}
assert_eq(event is @http1.Request(_), true)
let out = conn.send(@http1.Response(answer)) catch {
  e => abort(e.to_string())
}
assert_eq(out.length(), 64)
```

## A WebSocket message, compressed

Compression is `pmd`, the frames are `ws`, and RSV1 is the extension's — the
frame type has no bit for it, so it is set when the frame is written and read
back beside the frame.

```moonbit
let terms = @pmd.Extension::agree(
  @pmd.offers("permessage-deflate; client_max_window_bits"[:])[:],
).unwrap()
let (frame, compressed) = @pmd.Writer::new(extension=terms).frame(
  @ws.Opcode::Text,
  b"Hello"[:],
)
assert_eq(compressed, true)
assert_eq(frame.payload, b"\xf2H\xcd\xc9\xc9\x07\x00")

let octets = frame.encode_extension(rsv1=compressed)
let (back, used, rsv1) = @ws.decode_extension(octets[:], client=false).unwrap()
let reader = @pmd.Reader::new(extension=terms, role=@pmd.Role::Client)
let step = reader.feed(back, compressed=rsv1) catch {
  e => abort(e.to_string())
}
assert_eq(step.message, Some(@ws.Message::Text("Hello")))
assert_eq(used, octets.length())
```

## Decide whether a stored response may be reused

`cache` answers the four questions a cache asks and holds no store; `conditional`
answers what a 304 is owed; `range` resolves a range against a length.

```moonbit
let sent = @moondate.http("Sun, 06 Nov 1994 08:49:37 GMT")
let entry = @cache.Entry::read(
  status=200,
  headers=[("Cache-Control", "max-age=60")],
  request=[],
  sent~,
  received=sent,
)
assert_eq(entry.lifetime(), Some(60))
assert_eq(entry.verdict(request=@cache.control, presented=[], now=sent), @cache.Verdict::Serve)
```

## Rules that catch people out

- **No transport.** Bodies stay `Data` events and answers stay `Bytes`; sending
  them, and how, belongs to whoever owns the socket. A stream written as one body
  is not a stream.
- **Two readings of an event stream.** `sse.decode` gives the frames as written;
  `sse.events` gives what an `EventSource` dispatches — no event for a frame
  without data, `message` as the default type, the id and re-ty carried across
  frames.
- **Every bound is an argument** with the mainstream default: `http1.limits`
  (head, field count), `pmd.Reader(limit=)` for what one compressed message may
  expand to, `form.parse(limits=, strict=)`. A bound that is passed reads
  `Exceeded(limit~, got~)`.
- **`strict` is off by default** where being told is a policy rather than a rule:
  a request that carries no form is an empty form, and a truncated upload gives up
  the parts it read.
- **A refusal names where.** `Refused` carries `at` for the offset, `got` and
  `want` for what was seen, and `status()` for the status an HTTP/1.1 answer owes.
- **HTTP/3 faults close the connection**, so every refusal there carries the
  `Code` to close with: `e.code()`.
- **Limits do not cover bodies.** `http1` hands a body over as it arrives; if a
  body must be small, that is the caller's check.
