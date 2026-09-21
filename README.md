# moonhttp

The HTTP family for MoonBit: the formats a request and a response are written
in, with nothing about sockets in them.

```moonbit
// An event stream, one frame at a time.
@sse.Event::new(data="{\"seq\":1}", kind=Some("tick"), id=Some("1")).encode()
@sse.decode(received[:])

// A posted form, whichever way the browser encoded it.
let form = @mime.parse(body[:], content_type[:])
form.field("name")
form.file("avatar")
```

Run `moon run examples/tour` for the whole surface in one go.

## Packages

| Package | What | Specification |
|:--:|:--|:--|
| `sse` | Server-Sent Events, both directions | WHATWG HTML, the event-stream format |
| `mime` | `multipart/form-data` and `application/x-www-form-urlencoded` | RFC 7578, WHATWG URL §5.1 |

## Framing, not transport

Nothing here opens a connection or writes to one. `sse` turns an event into the
bytes of a frame and back; sending each frame as its own chunk is the server's
job, and it matters — a stream delivered as one body is not a stream, because a
client dispatches an event only when it reads that event's blank line.

`mime` reads a body that has already arrived. Both of its encodings are bounded
by a `Limits` the caller sets, because the body came from whoever sent it: a
million empty parts and one enormous part are two ways of asking a server to
allocate more than it has. A form over its bounds is refused whole, not
truncated — a handler given the first thousand parts of a larger form would be
answering a request nobody sent.

## What is checked

`sse` is measured against the two example streams the WHATWG specification
prints, which are the cases an implementation that trims too much or too little
gets wrong; then every frame it writes is read back as the event that wrote it,
the exact bytes of each frame are pinned, all three line endings are accepted,
and the things a reader must ignore rather than refuse are ignored.

`mime` is measured against a `multipart/form-data` body written the way a
browser writes one — repeated names, a file with its own headers, the trailing
CRLF that belongs to the delimiter and not the content — and against the
percent-encoding edges, including a stray `%` that is not an escape and the `+`
that is a space in a form body and nowhere else.

## What is not here yet

HTTP/1.1 message framing, HTTP/2 with HPACK, HTTP/3 with QPACK, WebSocket
framing, content negotiation, cookies, ranges, caching and conditional requests.
They are planned in that order; the tracking list lives with the project.

TLS is `moontls` and QUIC is `moonquic`, so that parsing an HTTP message does
not mean carrying a handshake. Compression is `moonzip`.

## Install

```bash
moon add moonbitstack/moonhttp
```

## Licence

Apache-2.0.
