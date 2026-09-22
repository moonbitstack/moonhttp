# moonhttp

The HTTP family for MoonBit: the formats a request and a response are written
in, with nothing about sockets in them.

```moonbit
// An event stream, one frame at a time.
@sse.Event::new(data="{\"seq\":1}", kind="tick", id="1").encode()
@sse.decode(received[:])  // the frames as written
@sse.events(received[:])  // what an EventSource dispatches from them

// A cookie set on the way out and read on the way back.
@cookie.Cookie::new("sid", token, http_only=true, secure=true).encode()
@cookie.get(request_header[:], "sid"[:])

// A posted form, whichever way the browser encoded it.
let form = @mime.parse(body[:], content_type[:])
form.field("name")
form.file("avatar")
```

Run `moon run examples/tour` for the whole surface in one go. The eleven worked
examples run a package each:

```
moon run examples/04-ws-handshake   moon run examples/08-qpack-dynamic
moon run examples/05-ws-frame       moon run examples/09-http3-frames
moon run examples/06-qpack-primitives   moon run examples/10-http3-message
moon run examples/07-qpack-field    moon run examples/11-http3-conn
```

## Packages

| Package | What | Specification |
|:--:|:--|:--|
| `sse` | Server-Sent Events, both directions | WHATWG HTML, the event-stream format |
| `mime` | `multipart/form-data` and `application/x-www-form-urlencoded`, and percent-encoding both ways | RFC 7578, WHATWG URL §5.1, RFC 3986 |
| `media` | What a response says its body is, and under what name to save it | RFC 9110 §8.3, RFC 6266 |
| `cookie` | `Cookie` and `Set-Cookie`, each read and written | RFC 6265, and its revision for `SameSite` |
| `ws` | WebSocket framing: opcodes, masking, fragment reassembly, close statuses | RFC 6455 §5, §7.4.1 |
| `upgrade` | The WebSocket opening handshake, both sides | RFC 6455 §4 |
| `huffman` | The Huffman code both header compressions use | RFC 7541 Appendix B |
| `header` | A header field: a name and a value, as octets | RFC 9110 §5 |
| `hpack` | HTTP/2 header compression: both tables, both ends | RFC 7541 |
| `qpack` | HTTP/3 header compression: both tables, the field lines, both instruction streams | RFC 9204 |
| `http1` | HTTP/1.1 messages: the request and status lines, field lines, body framing and the chunked coding | RFC 9112 |
| `http2` | HTTP/2 framing: the nine-octet header, all ten frame types, the connection preface | RFC 9113 |
| `http3` | HTTP/3 frames, their placement rules, settings, stream types and connection | RFC 9114 |

## One vocabulary

The same word means the same thing in every package here, and in every other
package the organisation publishes. `encode` and `decode` are a pair, and
`parse` is for a format with no symmetric writer. `code` is an enum's value on
the wire, so a WebSocket close status is `status` and never `code`. A limit
passed is `Exceeded(limit~, got~)`, a predicate reads as an adjective or is
named `is_`, and a refusal is `Refused`.

## Configuration

Every bound and every leniency is an argument, and every default is the one the
mainstream uses.

```moonbit
// A bound belongs to an endpoint. Either form names one.
let small = @mime.Limits::new(parts=8, part_size=64 * 1024)
let same = { ..@mime.limits, parts: 8, part_size: 64 * 1024 }

@mime.parse(body[:], content_type[:], limits=small)

// By default a body that is not a form is an empty form, and a multipart body
// that stops making sense gives up the parts it read. `strict` says so instead.
@mime.parse(body[:], content_type[:], strict=true)   // raises NotAForm
@mime.multipart(body[:], edge[:], strict=true)       // raises Malformed(at~)

@sse.Event::of("hello").encode(space=false)          // drop the optional space
```

| Setting | Default | Why that one |
|:--:|:--:|:--|
| `limits.parts` | 1000 | Starlette's `max_files` and `max_fields` |
| `limits.part_size` | 1 MiB | python-multipart's in-memory part size |
| `strict` | off | A truncated upload is ordinary on a dropped connection, and "this request carried no form" is an answer rather than a failure. On is for the caller who would rather be told |
| `space` | on | The space after a colon is optional in the format and universal on the wire; a reader strips it either way |

`Limits` has no per-call mirror, and therefore no precedence rule. A bound
belongs to an endpoint rather than to a request — an avatar upload and a
spreadsheet import are two endpoints, each with its own — so the record is the
only place it comes from and there is nothing to arbitrate. Where a setting can
arrive from two places, as in `mooncred`, the precedence is published with it.

## Downloads

Naming a download is a question about a format, not about a framework: the
answer is the same whether the bytes came from a file, a database or a
generator. So it lives here rather than in whatever is serving them.

```moonbit
@media.type_of("report.pdf")                      // "application/pdf"
@media.disposition("my report.pdf")               // filename*=utf-8''my%20report.pdf
@media.disposition("cover.png", inline=true)      // display it, do not save it
```

A name that survives percent-encoding unchanged is quoted as it is; anything
else — a space, an accent, a quote, a newline — goes out as RFC 6266's
`filename*`, which is the only form that can carry a character outside ASCII and
the only one a name cannot break out of.

Text types carry `charset=utf-8`, because a browser handed `text/plain` with no
charset applies its own locale's and shows something else.

**Still to come for a complete download**: `Range` and `Content-Range`
(RFC 9110 §14), which is what resumable downloads and media seeking need, and
conditional requests. Reading the file and sending it in pieces is the server's,
not this library's — there are no sockets here.

## Framing, not transport

Nothing here opens a connection or writes to one. `sse` turns an event into the
bytes of a frame and back; sending each frame as its own chunk is the server's
job, and it matters — a stream delivered as one body is not a stream, because a
client dispatches an event only when it reads that event's blank line.

A client wants the second of `sse`'s two readings. `decode` answers each frame as
written; `events` answers what a browser's `EventSource` hands its listeners —
no event for a frame without data, the type defaulting to `message`, and the id
and reconnection delay carried from frame to frame as the stream's own state.

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
and the things a reader must ignore rather than refuse are ignored. `events` is
read against the same streams, and each rule by which it differs from `decode`
is checked by a test that turns red when the rule is removed.

`mime` is measured against a `multipart/form-data` body written the way a
browser writes one — repeated names, a file with its own headers, the trailing
CRLF that belongs to the delimiter and not the content — and against the
percent-encoding edges, including a stray `%` that is not an escape and the `+`
that is a space in a form body and nowhere else.

`hpack` is measured against all twelve worked examples of RFC 7541 Appendix C, in
both directions: the encoder reproduces the published blocks octet for octet and
the decoder reproduces the published header lists, with the three requests of a
series sharing one dynamic table and the three responses evicting under a
256-octet ceiling. `huffman` is measured against the coded strings those same
blocks contain.

`http3` is measured section by section: every frame type round-trips, every
placement rule of §7.2 is checked on each of the three stream kinds, the
settings and the unidirectional stream types round-trip, and a request stream
decodes into its pseudo-headers, its fields and its body.

`qpack` is measured against the instruction vectors of RFC 9204 Appendix B and,
section by section, against every representation §4.5 defines — indexed and
post-base, relative and absolute, with a name reference and with a literal name.

`ws` is measured against all five frames RFC 6455 §5.7 prints: the unmasked and
masked text messages, the fragmented one, the ping with its pong, and the two
long length forms. `upgrade` is measured against the key and proof §1.3 prints,
which is the one computation in it.

## What is not here yet

Content negotiation, ranges, caching and conditional requests. They are planned in
that order; the tracking list lives with the project.

The variable-length integers are not here either. HTTP/3's frames are counted in
QUIC's varint and both header compressions count in RFC 7541's prefixed integer;
neither belongs to HTTP, and both are written in more than one protocol. They
are `moonvar`, which this depends on and which depends on nothing.

TLS is `moontls` and QUIC is `moonquic`, so that parsing an HTTP message does
not mean carrying a handshake. Compression is `moonzip`.

## Install

```bash
moon add moonbitstack/moonhttp
```

## Licence

Apache-2.0.
