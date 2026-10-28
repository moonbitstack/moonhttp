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
let form = @form.parse(body[:], content_type[:])
form.field("name")
form.file("avatar")

// A second request for something that has not changed.
let etag = @conditional.hash(body[:], digest=@sha2.Hasher::new())
@conditional.Ask::read(headers[:]).evaluate(verb="GET", etag~)  // Go | Fresh | Failed

// A WebSocket message compressed the way RFC 7692 asks, and the bit that says so.
let terms = @pmd.Extension::agree(@pmd.offers(offer[:])[:]).unwrap()
let (frame, compressed) = @pmd.Writer::new(extension=terms).frame(@ws.Opcode::Text, body[:])
frame.encode_extension(rsv1=compressed)  // one deflate segment, tail stripped

// A stored response, and what may be done with it.
let stored = @cache.Entry::read(status=200, headers, request, sent~, received~)
stored.verdict(request=@cache.control, presented=headers, now~)  // Serve | Validate | Miss
stored.conditional()  // the If-None-Match a cache sends instead

// And where a 302 sends the request next.
@client.follow(status=302, location="/next", from~, verb=@method.Method::Post, visited=[from][:])
```

Run `moon run src/examples/tour` for the whole surface in one go. The worked
examples run a package each:

```
moon run src/examples/04-ws-handshake       moon run src/examples/09-http3-frames
moon run src/examples/05-ws-frame           moon run src/examples/10-http3-message
moon run src/examples/06-qpack-primitives   moon run src/examples/11-http3-conn
moon run src/examples/07-qpack-field        moon run src/examples/12-range
moon run src/examples/08-qpack-dynamic      moon run src/examples/13-conditional
moon run src/examples/14-ws-compressed      moon run src/examples/15-cache
```

`src/examples/16-ws-echo` is the other kind: a server, not a walkthrough. It
serves `ws://127.0.0.1:9001` with this library's handshake, frames and
compression over a socket from `moonbitlang/async`, which is what
`scripts/autobahn/run.sh` runs Autobahn against.

The API reference is generated from the sources' doc comments:
[moonbitstack.github.io/moonhttp](https://moonbitstack.github.io/moonhttp).

## Packages

| Package | What | Specification |
|:--:|:--|:--|
| `sse` | Server-Sent Events, both directions | WHATWG HTML, the event-stream format |
| `form` | A request body read as the form its `Content-Type` says it is, `multipart/form-data` or `application/x-www-form-urlencoded` | WHATWG HTML form submission |
| `range` | Asking for part of a representation: the fields, the arithmetic that resolves a range against a length, and the multi-range body | RFC 9110 §14 |
| `conditional` | Entity-tags, the five precondition fields, and the order they are weighed in | RFC 9110 §8.8, §13 |
| `cache` | What may be stored, how long it stays fresh, how old it is, and whether it may answer: the decisions, with no store | RFC 9111 |
| `client` | Where a redirect sends a request, with which method and which credentials; and `Alt-Svc` read into the alternatives it names | RFC 9110 §15.4, RFC 7838 |
| `cookie` | `Cookie` and `Set-Cookie`, each read and written | RFC 6265, and its revision for `SameSite` |
| `ws` | WebSocket framing: opcodes, masking, fragment reassembly, close statuses | RFC 6455 §5, §7.4.1 |
| `pmd` | The permessage-deflate extension: its four parameters, the offer and the answer, and a reader and writer over `ws` frames | RFC 7692 |
| `deflate` | Raw DEFLATE shaped for a stream that outlives a message: a window carried across messages, and a ceiling on what one may expand to | RFC 1951 |
| `upgrade` | The WebSocket opening handshake, both sides | RFC 6455 §4 |
| `huffman` | The Huffman code both header compressions use | RFC 7541 Appendix B |
| `method` | The request method: the nine standard ones and any other token, with whether each is safe and idempotent | RFC 9110 §9, RFC 5789 |
| `header` | A header field: a name and a value, as octets | RFC 9110 §5 |
| `hpack` | HTTP/2 header compression: both tables, both ends, and a bound on the list a block decodes to | RFC 7541 |
| `qpack` | HTTP/3 header compression: both tables, the field lines, both instruction streams | RFC 9204 |
| `http1` | HTTP/1.1 messages: the request and status lines, field lines, body framing and the chunked coding; `Conn`, a whole connection for either end on h11's state machine, octets in and events out | RFC 9112 |
| `http2` | HTTP/2 framing: the nine-octet header, all ten frame types, the connection preface; `Conn`, a whole connection for either end after python-hyper h2, with stream states, flow control, settings, push and field validation | RFC 9113, RFC 8441 |
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
let small = @moonmime.Limits::new(parts=8, part_size=64 * 1024)
let same = { ..@moonmime.limits, parts: 8, part_size: 64 * 1024 }

@form.parse(body[:], content_type[:], limits=small)

// By default a body that is not a form is an empty form, and a multipart body
// that stops making sense gives up the parts it read. `strict` says so instead.
@form.parse(body[:], content_type[:], strict=true)   // raises NotAForm, or Malformed(at~)

@sse.Event::of("hello").encode(space=false)          // drop the optional space

// A compressed message is the one place a peer can ask for memory it did not
// pay for, so the reader bounds what one expands to, in octets.
@pmd.Reader::new(limit=1 * 1024 * 1024)

// And a writer can leave a message under this many octets alone, which is worth
// doing: a compressed "OK" is longer than "OK".
@pmd.Writer::new(threshold=64)
```

| Setting | Default | Why that one |
|:--:|:--:|:--|
| `limits.parts` | 1000 | Starlette's `max_files` and `max_fields` |
| `limits.part_size` | 1 MiB | python-multipart's in-memory part size |
| `strict` | off | A truncated upload is ordinary on a dropped connection, and "this request carried no form" is an answer rather than a failure. On is for the caller who would rather be told |
| `space` | on | The space after a colon is optional in the format and universal on the wire; a reader strips it either way |
| `limit` (`pmd`) | 16 MiB | The ceiling `ws` puts on a message anyway. RFC 7692 sets none, and a compressed message is where that absence would cost the most |
| `threshold` (`pmd`) | 0 | Every message compressed, which is what agreeing to the extension means. A caller compressing a bulletin board and not a chat box raises it |

`Limits` has no per-call mirror, and therefore no precedence rule. A bound
belongs to an endpoint rather than to a request — an avatar upload and a
spreadsheet import are two endpoints, each with its own — so the record is the
only place it comes from and there is nothing to arbitrate. Where a setting can
arrive from two places, as in `mooncred`, the precedence is published with it.

## Downloads

A download needs three answers, and each comes from its own place: what the body
is and under what name to save it is [moonmime](https://github.com/moonbitstack/moonmime)'s
`guess_type` and `content_disposition`; resuming it and seeking in it is `range`;
not sending it again is `conditional`. Reading the file and sending it in pieces
is the server's, not this library's — there are no sockets here.

## Framing, not transport

Nothing here opens a connection or writes to one. `sse` turns an event into the
bytes of a frame and back; sending each frame as its own chunk is the server's
job, and it matters — a stream delivered as one body is not a stream, because a
client dispatches an event only when it reads that event's blank line.

A client wants the second of `sse`'s two readings. `decode` answers each frame as
written; `events` answers what a browser's `EventSource` hands its listeners —
no event for a frame without data, the type defaulting to `message`, and the id
and reconnection delay carried from frame to frame as the stream's own state.

`form` reads a body that has already arrived. Both of its encodings are bounded
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

`form` is measured on both encodings by content type, upper case and a charset
parameter included, on what `strict` turns into an error, and on one bound
holding for both. The decoders behind it are measured where they live:
moonmime against a browser's multipart body, moonurl against the parser and
serialiser cases of web-platform-tests.

`conditional` follows §13, which states rules rather than printing vectors: the
comparison table of §8.8.3.2 entry for entry, then §13.2.2's steps one at a
time, then against each other — the order is the part that gets got wrong. The
content tag is pinned to SHA-256's vector for `hello`.

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

`deflate` is read against streams zlib wrote, because those are the ones a
WebSocket endpoint actually meets: messages at every length where DEFLATE or the
frame layer changes shape, a stored block, a dynamic block, a window negotiated
down to nine bits, and four messages that only decode if the window of the first
survives into the last. The other direction is checked by giving what it writes to
another DEFLATE implementation to read. Every split of a compressed message is
read as two pieces, which is what a message arriving in fragments is.

`pmd` is measured on §7.1's four parameters — read, written and negotiated, each
with the values the grammar forbids — and then against Autobahn, whose 12.x and
13.x groups are the conformance suite for this extension: `scripts/autobahn/run.sh`
starts the endpoint and points the fuzzingclient at it, and CI runs it. The same
behaviours are replayed frame by frame in the unit tests, and
`scripts/autobahn/interop.py` is the check that needs no Docker: a permessage-deflate
client written against zlib, which is what a browser is.

`cache` follows §4.2.1's order for a freshness lifetime, §4.2.2's tenth, §4.2.3's
arithmetic on four clock readings, §3's list of reasons not to store — each as a
test that would pass if the rule were dropped — and §4's list of reasons not to
reuse, including the ones a `Vary` mismatch and a disconnect turn on. The
cache-tests suite's cases that a decision is the whole answer to are replayed as
well (`scripts/cache-tests.json`); the dozen it reads differently are named with
the reading this package follows in `scripts/gen_cache_vectors.mjs`.

`client` is measured on §15.4's method rewrites (a 301, a 302 and a 303; a 307 and
a 308 that keep both method and body), on the credentials that stop at the origin
they were meant for, on relative `Location` resolution, on loops written two ways,
and on the `Alt-Svc` examples §3 of RFC 7838 prints.

## What lives elsewhere

URI references and data URLs are [moonurl](https://github.com/moonbitstack/moonurl);
media types, multipart and `Content-Disposition` are [moonmime](https://github.com/moonbitstack/moonmime).

The variable-length integers are not here either. HTTP/3's frames are counted in
QUIC's varint and both header compressions count in RFC 7541's prefixed integer;
neither belongs to HTTP, and both are written in more than one protocol. They
are `moonvar`, which this depends on and which depends on nothing.

TLS is `moontls` and QUIC is `moonquic`, so that parsing an HTTP message does
not mean carrying a handshake. Content codings are `moonzip`; `deflate` here is
the other shape — a stream that is stopped and resumed inside, which is what
RFC 7692 §7.2 needs and what a file compressor has no reason to offer.

## Install

```bash
moon add moonbitstack/moonhttp
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
