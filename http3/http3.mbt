// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Why a frame, a stream or a connection was refused.
///
/// RFC 9114 §8 gives each case its own connection error; they are one type here because
/// the answer to every one of them is the same — close the connection — and the message
/// says which it was.
pub(all) suberror Refused {
  Malformed(String)
} derive(Eq, Debug)

///|
/// A refusal prints as the fault it is.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Malformed(m) => logger.write_string("Malformed(" + m + ")")
  }
}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

// The HTTP/3 frame layer (RFC 9114 §7.2): every frame on an HTTP/3 stream is a
// variable-length `Type`, a variable-length `Length`, and that many payload octets.
// This is the mapping that turns a QUIC stream's bytes into the DATA / HEADERS /
// SETTINGS / GOAWAY / … frames HTTP/3 runs on, built directly on the QUIC varint codec.
// DATA and HEADERS carry opaque payloads (a body, or a QPACK-encoded field section —
// QPACK is a separate layer); SETTINGS is decoded into its identifier/value pairs.

///|
/// HTTP/3 frame type codes (RFC 9114 §11.2.1).
let data : UInt64 = 0x00

///|
let headers : UInt64 = 0x01

///|
let cancel_push : UInt64 = 0x03

///|
let settings_type : UInt64 = 0x04

///|
let push_promise : UInt64 = 0x05

///|
let goaway : UInt64 = 0x07

///|
let max_push_id : UInt64 = 0x0d

///|
/// A decoded HTTP/3 frame. `Data`/`Headers`/`PushPromise` carry their opaque payloads;
/// `Settings` carries the decoded `(identifier, value)` pairs. `Reserved` is any
/// unknown or grease frame type (RFC 9114 §7.2.8 / §9), which a receiver ignores;
/// `ReservedHttp2` is one of the frame types reused from HTTP/2 (0x02, 0x06, 0x08,
/// 0x09), which RFC 9114 §7.2 requires be treated as a connection error.
pub(all) enum Frame {
  Data(Bytes)
  Headers(Bytes)
  CancelPush(UInt64)
  Settings(Array[(UInt64, UInt64)])
  PushPromise(UInt64, Bytes)
  GoAway(UInt64)
  MaxPushId(UInt64)
  Reserved(UInt64, Bytes)
  ReservedHttp2(UInt64)
} derive(Eq, Debug)

///|
/// Whether `t` is an HTTP/2 frame type reused in HTTP/3's registry with no HTTP/3
/// meaning (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION) — a connection error on
/// receipt (RFC 9114 §11.2.1).
fn is_reserved(t : UInt64) -> Bool {
  t == 0x02 || t == 0x06 || t == 0x08 || t == 0x09
}

///|
/// Encode one HTTP/3 frame: its type, its payload length, then the payload.
pub fn Frame::encode(frame : Frame) -> Bytes {
  let (frame_type, payload) = match frame {
    Data(body) => (data, body)
    Headers(block) => (headers, block)
    CancelPush(id) => (cancel_push, @varint.encode(id))
    Settings(pairs) => (settings_type, settings(pairs))
    PushPromise(id, block) => (push_promise, prefixed(id, block))
    GoAway(id) => (goaway, @varint.encode(id))
    MaxPushId(id) => (max_push_id, @varint.encode(id))
    Reserved(t, body) => (t, body)
    ReservedHttp2(t) => (t, b"")
  }
  let buf = Buffer()
  buf.write_bytes(@varint.encode(frame_type))
  buf.write_bytes(@varint.encode(payload.length().to_uint64()))
  buf.write_bytes(payload)
  buf.to_bytes()
}

///|
/// A varint-prefixed id followed by an opaque block (a PUSH_PROMISE payload).
fn prefixed(id : UInt64, block : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(@varint.encode(id))
  buf.write_bytes(block)
  buf.to_bytes()
}

///|
/// Encode a SETTINGS payload: each pair as its identifier varint then its value varint
/// (RFC 9114 §7.2.4).
pub fn settings(pairs : Array[(UInt64, UInt64)]) -> Bytes {
  let buf = Buffer()
  for pair in pairs {
    buf.write_bytes(@varint.encode(pair.0))
    buf.write_bytes(@varint.encode(pair.1))
  }
  buf.to_bytes()
}

///|
/// Decode one HTTP/3 frame from the front of `input`. Returns `Some((frame, consumed))`
/// on a complete frame, `None` when more bytes are needed (a partial frame — the type,
/// the length, or the payload has not fully arrived), and raises on a malformed frame
/// (a truncated SETTINGS pair or a required varint field that is absent).
pub fn decode(input : BytesView) -> (Frame, Int)? raise Refused {
  let (frame_type, type_len) = match @varint.decode(input) {
    Some(v) => v
    None => return None
  }
  let rest = input[type_len:]
  let (length, len_len) = match @varint.decode(rest) {
    Some(v) => v
    None => return None
  }
  let payload_len = length.to_int()
  let header_len = type_len + len_len
  if input.length() < header_len + payload_len {
    return None
  }
  let payload = input[header_len:header_len + payload_len].to_owned()
  let consumed = header_len + payload_len
  let frame = of_payload(frame_type, payload)
  Some((frame, consumed))
}

///|
/// Build the typed frame from its type code and its already-sliced payload.
fn of_payload(frame_type : UInt64, payload : Bytes) -> Frame raise Refused {
  if frame_type == data {
    Data(payload)
  } else if frame_type == headers {
    Headers(payload)
  } else if frame_type == cancel_push {
    CancelPush(one(payload, "CANCEL_PUSH"))
  } else if frame_type == settings_type {
    Settings(read_settings(payload))
  } else if frame_type == push_promise {
    let (id, id_len) = lead(payload, "PUSH_PROMISE")
    PushPromise(id, payload[id_len:payload.length()].to_owned())
  } else if frame_type == goaway {
    GoAway(one(payload, "GOAWAY"))
  } else if frame_type == max_push_id {
    MaxPushId(one(payload, "MAX_PUSH_ID"))
  } else if is_reserved(frame_type) {
    ReservedHttp2(frame_type)
  } else {
    Reserved(frame_type, payload)
  }
}

///|
/// Decode a SETTINGS payload into its `(identifier, value)` pairs. A trailing partial
/// pair (an identifier with no value, or a truncated varint) is a frame error.
pub fn read_settings(payload : Bytes) -> Array[(UInt64, UInt64)] raise Refused {
  let pairs : Array[(UInt64, UInt64)] = []
  let view = payload[:]
  let mut off = 0
  let n = view.length()
  while off < n {
    let (id, id_len) = match @varint.decode(view[off:]) {
      Some(v) => v
      None => raise Malformed("truncated SETTINGS identifier")
    }
    off += id_len
    let (value, val_len) = match @varint.decode(view[off:]) {
      Some(v) => v
      None => raise Malformed("truncated SETTINGS value")
    }
    off += val_len
    pairs.push((id, value))
  }
  pairs
}

///|
/// A payload that is exactly one varint (CANCEL_PUSH / GOAWAY / MAX_PUSH_ID).
fn one(payload : Bytes, name : String) -> UInt64 raise Refused {
  let (value, _) = lead(payload, name)
  value
}

///|
/// The leading varint of a payload plus the octets it consumed.
fn lead(payload : Bytes, name : String) -> (UInt64, Int) raise Refused {
  match @varint.decode(payload[:]) {
    Some(v) => v
    None => raise Malformed(name + " frame missing its varint field")
  }
}

///|
/// Decode every complete frame at the front of `input`, returning the frames and the
/// number of octets consumed (the tail, a partial frame, is left for the next read). A
/// stream reader feeds accumulated bytes and keeps the unconsumed remainder.
pub fn decode_all(input : Bytes) -> (Array[Frame], Int) raise Refused {
  let frames : Array[Frame] = []
  let mut off = 0
  let view = input[:]
  for ;; {
    match decode(view[off:]) {
      Some((frame, consumed)) => {
        frames.push(frame)
        off += consumed
      }
      None => break
    }
  }
  (frames, off)
}

///|
pub extend Frame with Debug::{to_repr}

///|
pub extend Frame with Eq::{not_equal, equal}

// Which HTTP/3 frames are permitted on which stream (RFC 9114 §7.2): the codec decodes any frame,
// but an endpoint must reject one that appears where the protocol does not allow it (an
// H3_FRAME_UNEXPECTED connection error). DATA/HEADERS ride request and push streams; SETTINGS,
// GOAWAY, MAX_PUSH_ID, and CANCEL_PUSH ride only the control stream; PUSH_PROMISE rides a request
// stream; a greased reserved type is ignored anywhere; and the frame types HTTP/3 reserves because
// HTTP/2 used them (PRIORITY 0x02, PING 0x06, WINDOW_UPDATE 0x08, CONTINUATION 0x09) are a
// connection error on any stream (§7.2.1, §11.2.1).

///|
/// The stream a frame was received on, for the purpose of frame-placement rules (RFC 9114 §6.2).
pub(all) enum On {
  Control
  Request
  Push
} derive(Eq, Debug)

///|
/// Whether `frame` is permitted on a stream of kind `ctx` (RFC 9114 §7.2).
pub fn allowed(frame : Frame, ctx : On) -> Bool {
  match frame {
    ReservedHttp2(_) => false
    Data(_) | Headers(_) => ctx == Request || ctx == Push
    Settings(_) | GoAway(_) | MaxPushId(_) | CancelPush(_) => ctx == Control
    PushPromise(_, _) => ctx == Request
    Reserved(_, _) => true
  }
}

///|
/// Raise `Refused` (H3_FRAME_UNEXPECTED) when `frame` is not permitted on `ctx`.
pub fn check(frame : Frame, ctx : On) -> Unit raise Refused {
  if !allowed(frame, ctx) {
    raise Malformed(
      "frame not permitted on this stream (RFC 9114 §7.2, H3_FRAME_UNEXPECTED)",
    )
  }
}

///|
pub extend On with Debug::{to_repr}

///|
pub extend On with Eq::{not_equal, equal}

// The HTTP/3 SETTINGS an endpoint advertises on its control stream (RFC 9114 §7.2.4): the QPACK
// dynamic-table capacity and blocked-stream limit the peer may use when encoding header fields,
// and the largest header section this endpoint will accept. A control stream must open with a
// SETTINGS frame; this names those settings and reads them off the control stream a peer sends —
// the negotiation curl performs before any request.

///|
/// SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204 §5).
pub let qpack_capacity : UInt64 = 0x01

///|
/// SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 §7.2.4.1).
pub let max_field_section : UInt64 = 0x06

///|
/// SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 §5).
pub let blocked_streams : UInt64 = 0x07

///|
/// An endpoint's HTTP/3 settings.
pub(all) struct Settings {
  qpack_max_table_capacity : UInt64
  max_field_section_size : UInt64
  qpack_blocked_streams : UInt64
} derive(Eq, Debug)

///|
/// Settings with the given QPACK table capacity, maximum field section size, and blocked-stream
/// limit.
pub fn Settings::new(
  qpack_max_table_capacity : UInt64,
  max_field_section_size : UInt64,
  qpack_blocked_streams : UInt64,
) -> Settings {
  { qpack_max_table_capacity, max_field_section_size, qpack_blocked_streams, }
}

///|
/// The `(identifier, value)` pairs to carry in a SETTINGS frame.
pub fn Settings::pairs(self : Settings) -> Array[(UInt64, UInt64)] {
  [
    (qpack_capacity, self.qpack_max_table_capacity),
    (max_field_section, self.max_field_section_size),
    (blocked_streams, self.qpack_blocked_streams),
  ]
}

///|
/// Read settings from received `(identifier, value)` pairs, taking the value for each known
/// identifier (0 when absent) and ignoring unknown ones (RFC 9114 §7.2.4.1 grease tolerance).
pub fn Settings::of_pairs(pairs : Array[(UInt64, UInt64)]) -> Settings {
  let mut qmtc = 0UL
  let mut mfss = 0UL
  let mut qbs = 0UL
  for p in pairs {
    if p.0 == qpack_capacity {
      qmtc = p.1
    } else if p.0 == max_field_section {
      mfss = p.1
    } else if p.0 == blocked_streams {
      qbs = p.1
    }
  }
  {
    qpack_max_table_capacity: qmtc,
    max_field_section_size: mfss,
    qpack_blocked_streams: qbs,
  }
}

///|
/// Decode an endpoint's control stream (RFC 9114 §6.2.1): its type prefix must be the control
/// stream, and its first frame a SETTINGS frame, whose settings are returned. `None` if the
/// stream is not a control stream or does not open with SETTINGS. Raises on a malformed frame.
pub fn read_control(input : BytesView) -> Settings? raise Refused {
  match Stream::decode(input) {
    Some((ControlKind, consumed)) => {
      let (frames, _) = decode_all(input[consumed:].to_owned())
      if frames.length() > 0 {
        match frames[0] {
          Settings(pairs) => Some(Settings::of_pairs(pairs))
          _ => None
        }
      } else {
        None
      }
    }
    _ => None
  }
}

///|
pub extend Settings with Debug::{to_repr}

///|
pub extend Settings with Eq::{not_equal, equal}

// HTTP/3 unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2). Every unidirectional
// stream opens with a variable-length integer naming its type: the control stream (0x00)
// that carries SETTINGS and connection-control frames, a server push stream (0x01) prefixed
// with its push id, and the QPACK encoder (0x02) and decoder (0x03) streams that carry the
// dynamic-table instructions. Unrecognized types are reserved/greased and their payloads are
// ignored (§6.2, §6.2.3). This is the demultiplexer a connection runs over the raw QUIC
// unidirectional streams before dispatching to the frame and QPACK-instruction codecs.

///|
/// An HTTP/3 unidirectional stream's type (RFC 9114 §6.2, RFC 9204 §4.2).
pub(all) enum Stream {
  ControlKind
  PushKind(UInt64)
  EncoderKind
  DecoderKind
  ReservedKind(UInt64)
} derive(Eq, Debug)

///|
/// Encode a unidirectional stream's opening bytes: the type varint, plus the push id for a
/// push stream (RFC 9114 §6.2.2).
pub fn Stream::encode(stream : Stream) -> Bytes {
  match stream {
    ControlKind => @varint.encode(0x00)
    PushKind(push_id) => {
      let buf = Buffer()
      buf.write_bytes(@varint.encode(0x01))
      buf.write_bytes(@varint.encode(push_id))
      buf.to_bytes()
    }
    EncoderKind => @varint.encode(0x02)
    DecoderKind => @varint.encode(0x03)
    ReservedKind(t) => @varint.encode(t)
  }
}

///|
/// Decode a unidirectional stream's opening bytes: the type varint (and a push id for a push
/// stream). Returns the stream kind and bytes consumed, or `None` on a partial read.
pub fn Stream::decode(input : BytesView) -> (Stream, Int)? {
  let (stream_type, type_len) = match @varint.decode(input) {
    Some(v) => v
    None => return None
  }
  match stream_type {
    0x00 => Some((ControlKind, type_len))
    0x01 =>
      match @varint.decode(input[type_len:]) {
        Some((push_id, id_len)) => Some((PushKind(push_id), type_len + id_len))
        None => None
      }
    0x02 => Some((EncoderKind, type_len))
    0x03 => Some((DecoderKind, type_len))
    other => Some((ReservedKind(other), type_len))
  }
}

///|
/// Encode a control stream (RFC 9114 §6.2.1): the control-stream type, then a SETTINGS frame
/// with `settings`, which a control stream must send first.
pub fn control(settings : Array[(UInt64, UInt64)]) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(Stream::encode(ControlKind))
  buf.write_bytes(Frame::encode(Settings(settings)))
  buf.to_bytes()
}

///|
pub extend Stream with Debug::{to_repr}

///|
pub extend Stream with Eq::{not_equal, equal}

// Mapping an HTTP message onto an HTTP/3 request or response stream (RFC 9114 §4.1). A
// message is a HEADERS frame carrying a QPACK-encoded field section, followed by zero or
// more DATA frames carrying the body, and optionally a trailing HEADERS frame for trailers.
// Requests and responses differ only in their pseudo-headers — :method/:scheme/:authority/
// :path for a request, :status for a response — which are ordinary field lines that precede
// the regular headers (§4.3.1). This ties the QPACK field-section codec and the HTTP/3 frame
// codec into the messages a connection actually exchanges; only the QUIC stream carrying
// these bytes is left to the async transport.

///|
/// Encode a message body as an HTTP/3 request/response stream: a HEADERS frame with the
/// QPACK-encoded `headers` (static table only), then a DATA frame when `body` is non-empty.
pub fn message(headers : Array[@header.Header], body : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(Frame::encode(Headers(@qpack.encode(headers))))
  if body.length() > 0 {
    buf.write_bytes(Frame::encode(Data(body)))
  }
  buf.to_bytes()
}

///|
/// Decode an HTTP/3 request/response stream back into its header list and body: the first
/// HEADERS frame gives the headers, the DATA frames concatenate into the body, and a second
/// HEADERS frame (trailers) and unknown frames are ignored (RFC 9114 §4.1). Raises if there
/// is no HEADERS frame or a frame is malformed.
pub fn read_message(
  bytes : Bytes,
) -> (Array[@header.Header], Bytes) raise Refused {
  let (frames, _) = decode_all(bytes)
  let mut headers : Array[@header.Header]? = None
  let body = Buffer()
  for frame in frames {
    match frame {
      Headers(field_section) =>
        match headers {
          None =>
            headers = Some(
              @qpack.decode(field_section) catch {
                _ => raise Malformed("malformed QPACK field section")
              },
            )
          Some(_) => () // trailers
        }
      Data(chunk) => body.write_bytes(chunk)
      _ => () // reserved, greased, or control frames on a request stream
    }
  }
  match headers {
    Some(h) => (h, body.to_bytes())
    None => raise Malformed("HTTP/3 message has no HEADERS frame")
  }
}

///|
/// Encode an HTTP/3 request: the `:method`, `:scheme`, `:authority`, and `:path` pseudo-
/// headers (RFC 9114 §4.3.1), then `headers`, then the body.
pub fn request(
  meth : String,
  scheme : String,
  authority : String,
  path : String,
  headers : Array[@header.Header],
  body : Bytes,
) -> Bytes {
  let all : Array[@header.Header] = [
    @header.Header::of(":method", meth),
    @header.Header::of(":scheme", scheme),
    @header.Header::of(":authority", authority),
    @header.Header::of(":path", path),
  ]
  for h in headers {
    all.push(h)
  }
  message(all, body)
}

///|
/// Encode an HTTP/3 response: the `:status` pseudo-header (RFC 9114 §4.3.2), then `headers`,
/// then the body.
pub fn response(
  status : String,
  headers : Array[@header.Header],
  body : Bytes,
) -> Bytes {
  let all : Array[@header.Header] = [@header.Header::of(":status", status)]
  for h in headers {
    all.push(h)
  }
  message(all, body)
}

// The HTTP/3 connection setup and unidirectional-stream demultiplexer (RFC 9114 §6.2): once the
// QUIC handshake completes, each endpoint opens a control stream and sends its SETTINGS first, then
// classifies every unidirectional stream the peer opens — control (whose SETTINGS it reads and
// keeps), the two QPACK instruction streams, a server push stream, or a reserved/greased type it
// ignores. This is the connection state that sits above the QUIC streams and drives the frame and
// QPACK codecs; the live QUIC connection supplies the stream bytes.

///|
/// Which side of the connection an endpoint is (RFC 9114 §3.1): a server must not receive a push
/// stream, so the role decides whether one is a protocol violation.
pub(all) enum Role {
  Client
  Server
} derive(Eq, Debug)

///|
/// The result of accepting a peer's unidirectional stream: the control stream carries the peer's
/// SETTINGS, the QPACK streams carry table instructions, a push stream carries its id, and an
/// unrecognized type is reserved/greased.
pub(all) enum Event {
  ControlEstablished(Settings)
  QpackEncoder
  QpackDecoder
  Push(UInt64)
  Reserved(UInt64)
} derive(Eq, Debug)

///|
/// One endpoint of an HTTP/3 connection: its role, the settings it advertises, and — once the peer
/// opens its control stream — the peer's settings.
pub struct Conn {
  role : Role
  local_settings : Settings
  mut peer_settings : Settings?
  mut control_seen : Bool
}

///|
/// A connection that will advertise `local_settings`.
pub fn Conn::new(role : Role, local_settings : Settings) -> Conn {
  { role, local_settings, peer_settings: None, control_seen: false, }
}

///|
/// The bytes to write when opening our control stream: the control-stream type then our SETTINGS
/// frame, which a control stream must send first (RFC 9114 §6.2.1).
pub fn Conn::open_control_stream(self : Conn) -> Bytes {
  control(self.local_settings.pairs())
}

///|
/// Accept a peer's unidirectional stream from its opening bytes: classify it and, for the control
/// stream, decode and keep the peer's SETTINGS. A second control stream, a control stream not
/// opening with SETTINGS, and a server receiving a push stream are all connection errors
/// (RFC 9114 §6.2).
pub fn Conn::accept_uni_stream(self : Conn, bytes : Bytes) -> Event raise {
  guard Stream::decode(bytes[:]) is Some((stream_type, _)) else {
    raise Malformed("truncated unidirectional stream header")
  }
  match stream_type {
    ControlKind => {
      if self.control_seen {
        raise Malformed(
          "a second control stream is a connection error (RFC 9114 §6.2.1)",
        )
      }
      let settings = match read_control(bytes[:]) {
        Some(s) => s
        None =>
          raise Malformed("a control stream must open with a SETTINGS frame")
      }
      self.control_seen = true
      self.peer_settings = Some(settings)
      ControlEstablished(settings)
    }
    EncoderKind => QpackEncoder
    DecoderKind => QpackDecoder
    PushKind(id) => {
      if self.role == Server {
        raise Malformed(
          "a server must not receive a push stream (RFC 9114 §6.2.2)",
        )
      }
      Push(id)
    }
    ReservedKind(t) => Reserved(t)
  }
}

///|
/// Whether the peer's control-stream SETTINGS have been received (connection setup complete).
pub fn Conn::settings_established(self : Conn) -> Bool {
  self.peer_settings is Some(_)
}

///|
/// The peer's advertised settings, once its control stream has been accepted.
pub fn Conn::peer_settings(self : Conn) -> Settings? {
  self.peer_settings
}

///|
pub extend Role with Debug::{to_repr}

///|
pub extend Role with Eq::{not_equal, equal}

///|
pub extend Event with Debug::{to_repr}

///|
pub extend Event with Eq::{not_equal, equal}

// Serving an HTTP/3 request on a request stream (RFC 9114 §4.1): a client opens a bidirectional
// stream carrying a HEADERS frame (the pseudo-headers :method/:scheme/:authority/:path and the
// regular headers) and DATA frames (the body); the server decodes that into a request, runs a
// handler, and writes the response — a HEADERS frame with :status and the DATA of the body —
// back on the same stream. This is the connection-level routing over the HTTP/3 message codec, a
// mooncat HTTP/3 server's request/response path.

///|
/// A decoded HTTP/3 request: the pseudo-headers pulled out, the remaining header fields, and the
/// body.
pub(all) struct Request {
  meth : String
  scheme : String
  authority : String
  path : String
  headers : Array[@header.Header]
  body : Bytes
}

///|
/// Decode an HTTP/3 request stream into a request, separating the pseudo-headers from the
/// regular ones (RFC 9114 §4.3.1). `None` when the required `:method` and `:path` are absent.
/// Raises on a malformed stream.
///
/// `strict` also applies §7.2's placement rules, so a frame that belongs on the control
/// stream — a SETTINGS, say — is refused rather than read past. It is off by default
/// because a reader that only wants the request need not care what else arrived.
pub fn read_request(
  bytes : Bytes,
  strict? : Bool = false,
) -> Request? raise Refused {
  if strict {
    // §7.2: a frame the protocol does not allow on a request stream is an
    // H3_FRAME_UNEXPECTED connection error, not something to read past.
    let (frames, _) = decode_all(bytes)
    for frame in frames {
      check(frame, Request)
    }
  }
  let (all_headers, body) = read_message(bytes)
  let mut meth = ""
  let mut scheme = ""
  let mut authority = ""
  let mut path = ""
  let regular : Array[@header.Header] = []
  for h in all_headers {
    let (name, value) = h.ascii()
    match name {
      ":method" => meth = value
      ":scheme" => scheme = value
      ":authority" => authority = value
      ":path" => path = value
      _ => regular.push(h)
    }
  }
  if meth == "" || path == "" {
    None
  } else {
    Some({ meth, scheme, authority, path, headers: regular, body, })
  }
}

///|
/// An HTTP/3 response: the status, the header fields, and the body.
pub(all) struct Response {
  status : String
  headers : Array[@header.Header]
  body : Bytes
}

///|
/// Encode the response as an HTTP/3 response stream (a HEADERS frame with `:status`, then DATA).
pub fn Response::encode(self : Response) -> Bytes {
  response(self.status, self.headers, self.body)
}

///|
/// Serve one HTTP/3 request stream: decode the request, apply `handler`, and encode its
/// response stream. A request missing its pseudo-headers is answered with a 400. Raises on a
/// malformed request stream.
pub fn serve(
  request_bytes : Bytes,
  handler : (Request) -> Response,
) -> Bytes raise Refused {
  match read_request(request_bytes) {
    Some(req) => handler(req).encode()
    None => Response::{ status: "400", headers: [], body: b"", }.encode()
  }
}
