// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The HTTP/3 frame layer (RFC 9114 §7.1, §7.2): every frame on an HTTP/3 stream is a
// variable-length `Type`, a variable-length `Length`, and that many payload octets. This is the
// mapping that turns a QUIC stream's bytes into the DATA / HEADERS / SETTINGS / GOAWAY / …
// frames HTTP/3 runs on, built directly on the QUIC varint codec. DATA and HEADERS carry opaque
// payloads (a body, or a QPACK-encoded field section — QPACK is a separate layer); SETTINGS is
// decoded into its identifier/value pairs.

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
/// The largest a frame's declared length can be, since a length is a variable-length integer
/// (RFC 9000 §16). A reader that sets no limit of its own is bounded by this.
let largest : UInt64 = 0x3fff_ffff_ffff_ffffUL

///|
/// A decoded HTTP/3 frame. `Data`/`Headers`/`PushPromise` carry their opaque payloads;
/// `Settings` carries the decoded `(identifier, value)` pairs. `Reserved` is any unknown or
/// grease frame type (RFC 9114 §7.2.8 / §9), which a receiver ignores; `ReservedHttp2` is one of
/// the frame types reused from HTTP/2 (0x02, 0x06, 0x08, 0x09), which RFC 9114 §7.2 requires be
/// treated as a connection error.
#derive(Eq, Debug)
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
}

///|
/// Whether `t` is an HTTP/2 frame type reused in HTTP/3's registry with no HTTP/3 meaning
/// (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION) — a connection error on receipt
/// (RFC 9114 §11.2.1).
fn is_reserved(t : UInt64) -> Bool {
  t == 0x02 || t == 0x06 || t == 0x08 || t == 0x09
}

///|
/// Encode one HTTP/3 frame: its type, its payload length, then the payload.
pub fn Frame::encode(frame : Frame) -> Bytes {
  let (frame_type, payload) = match frame {
    Data(body) => (data, body)
    Headers(block) => (headers, block)
    CancelPush(id) => (cancel_push, @quic.encode(id))
    Settings(pairs) => (settings_type, settings(pairs))
    PushPromise(id, block) => (push_promise, prefixed(id, block))
    GoAway(id) => (goaway, @quic.encode(id))
    MaxPushId(id) => (max_push_id, @quic.encode(id))
    Reserved(t, body) => (t, body)
    ReservedHttp2(t) => (t, b"")
  }
  let buf = Buffer()
  buf.write_bytes(@quic.encode(frame_type))
  buf.write_bytes(@quic.encode(payload.length().to_uint64()))
  buf.write_bytes(payload)
  buf.to_bytes()
}

///|
/// A varint-prefixed id followed by an opaque block (a PUSH_PROMISE payload).
fn prefixed(id : UInt64, block : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(@quic.encode(id))
  buf.write_bytes(block)
  buf.to_bytes()
}

///|
/// Encode a SETTINGS payload: each pair as its identifier varint then its value varint
/// (RFC 9114 §7.2.4).
pub fn settings(pairs : Array[(UInt64, UInt64)]) -> Bytes {
  let buf = Buffer()
  for pair in pairs {
    buf.write_bytes(@quic.encode(pair.0))
    buf.write_bytes(@quic.encode(pair.1))
  }
  buf.to_bytes()
}

///|
/// Decode one HTTP/3 frame from the front of `input`. Returns `Some((frame, consumed))` on a
/// complete frame, `None` when more bytes are needed (a partial frame — the type, the length, or
/// the payload has not fully arrived), and raises on a malformed frame (a truncated SETTINGS pair
/// or a required varint field that is absent).
///
/// `limit` is the largest payload this endpoint will hold (RFC 9114 §7.1). A frame that declares
/// more is refused as soon as its header arrives, before any of its payload is kept: a peer can
/// claim 2^62 octets and send none, and an endpoint that waits for them holds whatever it is
/// sent towards a promise it should never have accepted. Pass `largest` — the default — for a
/// stream whose frames are not field sections.
pub fn decode(
  input : BytesView,
  limit~ : UInt64 = largest,
) -> (Frame, Int32)? raise Refused {
  let (frame_type, type_len) = match @quic.decode(input) {
    Some(v) => v
    None => return None
  }
  let rest = input[type_len:]
  let (length, len_len) = match @quic.decode(rest) {
    Some(v) => v
    None => return None
  }
  if length > limit {
    raise fault(
      ExcessiveLoad,
      "a frame of \{length} octets, over the \{limit} this endpoint accepts",
    )
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
/// A payload that is exactly one varint (CANCEL_PUSH / GOAWAY / MAX_PUSH_ID).
fn one(payload : Bytes, name : String) -> UInt64 raise Refused {
  let (value, _) = lead(payload, name)
  value
}

///|
/// The leading varint of a payload plus the octets it consumed.
fn lead(payload : Bytes, name : String) -> (UInt64, Int32) raise Refused {
  match @quic.decode(payload[:]) {
    Some(v) => v
    None => raise fault(FrameError, name + " frame missing its varint field")
  }
}

///|
/// Decode every complete frame at the front of `input`, returning the frames and the number of
/// octets consumed (the tail, a partial frame, is left for the next read). A stream reader feeds
/// accumulated bytes and keeps the unconsumed remainder.
pub fn decode_all(
  input : Bytes,
  limit~ : UInt64 = largest,
) -> (Array[Frame], Int32) raise Refused {
  let frames : Array[Frame] = []
  let mut off = 0
  let view = input[:]
  for ;; {
    match decode(view[off:], limit~) {
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
#derive(Eq, Debug)
pub(all) enum On {
  Control
  Request
  Push
}

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
    raise fault(
      FrameUnexpected,
      "\{name_of(frame)} is not permitted on this stream (RFC 9114 §7.2)",
    )
  }
}

///|
/// A frame's type, as the RFC names it, for a refusal's message.
fn name_of(frame : Frame) -> String {
  match frame {
    Data(_) => "DATA"
    Headers(_) => "HEADERS"
    CancelPush(_) => "CANCEL_PUSH"
    Settings(_) => "SETTINGS"
    PushPromise(_, _) => "PUSH_PROMISE"
    GoAway(_) => "GOAWAY"
    MaxPushId(_) => "MAX_PUSH_ID"
    Reserved(t, _) => "frame 0x\{t}"
    ReservedHttp2(t) => "the HTTP/2 frame 0x\{t}"
  }
}

///|
pub extend On with Debug::{to_repr}

///|
pub extend On with Eq::{not_equal, equal}

///|
/// Two byte strings joined, which is what a reader does with the tail it kept and the bytes that
/// have just arrived.
fn joined(a : Bytes, b : Bytes) -> Bytes {
  let out = Buffer()
  out.write_bytes(a)
  out.write_bytes(b)
  out.to_bytes()
}
