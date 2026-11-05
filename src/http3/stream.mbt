// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// HTTP/3 unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2). Every unidirectional stream
// opens with a variable-length integer naming its type: the control stream (0x00) that carries
// SETTINGS and connection-control frames, a server push stream (0x01) prefixed with its push id,
// and the QPACK encoder (0x02) and decoder (0x03) streams that carry the dynamic-table
// instructions. Unrecognized types are reserved/greased and their payloads are ignored (§6.2,
// §6.2.3). This is the demultiplexer a connection runs over the raw QUIC unidirectional streams
// before dispatching to the frame and QPACK-instruction codecs.
//
// Three of those streams are critical (§6.2.1, RFC 9204 §4.2): the connection is only meaningful
// while the control, encoder and decoder streams are open, so closing one ends the connection and
// opening a second is a fault. A push stream is the other way round: only a server opens one, so
// one arriving at a server is a fault of the same kind.

///|
/// An HTTP/3 unidirectional stream's type (RFC 9114 §6.2, RFC 9204 §4.2).
#derive(Eq, Debug)
pub(all) enum Stream {
  ControlKind
  PushKind(UInt64)
  EncoderKind
  DecoderKind
  ReservedKind(UInt64)
}

///|
/// Encode a unidirectional stream's opening bytes: the type varint, plus the push id for a
/// push stream (RFC 9114 §6.2.2).
pub fn Stream::encode(stream : Stream) -> Bytes {
  match stream {
    ControlKind => @quic.encode(0x00)
    PushKind(push_id) => {
      let buf = Buffer()
      buf.write_bytes(@quic.encode(0x01))
      buf.write_bytes(@quic.encode(push_id))
      buf.to_bytes()
    }
    EncoderKind => @quic.encode(0x02)
    DecoderKind => @quic.encode(0x03)
    ReservedKind(t) => @quic.encode(t)
  }
}

///|
/// Decode a unidirectional stream's opening bytes: the type varint (and a push id for a push
/// stream). Returns the stream kind and bytes consumed, or `None` on a partial read.
pub fn Stream::decode(input : BytesView) -> (Stream, Int32)? {
  let (stream_type, type_len) = match @quic.decode(input) {
    Some(v) => v
    None => return None
  }
  match stream_type {
    0x00 => Some((ControlKind, type_len))
    0x01 =>
      match @quic.decode(input[type_len:]) {
        Some((push_id, id_len)) => Some((PushKind(push_id), type_len + id_len))
        None => None
      }
    0x02 => Some((EncoderKind, type_len))
    0x03 => Some((DecoderKind, type_len))
    other => Some((ReservedKind(other), type_len))
  }
}

///|
/// Whether the connection only holds together while this stream is open (RFC 9114 §6.2.1,
/// RFC 9204 §4.2). Closing one of these ends the connection; a push or reserved stream carries
/// nothing the connection needs.
pub fn Stream::is_critical(self : Stream) -> Bool {
  match self {
    ControlKind | EncoderKind | DecoderKind => true
    PushKind(_) | ReservedKind(_) => false
  }
}

///|
/// The name the RFC gives this kind of stream, for a refusal's message.
pub fn Stream::label(self : Stream) -> String {
  match self {
    ControlKind => "control stream"
    PushKind(_) => "push stream"
    EncoderKind => "QPACK encoder stream"
    DecoderKind => "QPACK decoder stream"
    ReservedKind(t) => "reserved stream 0x\{t}"
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
