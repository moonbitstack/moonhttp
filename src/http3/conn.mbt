// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The HTTP/3 connection's setup (RFC 9114 §3.1, §6.2): which side of the connection an endpoint
// is, the settings it advertises, and the peer's once its control stream says so. The connection
// also keeps the one piece of state the unidirectional streams share — which of them has been
// opened — because two control streams, two encoder streams and two decoder streams are a
// connection error, and a client's push stream is one at a server.
//
// Nothing here holds a socket or a clock: a unidirectional stream arrives as its opening bytes
// plus its type, and what the connection does about it is the same however those bytes travelled.

///|
/// Which side of the connection an endpoint is (RFC 9114 §3.1): a server must not receive a push
/// stream, so the role decides whether one is a protocol violation.
#derive(Eq, Debug)
pub(all) enum Role {
  Client
  Server
}

///|
/// The result of accepting a peer's unidirectional stream: the control stream carries the peer's
/// SETTINGS, the QPACK streams carry table instructions, a push stream carries its id, and an
/// unrecognized type is reserved/greased.
#derive(Eq, Debug)
pub(all) enum Event {
  ControlEstablished(Settings)
  QpackEncoder
  QpackDecoder
  Push(UInt64)
  Reserved(UInt64)
}

///|
/// One endpoint of an HTTP/3 connection: its role, the settings it advertises, and — once the peer
/// opens its control stream — the peer's settings.
pub struct Conn {
  role : Role
  local_settings : Settings
  mut peer_settings : Settings?
  mut control_seen : Bool
  mut encoder_seen : Bool
  mut decoder_seen : Bool
}

///|
/// A connection that will advertise `local_settings`.
pub fn Conn::new(role : Role, local_settings : Settings) -> Conn {
  {
    role,
    local_settings,
    peer_settings: None,
    control_seen: false,
    encoder_seen: false,
    decoder_seen: false,
  }
}

///|
/// The bytes to write when opening our control stream: the control-stream type then our SETTINGS
/// frame, which a control stream must send first (RFC 9114 §6.2.1).
pub fn Conn::open_control_stream(self : Conn) -> Bytes {
  control(self.local_settings.pairs())
}

///|
/// The settings this endpoint advertises.
pub fn Conn::local_settings(self : Conn) -> Settings {
  self.local_settings
}

///|
/// Record a unidirectional stream the peer has opened, by the kind its type names.
///
/// Three of the four kinds may appear once (RFC 9114 §6.2.1, §6.2.2, RFC 9204 §4.2): a second
/// control, encoder or decoder stream is H3_STREAM_CREATION_ERROR, and a push stream at a server
/// is the same fault, since only a server pushes. A reserved kind is a peer exercising §9 and is
/// taken as nothing at all.
pub fn Conn::open_stream(self : Conn, kind : Stream) -> Unit raise Refused {
  match kind {
    ControlKind =>
      if self.control_seen {
        raise fault(
          StreamCreationError,
          "a second control stream (RFC 9114 §6.2.1)",
        )
      } else {
        self.control_seen = true
      }
    EncoderKind =>
      if self.encoder_seen {
        raise fault(
          StreamCreationError,
          "a second QPACK encoder stream (RFC 9204 §4.2)",
        )
      } else {
        self.encoder_seen = true
      }
    DecoderKind =>
      if self.decoder_seen {
        raise fault(
          StreamCreationError,
          "a second QPACK decoder stream (RFC 9204 §4.2)",
        )
      } else {
        self.decoder_seen = true
      }
    PushKind(_) =>
      if self.role == Server {
        raise fault(
          StreamCreationError,
          "a push stream opened towards a server (RFC 9114 §6.2.2)",
        )
      }
    ReservedKind(_) => ()
  }
}

///|
/// Record the peer's settings, once its control stream has carried them.
pub fn Conn::accept_settings(self : Conn, settings : Settings) -> Unit {
  self.peer_settings = Some(settings)
}

///|
/// A stream the connection needed has ended: the control, encoder and decoder streams last as
/// long as the connection (RFC 9114 §6.2.1, RFC 9204 §4.2), so one of them closing is
/// H3_CLOSED_CRITICAL_STREAM.
pub fn Conn::close_stream(_self : Conn, kind : Stream) -> Unit raise Refused {
  if kind.is_critical() {
    raise fault(
      ClosedCriticalStream,
      "the \{kind.label()} closed (RFC 9114 §6.2.1, RFC 9204 §4.2)",
    )
  }
}

///|
/// Accept a peer's unidirectional stream from its opening bytes: classify it and, for the control
/// stream, decode and keep the peer's SETTINGS. A second control stream, a control stream not
/// opening with SETTINGS, and a server receiving a push stream are all connection errors
/// (RFC 9114 §6.2).
pub fn Conn::accept_uni_stream(
  self : Conn,
  bytes : Bytes,
) -> Event raise Refused {
  let kind = match Stream::decode(bytes[:]) {
    Some((kind, _)) => kind
    None => raise fault(FrameError, "a truncated unidirectional stream header")
  }
  self.open_stream(kind)
  match kind {
    ControlKind => {
      let settings = match read_control(bytes[:]) {
        Some(s) => s
        None =>
          raise fault(
            MissingSettings,
            "a control stream that does not open with a SETTINGS frame (RFC 9114 §6.2.1)",
          )
      }
      self.accept_settings(settings)
      ControlEstablished(settings)
    }
    EncoderKind => QpackEncoder
    DecoderKind => QpackDecoder
    PushKind(id) => Push(id)
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
