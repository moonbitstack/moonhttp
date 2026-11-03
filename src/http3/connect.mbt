// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// WebSocket over HTTP/3 (RFC 9220). The mechanism is the extended CONNECT of
// RFC 8441, carried by a request stream instead of an HTTP/2 stream: the
// pseudo-headers `:method`, `:protocol`, `:scheme`, `:authority` and `:path`, and
// a server setting — SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) — that tells a
// client the method may be used at all. Once the server answers 2xx, the stream
// is no longer an HTTP message stream; the WebSocket frames of `ws` ride its DATA
// frames, which is the caller's business and not this layer's.

///|
/// The `:protocol` value RFC 8441 §4 gives a WebSocket, which RFC 9220 §3 carries
/// over HTTP/3 unchanged.
pub let websocket : String = "websocket"

///|
/// Whether these settings let a peer send `:protocol` (RFC 9220 §3, RFC 8441 §3).
///
/// A server advertises it with SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, and a client
/// must wait for that value before it sends an extended CONNECT; one sent earlier is
/// a connection error, which is what [`Upgrade::of`] reports on the server side.
pub fn Settings::connect_protocol(self : Settings) -> Bool {
  self.enable_connect_protocol
}

///|
/// The request stream that opens an extended CONNECT (RFC 9220 §3, RFC 8441 §4): the
/// five pseudo-headers that name the method, the protocol, and the target.
///
/// `headers` are the ordinary fields the protocol asks for — for a WebSocket,
/// `sec-websocket-version` and `sec-websocket-key` from RFC 6455 §4.1. The request
/// carries no body; the stream is half-closed once the server answers.
pub fn connect(
  scheme : String,
  authority : String,
  path : String,
  protocol : String,
  headers : Array[@header.Header],
) -> Bytes {
  let all : Array[@header.Header] = [
    @header.Header::of(":method", "CONNECT"),
    @header.Header::of(":protocol", protocol),
    @header.Header::of(":scheme", scheme),
    @header.Header::of(":authority", authority),
    @header.Header::of(":path", path),
  ]
  for h in headers {
    all.push(h)
  }
  message(all, b"")
}

///|
/// The extended CONNECT a client sends to open a WebSocket: [`connect`] with the one
/// protocol RFC 8441 names.
pub fn websocket_request(
  scheme : String,
  authority : String,
  path : String,
  headers : Array[@header.Header],
) -> Bytes {
  connect(scheme, authority, path, websocket, headers)
}

///|
/// Whether `request` is a WebSocket extended CONNECT, without judging whether this
/// endpoint enabled the method.
pub fn is_websocket(request : Request) -> Bool {
  request.meth == "CONNECT" && request.protocol == websocket
}

///|
/// What a request asks of a server that may take an extended CONNECT, and whether
/// this server can answer it (RFC 9220 §3).
#derive(Eq, Debug)
pub(all) enum Upgrade {
  /// A WebSocket upgrade this endpoint accepts.
  Accept
  /// A `:protocol` this endpoint does not implement, which §3 answers with 501.
  Unsupported(String)
  /// A request that cannot be an extended CONNECT here: the client used `:protocol`
  /// before this endpoint enabled it, or named the wrong pseudo-headers for one.
  Refused(String)
}

///|
pub extend Upgrade with Eq::{equal, not_equal}

///|
pub extend Upgrade with Debug::{to_repr}

///|
/// Read what `request` asks for against `settings` (RFC 9220 §3).
///
/// The order of the checks is the order the protocol cares about: a `:protocol`
/// before the setting was sent is the client's error whatever else the request says;
/// then the request has to be an extended CONNECT at all; then its pseudo-headers
/// have to be the non-empty set §4 requires; and only then does the protocol name
/// decide between accepting it and answering 501.
pub fn Upgrade::of(request : Request, settings~ : Settings) -> Upgrade {
  if !settings.enable_connect_protocol {
    Refused(
      "the client sent :protocol before SETTINGS_ENABLE_CONNECT_PROTOCOL was sent",
    )
  } else if request.meth != "CONNECT" || request.protocol == "" {
    Refused("not an extended CONNECT")
  } else if request.scheme == "" ||
    request.path == "" ||
    request.authority == "" {
    Refused("an extended CONNECT without :scheme, :path or :authority")
  } else if request.protocol == websocket {
    Accept
  } else {
    Unsupported(request.protocol)
  }
}

///|
/// The response stream for `upgrade`: a 200 that turns the stream into WebSocket
/// data, a 501 for a protocol this endpoint does not implement, or a 400 for a
/// request that could not be one at all.
///
/// A `Refused` is really H3_MESSAGE_ERROR, which closes the connection rather than
/// the stream; the 400 is what a server sends when it would rather answer than tear
/// the connection down, and a caller that wants the connection error skips this and
/// closes instead.
pub fn Upgrade::response(
  self : Upgrade,
  headers~ : Array[@header.Header] = [],
) -> Response {
  match self {
    Accept => Response::{ status: "200", headers, body: b"", }
    Unsupported(_) => Response::{ status: "501", headers: [], body: b"", }
    Refused(_) => Response::{ status: "400", headers: [], body: b"", }
  }
}

///|
/// Answer an extended CONNECT: the verdict, written as the response stream.
pub fn websocket_response(
  request : Request,
  settings~ : Settings,
  headers~ : Array[@header.Header] = [],
) -> Response {
  Upgrade::of(request, settings~).response(headers~)
}
