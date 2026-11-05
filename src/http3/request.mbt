// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Serving an HTTP/3 request on a request stream (RFC 9114 §4.1): a client opens a bidirectional
// stream carrying a HEADERS frame (the pseudo-headers :method/:scheme/:authority/:path and the
// regular headers) and DATA frames (the body); the server reads that into a request, runs a
// handler, and writes the response — a HEADERS frame with :status and the DATA of the body — back
// on the same stream.
//
// Two things a server must judge before the application sees anything are here: the order the
// frames may arrive in, and the field section itself. Both are connection errors (§4.1.2, §7.2)
// because a peer that gets either wrong has a different idea of what the streams mean than this
// endpoint does, and no single stream reset settles that.

///|
/// A decoded HTTP/3 request: the pseudo-headers pulled out, the remaining header fields, and the
/// body.
pub(all) struct Request {
  meth : String
  scheme : String
  authority : String
  path : String
  /// The `:protocol` of an extended CONNECT (RFC 9220 §3), or the empty string on any
  /// other request. A WebSocket upgrade carries `"websocket"` here.
  protocol : String
  headers : Array[@header.Header]
  body : Bytes
}

///|
/// Decode an HTTP/3 request stream into a request, separating the pseudo-headers from the
/// regular ones (RFC 9114 §4.3.1). `None` when the field section is not a well-formed request at
/// all — the required pseudo-headers absent, one of them twice, or a field the protocol forbids.
/// Raises on a malformed stream.
///
/// `strict` also applies §7.2's placement rules, so a frame that belongs on the control
/// stream — a SETTINGS say — is refused rather than read past. It is off by default
/// because a reader that only wants the request need not care what else arrived.
pub fn read_request(
  bytes : Bytes,
  strict~ : Bool = false,
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
  guard request_fault(all_headers) is None else { return None }
  let mut meth = ""
  let mut scheme = ""
  let mut authority = ""
  let mut path = ""
  let mut protocol = ""
  let regular : Array[@header.Header] = []
  for h in all_headers {
    let (name, value) = h.ascii()
    match name {
      ":method" => meth = value
      ":scheme" => scheme = value
      ":authority" => authority = value
      ":path" => path = value
      ":protocol" => protocol = value
      _ => regular.push(h)
    }
  }
  Some({ meth, scheme, authority, path, protocol, headers: regular, body, })
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

///|
/// Whether `name` carries a byte an HTTP/3 field name may not: upper case (RFC 9114 §4.1.2 —
/// field names are lower case, and one that is not has been rewritten by an intermediary).
fn has_upper(name : Bytes) -> Bool {
  for i = 0; i < name.length(); i = i + 1 {
    let c = name[i].to_int()
    if c >= 0x41 && c <= 0x5a {
      return true
    }
  }
  false
}

///|
/// Whether a field is one RFC 9114 §4.2 forbids in a request: the fields that describe a single
/// hop in HTTP/1.1, and TE with anything but `trailers`.
fn is_connection_specific(name : String, value : String) -> Bool {
  match name {
    "connection"
    | "keep-alive"
    | "proxy-connection"
    | "transfer-encoding"
    | "upgrade" => true
    "te" => value.to_lower().trim() != "trailers"
    _ => false
  }
}

///|
/// Why a request's field section is malformed, or `None` when it is not (RFC 9114 §4.1.1,
/// §4.1.3, §4.2, §4.3.1 and RFC 9220 §3).
///
/// The pseudo-headers come first, each at most once, and only the five the protocol defines.
/// The ones a method needs are then checked: an ordinary request names :method, :scheme and
/// :path; a CONNECT names only :authority; an extended CONNECT also names :scheme, :path and
/// :authority beside :protocol.
fn request_fault(fields : Array[@header.Header]) -> String? {
  let seen : Array[String] = []
  let mut regular = false
  let mut verb = ""
  let mut scheme = ""
  let mut path = ""
  let mut authority = ""
  let mut protocol = ""
  let mut host = false
  for field in fields {
    let (name, value) = field.ascii()
    if has_upper(field.name) {
      return Some(
        "the field name \{name}, which is not lower case (RFC 9114 §4.1.2)",
      )
    }
    if field.name.length() > 0 && field.name[0] == b':' {
      if regular {
        return Some(
          "the pseudo-header \{name} after the regular fields (RFC 9114 §4.1.3)",
        )
      }
      if seen.contains(name) {
        return Some("the pseudo-header \{name} twice (RFC 9114 §4.1.3)")
      }
      seen.push(name)
      match name {
        ":method" => verb = value
        ":scheme" => scheme = value
        ":path" => path = value
        ":authority" => authority = value
        ":protocol" => protocol = value
        _ =>
          return Some(
            "the pseudo-header \{name}, which HTTP/3 does not define (RFC 9114 §4.3)",
          )
      }
    } else {
      regular = true
      if name == "host" {
        host = true
      }
      if is_connection_specific(name, value) {
        return Some("the connection-specific field \{name} (RFC 9114 §4.2)")
      }
    }
  }
  if verb == "" {
    return Some("a request with no :method (RFC 9114 §4.3.1)")
  }
  if verb == "CONNECT" {
    if protocol != "" {
      if scheme == "" || path == "" || authority == "" {
        return Some(
          "an extended CONNECT without :scheme, :path or :authority (RFC 9220 §3)",
        )
      }
    } else if scheme != "" || path != "" || authority == "" {
      return Some("a CONNECT without :authority, or with :scheme or :path")
    }
  } else {
    if scheme == "" || path == "" {
      return Some("a request without :scheme or :path (RFC 9114 §4.3.1)")
    }
    if protocol != "" {
      return Some(
        ":protocol on a request whose method is not CONNECT (RFC 9220 §3)",
      )
    }
    // §4.3.1: a scheme with a mandatory authority — http and https among them — needs one, in
    // :authority or in a Host field.
    if (scheme == "http" || scheme == "https") && authority == "" && !host {
      return Some(
        "a \{scheme} request with neither :authority nor Host (RFC 9114 §4.3.1)",
      )
    }
  }
  None
}

///|
/// Why a trailing field section is malformed, or `None` when it is not (RFC 9114 §4.1): a
/// trailing section carries no pseudo-headers and none of the §4.2 fields either.
fn trailer_fault(fields : Array[@header.Header]) -> String? {
  for field in fields {
    let (name, value) = field.ascii()
    if has_upper(field.name) {
      return Some(
        "the field name \{name}, which is not lower case (RFC 9114 §4.1.2)",
      )
    }
    if field.name.length() > 0 && field.name[0] == b':' {
      return Some("the pseudo-header \{name} in the trailers (RFC 9114 §4.1)")
    }
    if is_connection_specific(name, value) {
      return Some("the connection-specific field \{name} (RFC 9114 §4.2)")
    }
  }
  None
}

// A request stream as it arrives (RFC 9114 §4.1): the frame order, the field sections in it, and
// the body handed over as it comes rather than held whole. QUIC delivers a stream in pieces at
// whatever pace the network gives them, so the reader keeps the octets of a frame whose end has
// not arrived and yields only what is complete.

///|
/// What a request stream has produced.
#derive(Eq, Debug)
pub(all) enum Part {
  /// The request's head: the field section, pseudo-headers and all, decoded and checked.
  Head(Array[@header.Header])
  /// The next piece of the body, at most `chunk` octets of one DATA frame.
  Data(Bytes)
  /// The trailing field section.
  Trailers(Array[@header.Header])
}

///|
pub extend Part with Debug::{to_repr}

///|
pub extend Part with Eq::{not_equal, equal}

///|
/// One request stream's reader.
///
/// `head` says the field section that names the request has arrived, and `trailers` that the
/// closing one has: between them DATA carries the body, before them it is a fault, and after them
/// nothing more may come.
pub struct Incoming {
  mut held : Bytes
  mut head : Bool
  mut trailers : Bool
  mut left : UInt64
  limit : UInt64
  chunk : Int32
}

///|
/// A reader for a request stream whose field sections may not exceed `limit` octets
/// (SETTINGS_MAX_FIELD_SECTION_SIZE, RFC 9114 §7.1), handing the body over in pieces of at most
/// `chunk` octets.
pub fn Incoming::new(
  limit~ : UInt64 = 16384UL,
  chunk~ : Int32 = 16384,
) -> Incoming {
  { held: b"", head: false, trailers: false, left: 0UL, limit, chunk, }
}

///|
/// Take the bytes that just arrived on the stream and return the parts they complete. A partial
/// frame is kept until its rest comes.
///
/// What §4.1 and §7.2 make a connection error is refused here: DATA before HEADERS or after the
/// trailers, a frame that only a control stream carries, a field section over `limit`, and a
/// head or trailer section that is malformed.
pub fn Incoming::feed(
  self : Incoming,
  bytes : Bytes,
) -> Array[Part] raise Refused {
  let out : Array[Part] = []
  if bytes.length() > 0 {
    self.held = joined(self.held, bytes)
  }
  for ;; {
    if self.left > 0UL && self.held.length() > 0 {
      let have = self.held.length().to_uint64()
      let mut take = if have < self.left { have } else { self.left }
      if take > self.chunk.to_uint64() {
        take = self.chunk.to_uint64()
      }
      out.push(Data(self.held[0:take.to_int()].to_owned()))
      self.held = self.held[take.to_int():].to_owned()
      self.left = self.left - take
      continue
    }
    if self.held.length() == 0 {
      break
    }
    let (frame_type, type_len) = match @quic.decode(self.held[:]) {
      Some(v) => v
      None => break
    }
    let (length, len_len) = match @quic.decode(self.held[type_len:]) {
      Some(v) => v
      None => break
    }
    let header_len = type_len + len_len
    if frame_type == data {
      // §4.1: the body rides DATA frames, after the head and before the trailers.
      if !self.head {
        raise fault(FrameUnexpected, "DATA before HEADERS (RFC 9114 §4.1)")
      }
      if self.trailers {
        raise fault(FrameUnexpected, "DATA after the trailers (RFC 9114 §4.1)")
      }
      self.held = self.held[header_len:].to_owned()
      self.left = length
      continue
    }
    if length > self.limit {
      raise fault(
        ExcessiveLoad,
        "a frame of \{length} octets, over the \{self.limit} this endpoint accepts",
      )
    }
    if self.held.length() < header_len + length.to_int() {
      break
    }
    let payload = self.held[header_len:header_len + length.to_int()].to_owned()
    self.held = self.held[header_len + length.to_int():].to_owned()
    if frame_type == headers {
      if self.trailers {
        raise fault(
          FrameUnexpected,
          "a HEADERS frame after the trailers (RFC 9114 §4.1)",
        )
      }
      let fields = section(payload)
      if !self.head {
        match request_fault(fields) {
          Some(why) => raise fault(MessageError, why)
          None => {
            self.head = true
            out.push(Head(fields))
          }
        }
      } else {
        match trailer_fault(fields) {
          Some(why) => raise fault(MessageError, why)
          None => {
            self.trailers = true
            out.push(Trailers(fields))
          }
        }
      }
    } else if is_reserved(frame_type) {
      raise fault(
        FrameUnexpected,
        "the HTTP/2 frame 0x\{frame_type} on a request stream (RFC 9114 §7.2)",
      )
    } else if frame_type == settings_type ||
      frame_type == goaway ||
      frame_type == max_push_id ||
      frame_type == cancel_push ||
      frame_type == push_promise {
      raise fault(
        FrameUnexpected,
        "a control or push frame on a request stream (RFC 9114 §7.2)",
      )
    }
    // Any other type is reserved: §9 lets a peer exercise it, and it is ignored.
  }
  out
}

///|
/// The peer ended the request stream. A stream that ends between the octets of a frame never
/// carried the frame, which §7.1 makes H3_FRAME_ERROR.
pub fn Incoming::end(self : Incoming) -> Unit raise Refused {
  if self.left > 0UL || self.held.length() > 0 {
    raise fault(FrameError, "a request stream ending inside a frame")
  }
}

///|
/// Decode a field section, turning a QPACK refusal into the connection error §4.1.2 names for
/// one: the two ends no longer agree about the table.
fn section(payload : Bytes) -> Array[@header.Header] raise Refused {
  let got = Ok(@qpack.decode(payload)) catch { e => Err(e) }
  match got {
    Ok(fields) => fields
    Err(e) => raise fault(QpackDecompressionFailed, e.detail())
  }
}
