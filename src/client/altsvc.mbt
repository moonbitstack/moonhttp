// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How long an `Alt-Svc` value is fresh when it says nothing about it: a day
/// (RFC 7838 §3.1).
pub let lifespan : Int32 = 24 * 60 * 60

///|
/// An alternative service: one way to reach an origin that is not its own host
/// and port (RFC 7838 §2).
///
/// It is identified by the ALPN protocol, a host and a port — and it is
/// authoritative for the *origin*, not for itself: a connection to it still
/// presents the origin's name in TLS and its `Host`, which is what makes an
/// alternative a redirection rather than a different site.
pub(all) struct Alternative {
  /// The ALPN protocol name, as RFC 7301 defines it, percent-decoded.
  protocol : String
  /// The host to connect to, or `None` for the origin's own.
  host : String?
  /// The port to connect to. Never absent: an authority without one is not an
  /// alternative service.
  port : Int32
  /// How many seconds the advertisement is fresh for, from `ma` — a day when the
  /// field does not say.
  lifespan : Int32
  /// Whether the advertisement outlives a change of network, from `persist=1`.
  persist : Bool
} derive(Eq, Debug)

///|
pub extend Alternative with Eq::{equal, not_equal}

///|
pub extend Alternative with Debug::{to_repr}

///|
/// The alternatives one `Alt-Svc` field names, in the order the server prefers
/// them, or `None` for `clear` — which says the origin wants every alternative it
/// ever advertised forgotten, including any in the same field (§3).
///
/// A member this reader cannot make sense of is dropped rather than refusing the
/// field: the others are still what the origin said, and an unreadable one is no
/// reason to stop using the ones that read.
pub fn altsvc(value : StringView) -> Array[Alternative]? {
  let text = trim(value.to_owned())
  if lower(text) == "clear" {
    return None
  }
  let out : Array[Alternative] = []
  for piece in pieces(text, ',') {
    match one(piece) {
      Some(alternative) => out.push(alternative)
      None => ()
    }
  }
  Some(out)
}

///|
/// One `alt-value`: a protocol-id, an equals sign, a quoted authority, and the
/// parameters after it (§3).
fn one(piece : String) -> Alternative? {
  let piece = trim(piece)
  let at = match piece.find("=") {
    Some(at) => at
    None => return None
  }
  let protocol = unescape(trim(piece[:at].to_owned()))
  if protocol.length() == 0 {
    return None
  }
  // The authority is a quoted string, and everything after it is parameters.
  let rest = trim(piece[at + 1:].to_owned())
  if rest.length() < 2 || rest[0] != '"' {
    return None
  }
  let close = match rest[1:].find("\"") {
    Some(index) => index + 1
    None => return None
  }
  let authority = rest[1:close].to_owned()
  let (host, port) = match authority_port(authority) {
    Some(pair) => pair
    None => return None
  }
  let mut lifespan = lifespan
  let mut persist = false
  for parameter in pieces(rest[close + 1:].to_owned(), ';') {
    let parameter = trim(parameter)
    if parameter.length() == 0 {
      continue
    }
    let (name, value) = match parameter.find("=") {
      Some(at) =>
        (
          lower(trim(parameter[:at].to_owned())),
          Some(unquote(trim(parameter[at + 1:].to_owned()))),
        )
      None => (lower(parameter), None)
    }
    match name {
      "ma" =>
        match value {
          Some(text) =>
            match seconds(text) {
              Some(n) => lifespan = n
              None => ()
            }
          None => ()
        }
      // §3.1: only "1" means anything, and any other value is ignored.
      "persist" => if value is Some("1") { persist = true }
      _ => ()
    }
  }
  Some({ protocol, host, port, lifespan, persist, })
}

///|
/// The `[host]:port` an alternative is reached at (§3).
fn authority_port(text : String) -> (String?, Int32)? {
  let mut at = -1
  for i in 0..<text.length() {
    if text[i] == ':' {
      at = i
    }
  }
  if at < 0 {
    return None
  }
  let port = match seconds(text[at + 1:].to_owned()) {
    Some(port) => port
    None => return None
  }
  if port < 1 || port > 65535 {
    return None
  }
  let host = text[:at].to_owned()
  if host.length() == 0 {
    Some((None, port))
  } else if host.length() >= 2 &&
    host[0] == '[' &&
    host[host.length() - 1] == ']' {
    Some((Some(host[1:host.length() - 1].to_owned()), port))
  } else {
    Some((Some(host), port))
  }
}

///|
/// The field value for this alternative, in the form §3 prints.
pub fn Alternative::encode(self : Alternative) -> String {
  let out = StringBuilder()
  out.write_string(self.protocol)
  out.write_string("=\"")
  match self.host {
    Some(host) =>
      if host.contains(":") {
        out.write_string("[" + host + "]")
      } else {
        out.write_string(host)
      }
    None => ()
  }
  out.write_string(":" + self.port.to_string() + "\"")
  if self.lifespan != lifespan {
    out.write_string("; ma=" + self.lifespan.to_string())
  }
  if self.persist {
    out.write_string("; persist=1")
  }
  out.to_string()
}

///|
/// Whether the advertisement is still fresh (§2.2, §3.1): a day from when the
/// response carrying it was generated, or for as long as `ma` says.
///
/// Alt-Svc has a freshness lifetime of its own, which a response's `Cache-Control`
/// does not touch: the section is explicit that a cached response's lifetime says
/// nothing about how long its alternatives live.
pub fn Alternative::fresh(
  self : Alternative,
  issued~ : @moondate.Moment,
  now~ : @moondate.Moment,
) -> Bool {
  match now.diff(issued) {
    Some(span) => span.seconds() < self.lifespan.to_int64()
    None => false
  }
}

///|
/// The alternative to try first: the server's own order, filtered to the protocols
/// this client speaks and to advertisements that have not expired (§2.4).
///
/// A client that speaks none of them, or holds only stale advertisements, gets
/// `None` and stays on the origin.
pub fn best(
  alternatives : ArrayView[Alternative],
  protocols~ : ArrayView[String],
  issued~ : @moondate.Moment,
  now~ : @moondate.Moment,
) -> Alternative? {
  for alternative in alternatives {
    if !alternative.fresh(issued~, now~) {
      continue
    }
    for protocol in protocols {
      if alternative.protocol == protocol {
        return Some(alternative)
      }
    }
  }
  None
}

///|
/// The authority to connect to: the alternative's host and port, with the origin's
/// host where the field named none (§2).
pub fn Alternative::authority(
  self : Alternative,
  origin~ : @moonurl.Url,
) -> String {
  let host = match self.host {
    Some(host) => host
    None => origin.host.unwrap_or("")
  }
  if host.contains(":") {
    "[" + host + "]:" + self.port.to_string()
  } else {
    host + ":" + self.port.to_string()
  }
}

///|
/// A protocol-id's percent-encoded octets resolved (§3): an ALPN name may hold
/// octets a token cannot, and those are escaped in the field.
fn unescape(text : String) -> String {
  if !text.contains("%") {
    return text
  }
  let out : Array[Byte] = []
  let mut i = 0
  while i < text.length() {
    if text[i] == '%' && i + 2 < text.length() {
      match byte(text[i + 1], text[i + 2]) {
        Some(value) => {
          out.push(value.to_byte())
          i += 3
        }
        None => {
          out.push(b'%')
          i += 1
        }
      }
    } else {
      out.push(text[i].to_byte())
      i += 1
    }
  }
  @utf8.decode(Bytes::from_array(out)[:]) catch {
    _ => text
  }
}

///|
fn byte(high : UInt16, low : UInt16) -> Int32? {
  let high = hex(high)
  let low = hex(low)
  match (high, low) {
    (Some(high), Some(low)) => Some(high * 16 + low)
    _ => None
  }
}

///|
fn hex(c : UInt16) -> Int32? {
  let n = c.to_int()
  if n >= 0x30 && n <= 0x39 {
    Some(n - 0x30)
  } else if n >= 0x41 && n <= 0x46 {
    Some(n - 0x41 + 10)
  } else if n >= 0x61 && n <= 0x66 {
    Some(n - 0x61 + 10)
  } else {
    None
  }
}

///|
/// A `delta-seconds` value: digits only (§1.2.2 of RFC 9111).
fn seconds(text : String) -> Int32? {
  if text.length() == 0 || text.length() > 9 {
    return None
  }
  let mut out = 0
  for c in text {
    let digit = c.to_int() - 0x30
    if digit < 0 || digit > 9 {
      return None
    }
    out = out * 10 + digit
  }
  Some(out)
}
