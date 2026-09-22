// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The string appended to a client's key before hashing (RFC 6455 §4.2.2).
///
/// It is there so that a server which merely echoes what it was sent cannot pass for one
/// that understood the protocol — a cached HTTP proxy, say.
pub let guid : String = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

///|
/// The `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`: base64 of the SHA-1 of
/// the key with the GUID appended (RFC 6455 §4.2.2).
pub fn accept(key : String) -> String {
  @base64.encode(@sha1.hash(@utf8.encode(key + guid)[:])[:])
}

///|
/// The `Sec-WebSocket-Key` for sixteen random bytes (RFC 6455 §4.1).
///
/// The randomness is the caller's: the key has to be unpredictable to the server, and a
/// library with no entropy of its own should not invent any. A key of another length is
/// what the caller asked for and is encoded as given.
pub fn key(random : BytesView) -> String {
  @base64.encode(random)
}

///|
/// The first subprotocol the client offered that this endpoint supports, or `None`
/// (RFC 6455 §4.2.2). The client's order is its preference, so it is the one that decides.
pub fn subprotocol(
  offered : ArrayView[String],
  supported : ArrayView[String],
) -> String? {
  for want in offered {
    for have in supported {
      if want == have {
        return Some(want)
      }
    }
  }
  None
}

///|
/// A client's opening handshake (RFC 6455 §4.1): the GET that asks for the upgrade.
///
/// `key` comes from `key`, over bytes the caller drew. `protocols` and `origin` are
/// written only when given, because §4.1 makes both optional and a server may treat an
/// empty list as a request for a subprotocol it cannot provide.
pub fn request(
  host~ : String,
  key~ : String,
  path? : String = "/",
  protocols? : ArrayView[String] = [][:],
  origin? : String,
  extra? : ArrayView[(String, String)] = [][:],
) -> Bytes {
  let buf = StringBuilder()
  buf.write_string("GET " + path + " HTTP/1.1\r\n")
  buf.write_string("Host: " + host + "\r\n")
  buf.write_string("Upgrade: websocket\r\n")
  buf.write_string("Connection: Upgrade\r\n")
  buf.write_string("Sec-WebSocket-Key: " + key + "\r\n")
  buf.write_string("Sec-WebSocket-Version: 13\r\n")
  if protocols.length() > 0 {
    buf.write_string("Sec-WebSocket-Protocol: " + join(protocols) + "\r\n")
  }
  match origin {
    Some(o) => buf.write_string("Origin: " + o + "\r\n")
    None => ()
  }
  for h in extra {
    buf.write_string(h.0 + ": " + h.1 + "\r\n")
  }
  buf.write_string("\r\n")
  @utf8.encode(buf.to_string())
}

///|
/// The `101 Switching Protocols` that completes the handshake (RFC 6455 §4.2.2): the
/// upgrade headers, the proof, and the one subprotocol the server selected.
pub fn response(
  key : String,
  protocol? : String,
  extra? : ArrayView[(String, String)] = [][:],
) -> Bytes {
  let buf = StringBuilder()
  buf.write_string("HTTP/1.1 101 Switching Protocols\r\n")
  buf.write_string("Upgrade: websocket\r\n")
  buf.write_string("Connection: Upgrade\r\n")
  buf.write_string("Sec-WebSocket-Accept: " + accept(key) + "\r\n")
  match protocol {
    Some(p) => buf.write_string("Sec-WebSocket-Protocol: " + p + "\r\n")
    None => ()
  }
  for h in extra {
    buf.write_string(h.0 + ": " + h.1 + "\r\n")
  }
  buf.write_string("\r\n")
  @utf8.encode(buf.to_string())
}

///|
/// Why a handshake was not accepted, so a server can answer with the right status and a
/// client can say what the server got wrong.
pub(all) suberror Refused {
  /// `Upgrade` or `Connection` does not ask for a WebSocket (§4.2.1).
  NotAnUpgrade(String)
  /// A version other than 13, which §4.4 answers with `Sec-WebSocket-Version: 13`.
  Version(got~ : String)
  /// `Sec-WebSocket-Key` is missing, or not sixteen bytes of base64 (§4.2.1).
  Key(String)
  /// The server's `Sec-WebSocket-Accept` is not the proof for the key that was sent.
  Proof(want~ : String, got~ : String)
} derive(Eq, Debug)

///|
/// A refusal prints as the fault it is.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    NotAnUpgrade(m) => logger.write_string("NotAnUpgrade(" + m + ")")
    Version(got~) => logger.write_string("Version(got=" + got + ")")
    Key(m) => logger.write_string("Key(" + m + ")")
    Proof(want~, got~) =>
      logger.write_string("Proof(want=" + want + ", got=" + got + ")")
  }
}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

///|
/// Read a client's handshake headers and answer with its key and the subprotocols it
/// offered (RFC 6455 §4.2.1).
///
/// Header names are matched without regard to case, and `Connection` is read as the
/// comma-separated list §4.2.1 allows it to be, because a proxy may have added to it.
/// A version other than 13 is refused, which is what §4.4 asks a server to answer.
pub fn read(
  headers : ArrayView[(String, String)],
) -> (String, Array[String]) raise Refused {
  guard find(headers, "upgrade") is Some(upgrade) else {
    raise NotAnUpgrade("no Upgrade header")
  }
  if lower(upgrade.trim(chars=" ").to_owned()) != "websocket" {
    raise NotAnUpgrade("Upgrade is not websocket: " + upgrade)
  }
  guard find(headers, "connection") is Some(connection) else {
    raise NotAnUpgrade("no Connection header")
  }
  if !has(connection, "upgrade") {
    raise NotAnUpgrade("Connection does not ask for an upgrade: " + connection)
  }
  match find(headers, "sec-websocket-version") {
    Some(v) => if v.trim(chars=" ").to_owned() != "13" { raise Version(got=v) }
    None => raise Version(got="")
  }
  guard find(headers, "sec-websocket-key") is Some(k) else {
    raise Key("no Sec-WebSocket-Key")
  }
  let k = k.trim(chars=" ").to_owned()
  let raw = @base64.decode(k[:]) catch { _ => raise Key("not base64: " + k) }
  if raw.length() != 16 {
    raise Key("not sixteen bytes: " + k)
  }
  let offered = match find(headers, "sec-websocket-protocol") {
    Some(p) => split(p)
    None => []
  }
  (k, offered)
}

///|
/// Check a server's response headers against the key that was sent (RFC 6455 §4.1).
///
/// A client that skips this accepts an upgrade from anything that can write `101`, which
/// is the case §4.2.2's proof exists to rule out.
pub fn check(
  key : String,
  headers : ArrayView[(String, String)],
) -> Unit raise Refused {
  guard find(headers, "upgrade") is Some(upgrade) else {
    raise NotAnUpgrade("no Upgrade header")
  }
  if lower(upgrade.trim(chars=" ").to_owned()) != "websocket" {
    raise NotAnUpgrade("Upgrade is not websocket: " + upgrade)
  }
  guard find(headers, "connection") is Some(connection) else {
    raise NotAnUpgrade("no Connection header")
  }
  if !has(connection, "upgrade") {
    raise NotAnUpgrade("Connection does not confirm the upgrade: " + connection)
  }
  let want = accept(key)
  match find(headers, "sec-websocket-accept") {
    Some(got) => {
      let got = got.trim(chars=" ").to_owned()
      if got != want {
        raise Proof(want~, got~)
      }
    }
    None => raise Proof(want~, got="")
  }
}

///|
/// The first header of that name, matched without regard to case.
fn find(headers : ArrayView[(String, String)], name : String) -> String? {
  for h in headers {
    if lower(h.0) == name {
      return Some(h.1)
    }
  }
  None
}

///|
/// Whether a comma-separated header names `token`, ignoring case and surrounding space.
fn has(header : String, token : String) -> Bool {
  for part in split(header) {
    if lower(part) == token {
      return true
    }
  }
  false
}

///|
/// A comma-separated header's items, trimmed.
fn split(header : String) -> Array[String] {
  let out : Array[String] = []
  for part in header.split(",") {
    let one = part.trim(chars=" ").to_owned()
    if one.length() > 0 {
      out.push(one)
    }
  }
  out
}

///|
/// Header names and the tokens in them are case-insensitive (RFC 9110 §5.1), and only
/// ASCII case at that.
fn lower(s : String) -> String {
  let out = StringBuilder()
  for c in s {
    let n = c.to_int()
    out.write_char(
      if n >= 0x41 && n <= 0x5a {
        (n + 32).unsafe_to_char()
      } else {
        c
      },
    )
  }
  out.to_string()
}

///|
/// The items of a list header, comma-separated as §4.1 writes them.
fn join(items : ArrayView[String]) -> String {
  let out = StringBuilder()
  for i = 0; i < items.length(); i = i + 1 {
    if i > 0 {
      out.write_string(", ")
    }
    out.write_string(items[i])
  }
  out.to_string()
}
