// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The extension's name on the wire (RFC 7692 §5).
pub let name : String = "permessage-deflate"

///|
/// Which end of the connection is asking, which decides whose window and whose
/// takeover flag apply (§7.1).
///
/// Every parameter is directional: `server_max_window_bits` limits what the server
/// compresses with and what the client decompresses with, and says nothing about
/// the client's own compressor. One enum keeps that straight in one place instead
/// of at every call site.
pub(all) enum Role {
  Client
  Server
} derive(Eq, Debug)

///|
pub extend Role with Eq::{equal, not_equal}

///|
pub extend Role with Debug::{to_repr}

///|
/// The four parameters of §7.1 as agreed for one connection.
///
/// The window sizes are in bits, 8 to 15: the base-two logarithm of the LZ77
/// sliding window each side compresses with, so 15 is DEFLATE's own 32 KiB and 8
/// is 256 bytes. The takeover flags say whether a compressor may keep its window
/// from one message to the next — kept, a later message can point back into an
/// earlier one; reset, each message stands alone and the receiver need not reserve
/// the memory for it.
///
/// An absent parameter means the default, so a struct of defaults is also a valid
/// set of agreed terms. That is also why `client_window_named` is here: an offer
/// may name `client_max_window_bits` with no value, and a response may only carry
/// the parameter when the offer did (§7.1.2.2).
pub(all) struct Extension {
  /// The server's compressor keeps its window between messages.
  server_takeover : Bool
  /// The client's compressor keeps its window between messages.
  client_takeover : Bool
  /// The server's window, in bits.
  server_window : Int32
  /// The client's window, in bits.
  client_window : Int32
  /// Whether `client_max_window_bits` is named at all.
  client_window_named : Bool
} derive(Eq, Debug)

///|
pub extend Extension with Eq::{equal, not_equal}

///|
pub extend Extension with Debug::{to_repr}

///|
/// The terms with nothing named: both directions keep a 32 KiB window, which is
/// what a connection that agreed to permessage-deflate and nothing else has.
pub let defaults : Extension = {
  server_takeover: true,
  client_takeover: true,
  server_window: 15,
  client_window: 15,
  client_window_named: false,
}

///|
/// Terms with these values, the rest left at their defaults.
pub fn Extension::new(
  server_takeover? : Bool,
  client_takeover? : Bool,
  server_window? : Int32,
  client_window? : Int32,
  client_window_named? : Bool,
) -> Extension {
  let terms = match server_takeover {
    Some(v) => { ..defaults, server_takeover: v, }
    None => defaults
  }
  let terms = match client_takeover {
    Some(v) => { ..terms, client_takeover: v, }
    None => terms
  }
  let terms = match server_window {
    Some(v) => { ..terms, server_window: v, }
    None => terms
  }
  let terms = match client_window {
    Some(v) => { ..terms, client_window: v, }
    None => terms
  }
  match client_window_named {
    Some(v) => { ..terms, client_window_named: v, }
    None => terms
  }
}

///|
/// The parameters as one extension value, written for `role`.
///
/// A parameter at its default is left out, because saying nothing is how the
/// format says "the default". The exception is `client_max_window_bits` in a
/// client's offer, where naming it with no value is the one way to say "I
/// understand this parameter; choose for me".
pub fn Extension::encode(self : Extension, role~ : Role) -> String {
  let out = StringBuilder()
  out.write_string(name)
  if !self.server_takeover {
    out.write_string("; server_no_context_takeover")
  }
  if !self.client_takeover {
    out.write_string("; client_no_context_takeover")
  }
  if self.server_window != 15 {
    out.write_string(
      "; server_max_window_bits=" + self.server_window.to_string(),
    )
  }
  match role {
    Client =>
      if self.client_window_named {
        if self.client_window == 15 {
          out.write_string("; client_max_window_bits")
        } else {
          out.write_string(
            "; client_max_window_bits=" + self.client_window.to_string(),
          )
        }
      }
    Server =>
      // §7.1.2.2: a response carries the parameter only when the offer did, and
      // always with a value.
      if self.client_window_named {
        out.write_string(
          "; client_max_window_bits=" + self.client_window.to_string(),
        )
      }
  }
  out.to_string()
}

///|
/// Read one extension value, or `None` when it is not this extension or names a
/// parameter this one does not have.
///
/// §5.1 makes an unknown parameter a reason to decline rather than to ignore: a
/// parameter exists to change behaviour, and an endpoint that passed over one
/// would be agreeing to something it does not do. The same goes for a value the
/// grammar forbids — a window outside 8 to 15, a number with a leading zero, a
/// `*_no_context_takeover` carrying a value — so those are `None` and not a
/// default.
pub fn Extension::decode(value : StringView) -> Extension? {
  let pieces = pieces(value.to_owned(), ';')
  if pieces.length() == 0 {
    return None
  }
  if lower(trim(pieces[0])) != name {
    return None
  }
  let mut terms = defaults
  for i in 1..<pieces.length() {
    let piece = trim(pieces[i])
    if piece.length() == 0 {
      continue
    }
    let (key, raw) = match piece.find("=") {
      Some(at) => {
        let raw = trim(piece[at + 1:].to_owned())
        (trim(piece[:at].to_owned()), Some(unquote(raw)))
      }
      None => (piece, None)
    }
    match lower(key) {
      "server_no_context_takeover" =>
        if raw is Some(_) {
          return None
        } else {
          terms = { ..terms, server_takeover: false, }
        }
      "client_no_context_takeover" =>
        if raw is Some(_) {
          return None
        } else {
          terms = { ..terms, client_takeover: false, }
        }
      "server_max_window_bits" =>
        match raw {
          Some(text) =>
            match bits(text) {
              Some(w) => terms = { ..terms, server_window: w, }
              None => return None
            }
          None => return None
        }
      "client_max_window_bits" =>
        match raw {
          Some(text) =>
            match bits(text) {
              Some(w) =>
                terms = {
                  ..terms,
                  client_window: w,
                  client_window_named: true,
                }
              None => return None
            }
          None => terms = { ..terms, client_window_named: true, }
        }
      _ => return None
    }
  }
  Some(terms)
}

///|
/// A window size as §7.1.2.1 writes it: decimal, no leading zero, 8 to 15.
fn bits(text : String) -> Int32? {
  if text.length() == 0 || text.length() > 2 {
    return None
  }
  if text.length() > 1 && text[0] == '0' {
    return None
  }
  let mut value = 0
  for c in text {
    let digit = c.to_int() - 0x30
    if digit < 0 || digit > 9 {
      return None
    }
    value = value * 10 + digit
  }
  if value < 8 || value > 15 {
    return None
  }
  Some(value)
}

///|
/// Every permessage-deflate offer in a `Sec-WebSocket-Extensions` value, in the
/// order the client wrote them (RFC 6455 §9.1).
///
/// Offers for other extensions are dropped, and so is an offer for this one that
/// names something it does not have: §5.1 has a server decline those rather than
/// read part of one.
pub fn offers(header : StringView) -> Array[Extension] {
  let out : Array[Extension] = []
  for piece in pieces(header.to_owned(), ',') {
    match Extension::decode(piece[:]) {
      Some(terms) => out.push(terms)
      None => ()
    }
  }
  out
}

///|
/// The first offer this endpoint can accept, as the terms to answer with
/// (§7.1.2.2), or `None` when it can accept none of them.
///
/// `support` is what this endpoint is willing to do; without it, `defaults`.
/// The client's window is the one thing that can make an offer unacceptable:
/// with no `client_max_window_bits` the client will compress with the full
/// 32 KiB, and a server that cannot decompress that has to decline rather than
/// answer and then fail. Everything else is a narrowing, and narrowing is what an
/// answer is for.
pub fn Extension::agree(
  offers : ArrayView[Extension],
  support? : Extension,
) -> Extension? {
  let mine = match support {
    Some(terms) => terms
    None => defaults
  }
  for offer in offers {
    let server_window = if offer.server_window < mine.server_window {
      offer.server_window
    } else {
      mine.server_window
    }
    let (client_window, named) = if offer.client_window_named {
      let asked = if offer.client_window < mine.client_window {
        offer.client_window
      } else {
        mine.client_window
      }
      (asked, true)
    } else if mine.client_window < 15 {
      // The client would use the whole window and this endpoint cannot read it.
      continue
    } else {
      (15, false)
    }
    return Some({
      server_takeover: offer.server_takeover && mine.server_takeover,
      client_takeover: offer.client_takeover && mine.client_takeover,
      server_window,
      client_window,
      client_window_named: named,
    })
  }
  None
}

///|
/// Whether a server's answer stays inside what this client offered (§7.1.2.2).
///
/// A client checks the answer rather than trusting it. A server that answered with
/// a wider window than the offer named, or with `client_max_window_bits` when the
/// offer did not name it, has agreed to something the client never offered, and
/// §7.1.2.2 makes both of those the server's error. A takeover the server turned
/// off without being asked is not an error: §7.1.1.1 lets a server do that to keep
/// its memory.
pub fn Extension::accepts(self : Extension, answer : Extension) -> Bool {
  if answer.client_window_named && !self.client_window_named {
    return false
  }
  if answer.server_window > self.server_window {
    return false
  }
  answer.client_window <= self.client_window
}

///|
/// Reading one direction: the frames a peer sends, decompressed as they arrive.
///
/// A message is decompressed frame by frame rather than at the end, because the
/// ceiling has to be enforced where it is passed: a stream that expands past it
/// must fail the connection then, not after the octets are already in memory.
pub struct Reader {
  inner : @ws.Reader
  inflater : @deflate.Inflater
  limit : Int32
  mut compressed : Bool
  mut in_message : Bool
  mut got : Int32
}

///|
/// A reader for one direction under the agreed terms.
///
/// `role` says which end this is, and so whose parameters apply: a server reads
/// what the client compressed, which is `client_window` and `client_takeover`.
///
/// `limit` bounds one message after decompression. It is not a WebSocket
/// parameter — RFC 7692 sets no ceiling — but a compressed message is the one
/// place where a small frame can ask for unbounded memory, so the bound is the
/// caller's to set and defaults to what `ws` accepts anyway.
pub fn Reader::new(
  extension? : Extension,
  role~ : Role = Server,
  limit~ : Int32 = @ws.limit,
) -> Reader {
  let terms = match extension {
    Some(terms) => terms
    None => defaults
  }
  let (takeover, window) = match role {
    Client => (terms.server_takeover, terms.server_window)
    Server => (terms.client_takeover, terms.client_window)
  }
  {
    inner: @ws.Reader::new(limit~),
    inflater: @deflate.Inflater::new(bits=window, takeover~, limit~),
    limit,
    compressed: false,
    in_message: false,
    got: 0,
  }
}

///|
/// Take one frame with the value of its RSV1 bit, and answer as `ws.Reader` does
/// (RFC 7692 §6, §7.2.2).
///
/// `compressed` is what `ws.decode_extension` reported, which is true only on the
/// first frame of a message. A compressed message's later frames carry their share
/// of the same DEFLATE stream, so what a fragment holds is not a message until the
/// last frame of it has been read.
///
/// A stream that does not decompress fails the connection with 1007, and one that
/// expands past `limit` with 1009.
pub fn Reader::feed(
  self : Reader,
  frame : @ws.Frame,
  compressed~ : Bool = false,
) -> @ws.Step raise @ws.Refused {
  if frame.opcode.is_control() {
    // Control frames are never compressed, and `ws.check_extension` has already
    // refused a set RSV1 on one.
    return self.inner.feed(frame)
  }
  let first = !(frame.opcode is Continuation)
  if first {
    if self.in_message {
      raise @ws.Protocol("a new data frame before the last message finished")
    }
    self.in_message = true
    self.compressed = compressed
    self.got = 0
  }
  let payload = if self.compressed {
    self.inflate(frame.payload, more=!frame.fin)
  } else {
    frame.payload
  }
  let step = self.inner.feed({ fin: frame.fin, opcode: frame.opcode, payload, })
  if frame.fin {
    self.in_message = false
    self.compressed = false
    self.got = 0
  }
  step
}

///|
/// One fragment of a compressed message, expanded.
///
/// The inflater already carries the window when the terms allow it and drops it
/// when they do not, so what is left here is the ceiling and the translation of a
/// DEFLATE fault into the status the connection fails with.
fn Reader::inflate(
  self : Reader,
  payload : Bytes,
  more~ : Bool,
) -> Bytes raise @ws.Refused {
  let out = self.inflater.decompress(payload[:], more~) catch {
    // 1009 for too much, 1007 for anything else: §7.1.7's two failures.
    @deflate.Exceeded(..) =>
      raise @ws.Exceeded(limit=self.limit, got=self.limit.to_int64())
    _ => raise @ws.Payload("a message that does not decompress")
  }
  self.got = self.got + out.length()
  if self.got > self.limit {
    raise @ws.Exceeded(limit=self.limit, got=self.got.to_int64())
  }
  out
}

///|
/// Writing one direction: the messages this endpoint compresses.
pub struct Writer {
  deflater : @deflate.Deflater
  threshold : Int32
}

///|
/// A writer for one direction under the agreed terms.
///
/// `role` says which end this is, and so whose window and takeover flag apply: a
/// server writes with `server_window`, and keeps its window between messages only
/// when `server_takeover` holds.
///
/// `threshold` is the length below which a message is sent as it is. Zero — every
/// message compressed — is what a negotiated extension means and what every
/// implementation does by default; a caller that would rather not spend octets
/// compressing a short message sets it.
pub fn Writer::new(
  extension? : Extension,
  role~ : Role = Server,
  threshold~ : Int32 = 0,
) -> Writer {
  let terms = match extension {
    Some(terms) => terms
    None => defaults
  }
  let (takeover, window) = match role {
    Client => (terms.client_takeover, terms.client_window)
    Server => (terms.server_takeover, terms.server_window)
  }
  { deflater: @deflate.Deflater::new(bits=window, takeover~), threshold, }
}

///|
/// One frame of a data message, and whether its RSV1 bit is set.
///
/// The bit comes back beside the frame because `ws.Frame` has none: RSV1 is the
/// extension's, not the frame layer's, so a caller writes it with
/// `ws.Frame::encode_extension` and reads it back from `ws.decode_extension`.
///
/// A control frame is never compressed (§6.1), so one passed here comes back
/// untouched.
pub fn Writer::frame(
  self : Writer,
  opcode : @ws.Opcode,
  payload : BytesView,
  fin~ : Bool = true,
) -> (@ws.Frame, Bool) {
  if opcode.is_control() || payload.length() < self.threshold {
    return ({ fin, opcode, payload: payload.to_owned(), }, false)
  }
  ({ fin, opcode, payload: self.deflater.compress(payload), }, true)
}

// ------------------------------------------------------------------ the text

///|
/// Split on `sep`, but not inside a quoted string: an extension parameter's value
/// may be quoted (RFC 6455 §9.1), and a quoted value may hold the separator.
fn pieces(text : String, sep : Char) -> Array[String] {
  let out : Array[String] = []
  let mut buf = StringBuilder()
  let mut quoted = false
  for c in text {
    if c == '"' {
      quoted = !quoted
      buf.write_char(c)
    } else if c == sep && !quoted {
      out.push(buf.to_string())
      buf = StringBuilder()
    } else {
      buf.write_char(c)
    }
  }
  out.push(buf.to_string())
  out
}

///|
/// Strip the space and tab a field value may carry around a token (§5.6.3).
fn trim(text : String) -> String {
  let mut start = 0
  let mut end = text.length()
  while start < end && (text[start] == ' ' || text[start] == '\t') {
    start += 1
  }
  while end > start && (text[end - 1] == ' ' || text[end - 1] == '\t') {
    end -= 1
  }
  text[start:end].to_owned()
}

///|
/// A quoted-string's contents, which is what a parameter value means either way
/// round (§5.6.4).
fn unquote(text : String) -> String {
  if text.length() >= 2 && text[0] == '"' && text[text.length() - 1] == '"' {
    let inner = StringBuilder()
    let mut i = 1
    while i < text.length() - 1 {
      if text[i] == '\\' && i + 1 < text.length() - 1 {
        inner.write_char(text[i + 1].unsafe_to_char())
        i += 2
      } else {
        inner.write_char(text[i].unsafe_to_char())
        i += 1
      }
    }
    inner.to_string()
  } else {
    text
  }
}

///|
/// Token comparison is ASCII case-insensitive (§5.1).
fn lower(text : String) -> String {
  let out = StringBuilder()
  for c in text {
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
