// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Why a message was refused.
///
/// `Partial` is not a fault: it is the reader saying the bytes have not all
/// arrived, which is the answer a caller feeds more and asks again. Everything
/// else is a message that will not become valid by waiting.
pub(all) suberror Refused {
  Partial
  Malformed(String)
  Exceeded(limit~ : Int, got~ : Int)
  Smuggled(String)
} derive(Eq, Debug)

///|
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Partial => logger.write_string("Partial")
    Malformed(m) => logger.write_string("Malformed(" + m + ")")
    Exceeded(limit~, got~) =>
      logger.write_string("Exceeded(limit=\{limit}, got=\{got})")
    Smuggled(m) => logger.write_string("Smuggled(" + m + ")")
  }
}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

///|
/// The status a refusal deserves, for a server that answers rather than hangs up.
///
/// A message too large is 431 when it is the head (RFC 6585 §5) and 413 when it is
/// the body; this is about the head, which is what this package bounds. A framing
/// fault is 400.
pub fn Refused::status(self : Refused) -> Int {
  match self {
    Exceeded(..) => 431
    _ => 400
  }
}

///|
/// How a message's body is delimited (RFC 9112 §6).
///
/// The three ways are not interchangeable and picking the wrong one is how a
/// request gets smuggled past a proxy, so this is read from the headers once and
/// carried rather than re-derived.
pub(all) enum Body {
  Empty
  Sized(Int)
  Chunked
  // Until the connection closes, which only a response may use (§6.3).
  Closed
} derive(Eq, Debug)

///|
pub extend Body with Debug::{to_repr}

///|
pub extend Body with Eq::{not_equal, equal}

///|
/// The limits a reader holds a peer to.
///
/// The preset is [`limits`]. Build another with [`Limits::new`], or update one in
/// place with `{ ..limits, head: 8192 }`.
pub(all) struct Limits {
  head : Int
  fields : Int
} derive(Eq, Debug)

///|
pub extend Limits with Debug::{to_repr}

///|
pub extend Limits with Eq::{not_equal, equal}

///|
/// Sixteen kibibytes of head and a hundred fields.
///
/// 16 KiB is what h11 caps an incomplete event at and what uvicorn exposes as
/// `--h11-max-incomplete-event-size`; nginx's `large_client_header_buffers` and
/// Go's `MaxHeaderBytes` land in the same place. A hundred fields is Go's
/// `http2.Server` default and more than any real request carries.
pub let limits : Limits = { head: 16 * 1024, fields: 100, }

///|
/// Limits by name, every knob with the preset's value.
pub fn Limits::new(
  head? : Int = limits.head,
  fields? : Int = limits.fields,
) -> Limits {
  { head, fields, }
}

///|
/// A request's head: the request line and the fields under it.
///
/// Field names are lowercased, because HTTP/1.1 says they are case-insensitive and
/// every consumer would otherwise lowercase them again. Values are octets, not
/// text: a field value may carry anything, and gRPC's `-bin` metadata does.
pub(all) struct Request {
  verb : String
  target : String
  version : String
  fields : Array[@header.Header]
  body : Body
  // `Expect: 100-continue` — the client is waiting to be told to send the body.
  expects : Bool
  keep_alive : Bool
} derive(Eq)

///|
pub extend Request with Eq::{not_equal, equal}

///|
/// A response's head: the status line and the fields under it.
pub(all) struct Response {
  version : String
  status : Int
  reason : String
  fields : Array[@header.Header]
  body : Body
  keep_alive : Bool
} derive(Eq)

///|
pub extend Response with Eq::{not_equal, equal}

///|
/// The value of the first field named `name`, or `None`.
pub fn Request::field(self : Request, name : String) -> Bytes? {
  find(self.fields, name)
}

///|
/// The same, for a response.
pub fn Response::field(self : Response, name : String) -> Bytes? {
  find(self.fields, name)
}

///|
fn find(fields : Array[@header.Header], name : String) -> Bytes? {
  let want = ascii(name)
  for f in fields {
    if f.name == want {
      return Some(f.value)
    }
  }
  None
}

///|
/// A string's octets, which is all an ASCII field name is.
fn ascii(s : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < s.length(); i = i + 1 {
    buf.write_byte((s[i].to_int() & 0xff).to_byte())
  }
  buf.to_bytes()
}
