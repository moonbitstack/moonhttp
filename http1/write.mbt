// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A request head as octets.
///
/// The fields are written as given; this does not add a `Host`, a `Content-Length`
/// or anything else, because a caller that wanted those would have put them in and
/// one that did not would be surprised to find them.
pub fn Request::encode(self : Request) -> Bytes {
  let buf = Buffer()
  put(buf, self.verb)
  buf.write_byte(b' ')
  put(buf, self.target)
  buf.write_byte(b' ')
  put(buf, self.version)
  crlf(buf)
  fields(buf, self.fields)
  crlf(buf)
  buf.to_bytes()
}

///|
/// A response head as octets.
pub fn Response::encode(self : Response) -> Bytes {
  let buf = Buffer()
  put(buf, self.version)
  buf.write_byte(b' ')
  put(buf, self.status.to_string())
  buf.write_byte(b' ')
  put(buf, self.reason)
  crlf(buf)
  fields(buf, self.fields)
  crlf(buf)
  buf.to_bytes()
}

///|
/// A request by name, with the framing worked out from what it is given.
///
/// `body` decides what is written: a sized body gets a `Content-Length`, a chunked
/// one a `Transfer-Encoding`, and neither gets neither. That is the one thing a
/// hand-built request gets wrong, so it is not left to the caller.
pub fn Request::of(
  verb : String,
  target : String,
  fields? : Array[@header.Header] = [],
  version? : String = "HTTP/1.1",
  body? : Body = Empty,
  host? : String = "",
  keep_alive? : Bool = true,
) -> Request {
  let all : Array[@header.Header] = []
  if host != "" {
    all.push(@header.Header::of("host", host))
  }
  for f in fields {
    all.push(f)
  }
  match body {
    Sized(n) => all.push(@header.Header::of("content-length", n.to_string()))
    Chunked => all.push(@header.Header::of("transfer-encoding", "chunked"))
    _ => ()
  }
  if !keep_alive {
    all.push(@header.Header::of("connection", "close"))
  }
  { verb, target, version, fields: all, body, expects: false, keep_alive, }
}

///|
/// A response by name, with the framing worked out the same way.
pub fn Response::of(
  status : Int,
  fields? : Array[@header.Header] = [],
  reason? : String = "",
  version? : String = "HTTP/1.1",
  body? : Body = Empty,
  keep_alive? : Bool = true,
) -> Response {
  let all : Array[@header.Header] = []
  for f in fields {
    all.push(f)
  }
  match body {
    Sized(n) => all.push(@header.Header::of("content-length", n.to_string()))
    Chunked => all.push(@header.Header::of("transfer-encoding", "chunked"))
    // A response with neither runs to the close, so it has to say so.
    Closed => all.push(@header.Header::of("connection", "close"))
    Empty =>
      if status >= 200 && status != 204 && status != 304 {
        all.push(@header.Header::of("content-length", "0"))
      }
  }
  if !keep_alive && !all.iter().any(f => f.name == ascii("connection")) {
    all.push(@header.Header::of("connection", "close"))
  }
  {
    version,
    status,
    reason: if reason == "" {
      phrase(status)
    } else {
      reason
    },
    fields: all,
    body,
    keep_alive: keep_alive && body is (Sized(_) | Chunked | Empty),
  }
}

///|
/// The reason phrase a status is usually written with (RFC 9110 §15).
///
/// A client must not act on it (§4), so this is for the human reading a capture.
pub fn phrase(status : Int) -> String {
  match status {
    100 => "Continue"
    101 => "Switching Protocols"
    200 => "OK"
    201 => "Created"
    202 => "Accepted"
    204 => "No Content"
    206 => "Partial Content"
    301 => "Moved Permanently"
    302 => "Found"
    303 => "See Other"
    304 => "Not Modified"
    307 => "Temporary Redirect"
    308 => "Permanent Redirect"
    400 => "Bad Request"
    401 => "Unauthorized"
    403 => "Forbidden"
    404 => "Not Found"
    405 => "Method Not Allowed"
    406 => "Not Acceptable"
    408 => "Request Timeout"
    409 => "Conflict"
    410 => "Gone"
    411 => "Length Required"
    413 => "Content Too Large"
    414 => "URI Too Long"
    415 => "Unsupported Media Type"
    416 => "Range Not Satisfiable"
    417 => "Expectation Failed"
    422 => "Unprocessable Content"
    426 => "Upgrade Required"
    428 => "Precondition Required"
    429 => "Too Many Requests"
    431 => "Request Header Fields Too Large"
    500 => "Internal Server Error"
    501 => "Not Implemented"
    502 => "Bad Gateway"
    503 => "Service Unavailable"
    504 => "Gateway Timeout"
    505 => "HTTP Version Not Supported"
    _ => "Unknown"
  }
}

///|
/// The interim `100 Continue` a server sends when a request said it was waiting
/// (RFC 9110 §10.1.1).
pub let continue_ : Bytes = b"HTTP/1.1 100 Continue\r\n\r\n"

// -- the chunked transfer coding ----------------------------------------------

///|
/// One chunk: its size in hexadecimal, the octets, and a break (RFC 9112 §7.1).
pub fn chunk(data : BytesView) -> Bytes {
  let buf = Buffer()
  put(buf, data.length().to_string(radix=16))
  crlf(buf)
  buf.write_bytesview(data)
  crlf(buf)
  buf.to_bytes()
}

///|
/// The zero-size chunk that ends a body, with optional trailer fields after it.
pub fn last_chunk(trailers? : Array[@header.Header] = []) -> Bytes {
  let buf = Buffer()
  put(buf, "0")
  crlf(buf)
  fields(buf, trailers)
  crlf(buf)
  buf.to_bytes()
}

///|
/// What a chunked body reader found at the front of `data`.
pub(all) enum Chunk {
  // Octets of the body, and how many octets of `data` they took.
  Piece(Bytes, Int)
  // The body ended; its trailer fields, and how many octets that took.
  Done(Array[@header.Header], Int)
} derive(Eq)

///|
pub extend Chunk with Eq::{not_equal, equal}

///|
/// The chunk at the front of `data`.
///
/// Raises [`Refused::Partial`] while it has not all arrived. A size line longer
/// than sixteen hexadecimal digits is refused rather than accumulated: a size that
/// needs more than sixty-four bits is not a size.
pub fn chunked(data : BytesView) -> Chunk raise Refused {
  let stop = line_end(data, 0)
  if stop < 0 {
    raise Partial
  }
  // A chunk extension follows a semicolon and is ignored (§7.1.1).
  let mut cut = stop
  for i = 0; i < stop; i = i + 1 {
    if data[i] == b';' {
      cut = i
      break
    }
  }
  if cut == 0 || cut > 16 {
    raise Malformed("a chunk size that is not one")
  }
  let mut size = 0
  for i = 0; i < cut; i = i + 1 {
    let d = nibble(data[i].to_int())
    if d < 0 {
      raise Malformed("a chunk size that is not hexadecimal")
    }
    size = size * 16 + d
    if size < 0 {
      raise Malformed("a chunk size larger than an Int holds")
    }
  }
  let from = past(data, stop)
  if size == 0 {
    // The trailer section, which ends at a blank line like any other.
    let (trailers, used) = trailer(data[from:])
    return Done(trailers, from + used)
  }
  if data.length() < from + size + 2 {
    raise Partial
  }
  let body = data[from:from + size].to_owned()
  let tail = from + size
  if data[tail] != b'\r' && data[tail] != b'\n' {
    raise Malformed("a chunk not terminated by a break")
  }
  Piece(body, past(data, tail))
}

///|
/// The trailer fields after the last chunk, and how many octets they took.
fn trailer(data : BytesView) -> (Array[@header.Header], Int) raise Refused {
  let out : Array[@header.Header] = []
  let mut pos = 0
  for ;; {
    let stop = line_end(data, pos)
    if stop < 0 {
      raise Partial
    }
    if stop == pos {
      return (out, past(data, stop))
    }
    out.push(field(data[pos:stop]))
    pos = past(data, stop)
  }
}

// -- octets -------------------------------------------------------------------

///|
fn fields(buf : Buffer, all : Array[@header.Header]) -> Unit {
  for f in all {
    buf.write_bytes(f.name)
    buf.write_byte(b':')
    buf.write_byte(b' ')
    buf.write_bytes(f.value)
    crlf(buf)
  }
}

///|
fn crlf(buf : Buffer) -> Unit {
  buf.write_byte(b'\r')
  buf.write_byte(b'\n')
}

///|
/// A string's octets, one per code unit.
fn put(buf : Buffer, s : String) -> Unit {
  for i = 0; i < s.length(); i = i + 1 {
    buf.write_byte((s[i].to_int() & 0xff).to_byte())
  }
}

///|
/// A hexadecimal digit's value, or `-1`.
fn nibble(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    -1
  }
}
