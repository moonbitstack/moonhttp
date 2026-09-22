// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The request at the front of `data`, and how many octets it took.
///
/// Raises [`Refused::Partial`] while the head has not all arrived, which is the
/// answer a caller reads more on. This reads the head only: the body is framed by
/// [`Request::body`] and is the caller's to collect, because a body may be larger
/// than anything worth holding in one buffer.
pub fn request(
  data : BytesView,
  limits? : Limits = limits,
) -> (Request, Int) raise Refused {
  let (line, fields, used) = head(data, limits)
  let (verb, target, version) = request_line(line)
  let body = framing(fields, true)
  (
    {
      verb,
      target,
      version,
      fields,
      body,
      expects: token(fields, "expect", "100-continue"),
      keep_alive: alive(fields, version),
    },
    used,
  )
}

///|
/// The response at the front of `data`, and how many octets it took.
///
/// `verb` is the one the request used, because it decides the framing: a
/// response to HEAD has no body however its fields read (RFC 9112 §6.3).
pub fn response(
  data : BytesView,
  verb? : String = "GET",
  limits? : Limits = limits,
) -> (Response, Int) raise Refused {
  let (line, fields, used) = head(data, limits)
  let (version, status, reason) = status_line(line)
  let body = if verb.to_upper() == "HEAD" ||
    status == 204 ||
    status == 304 ||
    (status >= 100 && status < 200) {
    Empty
  } else {
    match framing(fields, false) {
      // A response with neither a length nor a chunked coding runs to the close of
      // the connection, which a request may never do.
      Empty =>
        if find(fields, "content-length") is Some(_) {
          Empty
        } else {
          Closed
        }
      other => other
    }
  }
  (
    {
      version,
      status,
      reason,
      fields,
      body,
      keep_alive: alive(fields, version),
    },
    used,
  )
}

///|
/// The head: a first line and the fields under it, terminated by a blank line.
fn head(
  data : BytesView,
  limits : Limits,
) -> (BytesView, Array[@header.Header], Int) raise Refused {
  let end = blank_line(data)
  if end < 0 {
    // Not all here yet — unless it is already past what will ever be read.
    if data.length() > limits.head {
      raise Exceeded(limit=limits.head, got=data.length())
    }
    raise Partial
  }
  if end > limits.head {
    raise Exceeded(limit=limits.head, got=end)
  }
  let mut at = line_end(data, 0)
  if at < 0 {
    raise Partial
  }
  let line = data[0:at]
  let fields : Array[@header.Header] = []
  let mut pos = past(data, at)
  while pos < end {
    let stop = line_end(data, pos)
    if stop < 0 || stop > end {
      raise Partial
    }
    if stop == pos {
      break
    }
    if fields.length() >= limits.fields {
      raise Exceeded(limit=limits.fields, got=fields.length() + 1)
    }
    fields.push(field(data[pos:stop]))
    pos = past(data, stop)
  }
  at = end
  (line, fields, past(data, end))
}

///|
/// One field line, `name: value` with the name lowercased and the value trimmed of
/// optional whitespace (RFC 9112 §5).
///
/// Obsolete line folding is refused rather than unfolded: §5.2 says a recipient
/// must either reject the message or replace the fold with spaces before
/// forwarding, and rejecting is the side that cannot be used to smuggle anything.
fn field(line : BytesView) -> @header.Header raise Refused {
  if line.length() > 0 && (line[0] == b' ' || line[0] == b'\t') {
    raise Smuggled("an obsolete folded field line")
  }
  let mut colon = -1
  for i = 0; i < line.length(); i = i + 1 {
    if line[i] == b':' {
      colon = i
      break
    }
  }
  if colon <= 0 {
    raise Malformed("a field line with no name")
  }
  // No space is allowed between the name and the colon (§5.1), and allowing one is
  // a known request-smuggling vector.
  if line[colon - 1] == b' ' || line[colon - 1] == b'\t' {
    raise Smuggled("whitespace before the colon of a field line")
  }
  let name = Buffer()
  for i = 0; i < colon; i = i + 1 {
    let c = line[i].to_int()
    if !is_token(c) {
      raise Malformed("a field name with a character it may not have")
    }
    name.write_byte((if c >= 0x41 && c <= 0x5a { c + 32 } else { c }).to_byte())
  }
  let mut from = colon + 1
  let mut to = line.length()
  while from < to && (line[from] == b' ' || line[from] == b'\t') {
    from = from + 1
  }
  while to > from && (line[to - 1] == b' ' || line[to - 1] == b'\t') {
    to = to - 1
  }
  { name: name.to_bytes(), value: line[from:to].to_owned(), }
}

///|
/// `METHOD SP target SP HTTP/x.y` (RFC 9112 §3).
fn request_line(line : BytesView) -> (String, String, String) raise Refused {
  let first = space(line, 0)
  if first < 0 {
    raise Malformed("a request line with no target")
  }
  let second = space(line, first + 1)
  if second < 0 {
    raise Malformed("a request line with no version")
  }
  let verb = text(line[0:first])
  for i = 0; i < first; i = i + 1 {
    if !is_token(line[i].to_int()) {
      raise Malformed("a verb with a character it may not have")
    }
  }
  if first + 1 == second {
    raise Malformed("an empty request target")
  }
  (verb, text(line[first + 1:second]), version(line[second + 1:]))
}

///|
/// `HTTP/x.y SP status SP reason` (RFC 9112 §4).
fn status_line(line : BytesView) -> (String, Int, String) raise Refused {
  let first = space(line, 0)
  if first < 0 {
    raise Malformed("a status line with no code")
  }
  let v = version(line[0:first])
  let rest = line[first + 1:]
  if rest.length() < 3 {
    raise Malformed("a status code is three digits")
  }
  let mut status = 0
  for i = 0; i < 3; i = i + 1 {
    let c = rest[i].to_int()
    if c < 0x30 || c > 0x39 {
      raise Malformed("a status code is three digits")
    }
    status = status * 10 + (c - 0x30)
  }
  // The reason phrase may be empty, and §4 says a client must not act on it.
  let reason = if rest.length() > 4 { text(rest[4:]) } else { "" }
  (v, status, reason)
}

///|
/// `HTTP/x.y`, checked rather than taken on trust.
fn version(v : BytesView) -> String raise Refused {
  if v.length() != 8 ||
    v[0] != b'H' ||
    v[1] != b'T' ||
    v[2] != b'T' ||
    v[3] != b'P' ||
    v[4] != b'/' ||
    v[6] != b'.' {
    raise Malformed("not an HTTP version")
  }
  let major = v[5].to_int()
  let minor = v[7].to_int()
  if major < 0x30 || major > 0x39 || minor < 0x30 || minor > 0x39 {
    raise Malformed("not an HTTP version")
  }
  text(v)
}

///|
/// How the body is delimited, from the fields (RFC 9112 §6).
///
/// A message carrying both a `Content-Length` and a chunked `Transfer-Encoding` is
/// refused: §6.1 says the length must be ignored, but two parsers disagreeing about
/// which to believe is exactly how a request is smuggled, so neither is believed.
fn framing(
  fields : Array[@header.Header],
  request : Bool,
) -> Body raise Refused {
  let chunked = match find(fields, "transfer-encoding") {
    Some(v) => {
      let coding = text(v[:]).to_lower()
      // Only a final `chunked` delimits; anything else leaves the length unknown,
      // which a request may not have.
      if !coding.contains("chunked") {
        raise Smuggled("a transfer coding that does not delimit the body")
      }
      true
    }
    None => false
  }
  let mut length = -1
  let mut seen = 0
  for f in fields {
    if f.name == ascii("content-length") {
      seen = seen + 1
      let n = digits(f.value)
      if n < 0 {
        raise Smuggled("a Content-Length that is not a number")
      }
      if seen > 1 && n != length {
        raise Smuggled("two different Content-Length fields")
      }
      length = n
    }
  }
  if chunked && seen > 0 {
    raise Smuggled("both a Content-Length and a chunked Transfer-Encoding")
  }
  if chunked {
    return Chunked
  }
  if seen > 0 {
    return if length == 0 { Empty } else { Sized(length) }
  }
  let _ = request
  Empty
}

///|
/// A field value as a non-negative count, or `-1` when it is not one.
///
/// A leading sign, a space or a second number are all refused: a `Content-Length`
/// of `+5` or `5, 5` is how two parsers are made to disagree.
fn digits(v : Bytes) -> Int {
  if v.length() == 0 {
    return -1
  }
  let mut out = 0
  for i = 0; i < v.length(); i = i + 1 {
    let c = v[i].to_int()
    if c < 0x30 || c > 0x39 {
      return -1
    }
    out = out * 10 + (c - 0x30)
    if out < 0 {
      return -1
    }
  }
  out
}

///|
/// Whether the connection survives this message (RFC 9112 §9.3).
///
/// HTTP/1.1 keeps it open unless told otherwise; HTTP/1.0 closes it unless told
/// otherwise. Getting this backwards is how a server hangs.
fn alive(fields : Array[@header.Header], version : String) -> Bool {
  let eleven = version == "HTTP/1.1"
  match find(fields, "connection") {
    Some(v) => {
      let c = text(v[:]).to_lower()
      if c.contains("close") {
        false
      } else if c.contains("keep-alive") {
        true
      } else {
        eleven
      }
    }
    None => eleven
  }
}

///|
/// Whether a field holds `want` among its comma-separated values.
fn token(fields : Array[@header.Header], name : String, want : String) -> Bool {
  match find(fields, name) {
    Some(v) => text(v[:]).to_lower().contains(want)
    None => false
  }
}

// -- octets -------------------------------------------------------------------

///|
/// The offset of the blank line that ends a head, or `-1`.
///
/// Both `\r\n\r\n` and the bare `\n\n` a hand-written client sends are accepted;
/// §2.2 says a recipient may.
fn blank_line(data : BytesView) -> Int {
  for i = 0; i < data.length(); i = i + 1 {
    if data[i] == b'\n' {
      if i + 1 < data.length() && data[i + 1] == b'\n' {
        return i + 1
      }
      if i + 2 < data.length() && data[i + 1] == b'\r' && data[i + 2] == b'\n' {
        return i + 1
      }
    }
  }
  -1
}

///|
/// Where the line starting at `from` ends, not counting its terminator, or `-1`.
fn line_end(data : BytesView, from : Int) -> Int {
  for i = from; i < data.length(); i = i + 1 {
    if data[i] == b'\n' {
      return if i > from && data[i - 1] == b'\r' { i - 1 } else { i }
    }
  }
  -1
}

///|
/// The offset just past the terminator of the line ending at `at`.
fn past(data : BytesView, at : Int) -> Int {
  let mut i = at
  if i < data.length() && data[i] == b'\r' {
    i = i + 1
  }
  if i < data.length() && data[i] == b'\n' {
    i = i + 1
  }
  i
}

///|
/// The offset of the space at or after `from`, or `-1`.
fn space(data : BytesView, from : Int) -> Int {
  for i = from; i < data.length(); i = i + 1 {
    if data[i] == b' ' {
      return i
    }
  }
  -1
}

///|
/// Octets as the text they spell, one code unit per octet.
fn text(v : BytesView) -> String {
  let out = StringBuilder()
  for i = 0; i < v.length(); i = i + 1 {
    out.write_char(v[i].to_int().unsafe_to_char())
  }
  out.to_string()
}

///|
/// Whether an octet may appear in a token — a verb, or a field name (RFC 9110
/// §5.6.2).
fn is_token(c : Int) -> Bool {
  (c >= 0x30 && c <= 0x39) ||
  (c >= 0x41 && c <= 0x5a) ||
  (c >= 0x61 && c <= 0x7a) ||
  c == 0x21 ||
  (c >= 0x23 && c <= 0x27) ||
  c == 0x2a ||
  c == 0x2b ||
  c == 0x2d ||
  c == 0x2e ||
  c == 0x5e ||
  c == 0x5f ||
  c == 0x60 ||
  c == 0x7c ||
  c == 0x7e
}
