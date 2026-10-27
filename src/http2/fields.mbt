// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which field section a list of fields is, for the rules of RFC 9113 §8.
priv enum Section {
  Request
  // The request a PUSH_PROMISE carries, which must also be safe and cacheable.
  Promise
  Response
  Trailers
}

///|
/// Why `fields` is not a valid section of its kind, or `None` (RFC 9113 §8.2, §8.3,
/// RFC 8441 §4).
///
/// `extended` is whether the receiver of the request has turned on extended CONNECT,
/// which is what lets a request carry `:protocol`.
fn fault(
  fields : Array[@header.Header],
  section : Section,
  extended~ : Bool = false,
) -> String? {
  let seen : Array[String] = []
  let mut regular = false
  let mut verb = ""
  let mut path = ""
  let mut status = b""
  let mut length : Int32? = None
  for f in fields {
    if f.name.length() == 0 {
      return Some("an empty field name")
    }
    let name = text(f.name)
    if f.name[0] == b':' {
      if regular {
        return Some("a pseudo-header after a regular field")
      }
      let allowed = match section {
        Request | Promise =>
          name is (":method" | ":scheme" | ":authority" | ":path") ||
          (name == ":protocol" && extended)
        Response => name == ":status"
        Trailers => false
      }
      if !allowed {
        return Some("the pseudo-header \{name} where it may not be")
      }
      if seen.contains(name) {
        return Some("the pseudo-header \{name} twice")
      }
      seen.push(name)
      match name {
        ":method" => verb = text(f.value)
        ":path" => path = text(f.value)
        ":status" => status = f.value
        _ => ()
      }
    } else {
      regular = true
      for b in f.name {
        let c = b.to_int()
        if c <= 0x20 || (c >= 0x41 && c <= 0x5a) || c >= 0x7f || c == 0x3a {
          return Some("a field name with a character it may not have")
        }
      }
      if name
        is ("connection"
        | "proxy-connection"
        | "keep-alive"
        | "transfer-encoding"
        | "upgrade") {
        return Some("the connection-specific field \{name}")
      }
      if name == "te" && text(f.value) != "trailers" {
        return Some("a te field other than trailers")
      }
      if name == "content-length" {
        let n = digits(f.value)
        if n < 0 || (length is Some(m) && m != n) {
          return Some("a content-length that is not one number")
        }
        length = Some(n)
      }
    }
    let v = f.value
    for b in v {
      if b == b'\x00' || b == b'\n' || b == b'\r' {
        return Some("a field value with NUL, CR or LF")
      }
    }
    if v.length() > 0 &&
      (
        v[0] == b' ' ||
        v[0] == b'\t' ||
        v[v.length() - 1] == b' ' ||
        v[v.length() - 1] == b'\t'
      ) {
      return Some("a field value with surrounding whitespace")
    }
  }
  match section {
    Request | Promise => {
      if verb == "" {
        return Some("a request with no :method")
      }
      if verb == "CONNECT" && !seen.contains(":protocol") {
        if seen.contains(":scheme") || seen.contains(":path") {
          return Some("a CONNECT with :scheme or :path")
        }
        if !seen.contains(":authority") {
          return Some("a CONNECT with no :authority")
        }
      } else {
        if !seen.contains(":scheme") || !seen.contains(":path") {
          return Some("a request with no :scheme or :path")
        }
        if path == "" {
          return Some("an empty :path")
        }
        if seen.contains(":protocol") && verb != "CONNECT" {
          return Some(":protocol on a request that is not CONNECT")
        }
      }
      if section is Promise && !(verb is ("GET" | "HEAD")) {
        return Some("a promised request that is not safe and cacheable")
      }
    }
    Response =>
      if status.length() != 3 || digits(status) < 100 {
        return Some("a response with no three-digit :status")
      }
    Trailers => ()
  }
  None
}

///|
/// The value of the first field named `name`.
fn find(fields : Array[@header.Header], name : String) -> Bytes? {
  for f in fields {
    if text(f.name) == name {
      return Some(f.value)
    }
  }
  None
}

///|
/// The `:status` of a response that [`fault`] has passed.
fn status(fields : Array[@header.Header]) -> Int32 {
  find(fields, ":status").map(digits).unwrap_or(0)
}

///|
/// The declared `content-length`, once [`fault`] has passed the fields.
fn length(fields : Array[@header.Header]) -> Int32? {
  find(fields, "content-length").map(digits)
}

///|
/// Octets as a non-negative number, or `-1` when they are not one.
fn digits(v : Bytes) -> Int32 {
  if v.length() == 0 {
    return -1
  }
  let mut out = 0
  for b in v {
    let c = b.to_int()
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
/// Octets as the text they spell, one code unit per octet.
fn text(b : Bytes) -> String {
  let out = StringBuilder()
  for c in b {
    out.write_char(c.to_int().unsafe_to_char())
  }
  out.to_string()
}
