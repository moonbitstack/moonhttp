// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One header field: a name and a value, as octets (RFC 9110 §5).
///
/// Octets and not strings, for two reasons. A field value is a byte sequence that a
/// receiver only later decides how to read, and gRPC's `-bin` metadata is binary by
/// design; decoding either to a `String` on the way past would lose what was sent.
///
/// Both header compressions produce and consume these, so HTTP/2 and HTTP/3 speak of a
/// header list in the same type and nothing has to be converted between them.
pub(all) struct Header {
  name : Bytes
  value : Bytes
} derive(Eq, Debug)

///|
/// A field from ASCII, which is how a specification writes one and how most code means
/// one. A code point past 0x7f is written as its low octet, so this is for names and
/// values that are ASCII to begin with.
pub fn Header::of(name : String, value : String) -> Header {
  { name: octets(name), value: octets(value), }
}

///|
/// The field's name and value read back as ASCII.
///
/// Every octet becomes one code point, so this round-trips what `of` wrote and turns
/// arbitrary bytes into something printable rather than refusing them; a value that is
/// meant to be UTF-8 is the caller's to decode.
pub fn Header::ascii(self : Header) -> (String, String) {
  (chars(self.name), chars(self.value))
}

///|
/// How many octets the field costs a compressor's table: its two parts and a fixed
/// overhead for the entry itself (RFC 7541 §4.1, and RFC 9204 §3.2.1 with the same
/// arithmetic).
pub fn Header::cost(self : Header, overhead? : Int = 32) -> Int {
  self.name.length() + self.value.length() + overhead
}

///|
fn octets(s : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < s.length(); i = i + 1 {
    buf.write_byte((s[i].to_int() & 0xff).to_byte())
  }
  buf.to_bytes()
}

///|
fn chars(b : Bytes) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
pub extend Header with Debug::{to_repr}

///|
pub extend Header with Eq::{not_equal, equal}
