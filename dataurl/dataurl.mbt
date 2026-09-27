// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What a data URL means when it names no media type (RFC 2397 §2).
///
/// A preset rather than a constant: a caller building a URL almost always has
/// something else in mind, and the one place this string is the answer is the
/// one place nobody writes it down.
pub let kind : String = "text/plain;charset=US-ASCII"

///|
/// A data URL taken apart: what the octets are, and the octets (RFC 2397 §3).
///
/// `data` is already decoded — whichever of the two spellings the URL used is a
/// property of the text, not of the representation, and a caller that had to
/// undo base64 itself would be reading the format twice.
pub(all) struct Url {
  /// The media type with its parameters, as the URL spells it.
  kind : String
  /// The payload.
  data : Bytes
} derive(Eq, Debug)

///|
pub extend Url with Eq::{equal, not_equal}

///|
pub extend Url with Debug::{to_repr}

///|
/// Why a string is not a data URL.
pub(all) suberror Refused {
  /// It does not begin with `data:`.
  Scheme
  /// Nothing separates the header from the payload (§3 requires a comma).
  Comma
  /// A `%` with fewer than two hex digits after it, at this offset into the
  /// payload. Only raised under `strict`; otherwise the `%` stands for itself.
  Escape(at~ : Int)
  /// The payload is not base64, at this offset into it.
  Base64(at~ : Int)
} derive(Eq, Debug)

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
/// A data URL carrying these octets.
pub fn Url::new(data : Bytes, kind? : String = kind) -> Url {
  { kind, data, }
}

///|
/// The charset the payload's text is in (RFC 2397 §2).
///
/// `US-ASCII` when nothing says otherwise, which is the default media type's
/// own parameter rather than a guess of ours.
pub fn Url::charset(self : Url) -> String {
  match @mime.param(self.kind[:], "charset") {
    Some(charset) => charset
    None => "US-ASCII"
  }
}

// ------------------------------------------------------------------- writing

///|
/// Write the URL out.
///
/// `base64` is what webpack's asset modules default to
/// (`generator.dataUrl.encoding`), and it is the only spelling that stays the
/// same length for octets that are not text. Turn it off for SVG and other
/// payloads a human may want to read in the URL.
///
/// A media type equal to [`kind`] is left out, because reading one back puts it
/// there again: the shorter form and the longer one decode to the same value.
pub fn Url::encode(self : Url, base64? : Bool = true) -> String {
  let out = StringBuilder()
  out.write_string("data:")
  if self.kind != kind {
    out.write_string(self.kind)
  }
  if base64 {
    out.write_string(";base64,")
    out.write_string(@base64.encode(self.data[:]))
  } else {
    out.write_char(',')
    out.write_string(@url.escape(self.data[:]))
  }
  out.to_string()
}

// ------------------------------------------------------------------- reading

///|
/// Read a data URL.
///
/// `strict` turns the two things browsers let pass into errors: base64 with
/// whitespace in it or the wrong amount of padding, and a `%` that is not an
/// escape. Left off, a lone `%` stands for itself and the whitespace is
/// dropped, which is what a document full of hand-written URLs needs.
pub fn Url::decode(
  text : StringView,
  strict? : Bool = false,
) -> Url raise Refused {
  guard starts(text, "data:") else { raise Scheme }
  let rest = text[5:]
  let mut comma = -1
  for i = 0; i < rest.length(); i = i + 1 {
    if rest[i].to_int() == 0x2C {
      comma = i
      break
    }
  }
  guard comma >= 0 else { raise Comma }
  let (kind, base64) = header(rest[:comma])
  let body = rest[comma + 1:]
  let data = if base64 { unpack(body, strict) } else { unescape(body, strict) }
  { kind, data, }
}

///|
/// The media type and whether `;base64` was there (§3).
///
/// A header of nothing but parameters — `data:;charset=utf-8,…` — is a
/// `text/plain` with those parameters, which is §2's default type wearing the
/// caller's charset rather than the caller's type going missing.
fn header(head : StringView) -> (String, Bool) {
  let head = trim(head)
  let base64 = ends(head, ";base64")
  let head = if base64 { trim(head[:head.length() - 7]) } else { head }
  if head.length() == 0 {
    (kind, base64)
  } else if head[0].to_int() == 0x3B {
    ("text/plain" + head.to_owned(), base64)
  } else {
    (head.to_owned(), base64)
  }
}

///|
/// Undo the base64 payload.
///
/// Under `strict` the text goes to the decoder as it stands, padding and all.
/// Otherwise the whitespace a wrapped URL picked up is dropped first — the
/// decoder itself already treats trailing `=` as optional.
fn unpack(body : StringView, strict : Bool) -> Bytes raise Refused {
  let text = if strict {
    guard body.length() % 4 == 0 else {
      raise Base64(at=body.length() - body.length() % 4)
    }
    body.to_owned()
  } else {
    let out = StringBuilder()
    for ch in body {
      if !space(ch.to_int()) {
        out.write_char(ch)
      }
    }
    out.to_string()
  }
  @base64.decode(text) catch {
    @moonbase.Bad(at~, ..)
    | @moonbase.Truncated(at~)
    | @moonbase.Padding(at~)
    | @moonbase.Checksum(at~) => raise Base64(at~)
  }
}

///|
/// Undo the percent coding.
///
/// Under `strict` a `%` without two hex digits after it is an error; otherwise
/// it is an octet like any other, which is what [`@url.unescape`] does
/// and what a browser does with a URL somebody typed.
fn unescape(body : StringView, strict : Bool) -> Bytes raise Refused {
  let raw = @utf8.encode(body)
  if strict {
    let mut i = 0
    while i < raw.length() {
      if raw[i] == b'%' {
        guard i + 2 < raw.length() && hex(raw[i + 1]) && hex(raw[i + 2]) else {
          raise Escape(at=i)
        }
        i += 3
      } else {
        i += 1
      }
    }
  }
  @url.unescape(raw[:])
}

// ------------------------------------------------------------------ plumbing

///|
fn hex(b : Byte) -> Bool {
  let c = b.to_int()
  (c >= 0x30 && c <= 0x39) ||
  (c >= 0x41 && c <= 0x46) ||
  (c >= 0x61 && c <= 0x66)
}

///|
fn space(c : Int) -> Bool {
  c == 0x20 || c == 0x09 || c == 0x0D || c == 0x0A
}

///|
fn trim(text : StringView) -> StringView {
  let mut lo = 0
  let mut hi = text.length()
  while lo < hi && space(text[lo].to_int()) {
    lo += 1
  }
  while hi > lo && space(text[hi - 1].to_int()) {
    hi -= 1
  }
  text[lo:hi]
}

///|
/// ASCII case-insensitive, because a URL scheme is (RFC 3986 §3.1) and because
/// `;BASE64` is written by more than one generator.
fn fold(c : Int) -> Int {
  if c >= 0x41 && c <= 0x5A {
    c + 32
  } else {
    c
  }
}

///|
fn starts(text : StringView, prefix : String) -> Bool {
  if text.length() < prefix.length() {
    return false
  }
  for i = 0; i < prefix.length(); i = i + 1 {
    if fold(text[i].to_int()) != fold(prefix[i].to_int()) {
      return false
    }
  }
  true
}

///|
fn ends(text : StringView, suffix : String) -> Bool {
  if text.length() < suffix.length() {
    return false
  }
  let at = text.length() - suffix.length()
  for i = 0; i < suffix.length(); i = i + 1 {
    if fold(text[at + i].to_int()) != fold(suffix[i].to_int()) {
      return false
    }
  }
  true
}
