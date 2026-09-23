// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The only range unit HTTP defines (RFC 9110 §14.1.2).
///
/// It is a parameter everywhere rather than a constant because §14.1 leaves the
/// registry open, and a reader that hard-coded `bytes` would silently
/// mis-handle a unit it was never told about instead of ignoring it.
pub let unit : String = "bytes"

///|
/// How many ranges one request may ask for before the answer is to send the
/// whole thing instead (RFC 9110 §14.2).
///
/// A request may name any number of ranges, and a server that honours all of
/// them does a great deal of seeking for one client — the shape of the 2011
/// Apache range attack. 200 is Apache's own `MaxRanges` default.
pub let limit : Int = 200

///|
/// One range as a client asked for it, before it is measured against a length
/// (RFC 9110 §14.1.1).
///
/// The three shapes are the grammar's: an int-range with both ends, an
/// int-range with only a first position, and a suffix-range. They stay
/// separate because they mean different things — `From(0)` asks for
/// everything, while `Last(0)` asks for nothing and is unsatisfiable.
pub(all) enum Spec {
  /// `first-last`: both positions, inclusive.
  Between(Int64, Int64)
  /// `first-`: from here to the end, however long it turns out to be.
  From(Int64)
  /// `-suffix`: the last so many octets.
  Last(Int64)
} derive(Eq, Debug)

///|
pub extend Spec with Eq::{equal, not_equal}

///|
pub extend Spec with Debug::{to_repr}

///|
/// One range measured against a representation: the first and last octet, both
/// inclusive (RFC 9110 §14.1.2).
///
/// Inclusive because the field is, and converting at the edge is where
/// off-by-one errors come from. [`Part::length`] gives the count for a caller
/// who wants one.
pub(all) struct Part {
  at : Int64
  last : Int64
} derive(Eq, Compare, Debug)

///|
pub extend Part with Eq::{equal, not_equal}

///|
pub extend Part with Compare::{compare, op_lt, op_le, op_ge, op_gt}

///|
pub extend Part with Debug::{to_repr}

///|
/// How many octets this part covers.
pub fn Part::length(self : Part) -> Int64 {
  self.last - self.at + 1L
}

// ------------------------------------------------------------------- reading

///|
/// A decimal number, saturating at `Int64::max_value` rather than wrapping.
///
/// RFC 9110 §14.1.2 requires a recipient to expect numerals larger than it can
/// hold and not to mis-parse them. Saturating is right for both positions: a
/// first position past the end is unsatisfiable either way, and a last position
/// past the end is clipped to the end either way.
fn digits(text : StringView) -> Int64? {
  // The largest Int64, as a literal rather than an import: this package has no
  // other reason to depend on one.
  let huge = 9223372036854775807L
  if text.length() == 0 {
    return None
  }
  let mut value = 0L
  for ch in text {
    if ch < '0' || ch > '9' {
      return None
    }
    if value > 922337203685477580L {
      value = huge
    } else {
      value = value * 10L + (ch.to_int() - 48).to_int64()
      if value < 0L {
        value = huge
      }
    }
  }
  Some(value)
}

///|
/// Trim the optional whitespace RFC 9110 §5.6.3 allows around a list element.
fn trim(text : StringView) -> StringView {
  let mut from = 0
  let mut to = text.length()
  while from < to && (text[from] == ' ' || text[from] == '\t') {
    from = from + 1
  }
  while to > from && (text[to - 1] == ' ' || text[to - 1] == '\t') {
    to = to - 1
  }
  text[from:to]
}

///|
/// One range-spec, or `None` if it is not one (RFC 9110 §14.1.1).
fn spec(text : StringView) -> Spec? {
  let text = trim(text)
  if text.length() == 0 {
    return None
  }
  if text[0] == '-' {
    return match digits(text[1:]) {
      Some(suffix) => Some(Last(suffix))
      None => None
    }
  }
  let mut dash = -1
  for i = 0; i < text.length(); i = i + 1 {
    if text[i] == '-' {
      dash = i
      break
    }
  }
  if dash < 0 {
    return None
  }
  guard digits(text[0:dash]) is Some(first) else { return None }
  let rest = text[dash + 1:]
  if rest.length() == 0 {
    return Some(From(first))
  }
  guard digits(rest) is Some(last) else { return None }
  // §14.1.1: an int-range whose last position precedes its first is invalid,
  // and §14.2 makes one invalid spec spoil the whole field.
  if last < first {
    return None
  }
  Some(Between(first, last))
}

///|
/// Read a `Range` field value (RFC 9110 §14.2).
///
/// `None` means the field is to be ignored, which §14.2 requires for a unit the
/// server does not implement and for a value that does not parse. Ignoring it
/// is not an error: the answer is the whole representation, with status 200.
///
/// An empty range-set is not a range request either — `bytes=` names no range,
/// and serving everything is the right reading of it.
pub fn decode(value : StringView, unit? : String = unit) -> Array[Spec]? {
  let value = trim(value)
  let mut eq = -1
  for i = 0; i < value.length(); i = i + 1 {
    if value[i] == '=' {
      eq = i
      break
    }
  }
  if eq < 0 {
    return None
  }
  if trim(value[0:eq]).to_owned() != unit {
    return None
  }
  let specs = []
  let rest = value[eq + 1:]
  let mut from = 0
  for i = 0; i <= rest.length(); i = i + 1 {
    if i == rest.length() || rest[i] == ',' {
      let piece = trim(rest[from:i])
      // §5.6.1 lets a list carry empty elements; they are skipped, not refused.
      if piece.length() > 0 {
        guard spec(piece) is Some(one) else { return None }
        specs.push(one)
      }
      from = i + 1
    }
  }
  if specs.length() == 0 {
    return None
  }
  Some(specs)
}

///|
/// Write a `Range` field value (RFC 9110 §14.2).
pub fn encode(specs : ArrayView[Spec], unit? : String = unit) -> String {
  let out = StringBuilder()
  out.write_string(unit)
  out.write_char('=')
  for i, one in specs {
    if i > 0 {
      out.write_string(", ")
    }
    match one {
      Between(first, last) => {
        out.write_string(first.to_string())
        out.write_char('-')
        out.write_string(last.to_string())
      }
      From(first) => {
        out.write_string(first.to_string())
        out.write_char('-')
      }
      Last(suffix) => {
        out.write_char('-')
        out.write_string(suffix.to_string())
      }
    }
  }
  out.to_string()
}

// ----------------------------------------------------------------- measuring

///|
/// Measure what was asked against a representation of `length` octets
/// (RFC 9110 §14.1.2).
///
/// `None` is unsatisfiable, and the answer to it is 416 with the
/// [`unsatisfied`] `Content-Range` — not 200, and not an empty 206. A request
/// is unsatisfiable only when *no* spec in it is satisfiable; §14.1.1 says one
/// good spec carries the field, and the ones that cannot be met are dropped.
///
/// `merge` coalesces ranges that overlap or touch, which §14.2 permits and
/// which keeps `bytes=0-100,50-150` from sending the middle twice. `limit`
/// caps how many ranges survive; past it the caller should send the whole
/// representation, so exceeding it reads as "no ranges here" rather than as an
/// error.
pub fn measure(
  specs : ArrayView[Spec],
  length~ : Int64,
  merge? : Bool = true,
  limit? : Int = limit,
) -> Array[Part]? {
  if length < 0L {
    return None
  }
  let parts = []
  for one in specs {
    let part = match one {
      Between(first, last) =>
        // §14.1.2: satisfiable if the first position is inside the
        // representation; the last is clipped to the end.
        if first >= length {
          None
        } else {
          Some({
            at: first,
            last: if last >= length {
              length - 1L
            } else {
              last
            },
          })
        }
      From(first) =>
        if first >= length {
          None
        } else {
          Some({ at: first, last: length - 1L, })
        }
      Last(suffix) =>
        // §14.1.2: a zero-length suffix asks for nothing and is never
        // satisfiable, even against a representation of zero length.
        if suffix <= 0L {
          None
        } else if suffix >= length {
          if length == 0L {
            None
          } else {
            Some({ at: 0L, last: length - 1L, })
          }
        } else {
          Some({ at: length - suffix, last: length - 1L, })
        }
    }
    if part is Some(part) {
      parts.push(part)
    }
  }
  if parts.length() == 0 {
    return None
  }
  let parts = if merge { coalesce(parts) } else { parts }
  if parts.length() > limit {
    return None
  }
  Some(parts)
}

///|
/// Join ranges that overlap or touch, in ascending order (RFC 9110 §14.2).
///
/// Touching counts: `0-99` and `100-199` are one run of two hundred octets, and
/// sending them as two parts costs a boundary for nothing.
fn coalesce(parts : Array[Part]) -> Array[Part] {
  let sorted = parts.copy()
  sorted.sort()
  let out : Array[Part] = []
  for part in sorted {
    if out.length() > 0 && part.at <= out[out.length() - 1].last + 1L {
      let last = out[out.length() - 1]
      if part.last > last.last {
        out[out.length() - 1] = { at: last.at, last: part.last, }
      }
    } else {
      out.push(part)
    }
  }
  out
}

// ------------------------------------------------------------------ answering

///|
/// A `Content-Range` field value (RFC 9110 §14.4): where a part sits in the
/// whole, or — in a 416 — only how big the whole is.
///
/// `part` is absent in the `*/complete` form a 416 carries. `complete` is
/// absent in the `part/*` form, which says the total length was not known when
/// the field was written.
pub(all) struct Content {
  unit : String
  part : Part?
  complete : Int64?
} derive(Eq, Debug)

///|
pub extend Content with Eq::{equal, not_equal}

///|
pub extend Content with Debug::{to_repr}

///|
/// The `Content-Range` of a part that was served (RFC 9110 §14.4).
///
/// `complete` is the length of the whole representation. Leaving it out writes
/// `*`, which §14.4 reserves for a sender that does not know the total — a
/// generated response being streamed, say. Give it when it is known: a client
/// recombining parts needs it.
pub fn Content::new(
  part : Part,
  complete? : Int64,
  unit? : String = unit,
) -> Content {
  { unit, part: Some(part), complete, }
}

///|
/// The `Content-Range` a 416 carries: `bytes */1234` (RFC 9110 §14.4).
///
/// It names no part because there is none to name; the number is what the
/// client needs in order to ask again for something that exists.
pub fn unsatisfied(complete : Int64, unit? : String = unit) -> Content {
  { unit, part: None, complete: Some(complete), }
}

///|
/// Write a `Content-Range` field value (RFC 9110 §14.4).
pub fn Content::encode(self : Content) -> String {
  let out = StringBuilder()
  out.write_string(self.unit)
  out.write_char(' ')
  match self.part {
    Some(part) => {
      out.write_string(part.at.to_string())
      out.write_char('-')
      out.write_string(part.last.to_string())
    }
    None => out.write_char('*')
  }
  out.write_char('/')
  match self.complete {
    Some(complete) => out.write_string(complete.to_string())
    None => out.write_char('*')
  }
  out.to_string()
}

///|
/// Read a `Content-Range` field value (RFC 9110 §14.4).
///
/// `None` is a value that cannot be trusted, and §14.4 is explicit about what
/// follows: a recipient must not recombine content with a stored representation
/// on the strength of an invalid `Content-Range`. So a last position before the
/// first, or a complete length that does not reach past the last position, is
/// refused here rather than repaired.
pub fn Content::decode(value : StringView) -> Content? {
  let value = trim(value)
  let mut space = -1
  for i = 0; i < value.length(); i = i + 1 {
    if value[i] == ' ' {
      space = i
      break
    }
  }
  if space <= 0 {
    return None
  }
  let unit = value[0:space].to_owned()
  let rest = trim(value[space + 1:])
  let mut slash = -1
  for i = 0; i < rest.length(); i = i + 1 {
    if rest[i] == '/' {
      slash = i
      break
    }
  }
  if slash < 0 {
    return None
  }
  let range = rest[0:slash]
  let whole = rest[slash + 1:]
  let complete = if whole.to_owned() == "*" {
    None
  } else {
    guard digits(whole) is Some(complete) else { return None }
    Some(complete)
  }
  if range.to_owned() == "*" {
    // §14.4: the unsatisfied form has to say how long the whole is, or it
    // carries no information at all.
    guard complete is Some(_) else { return None }
    return Some({ unit, part: None, complete, })
  }
  let mut dash = -1
  for i = 0; i < range.length(); i = i + 1 {
    if range[i] == '-' {
      dash = i
      break
    }
  }
  if dash < 0 {
    return None
  }
  guard digits(range[0:dash]) is Some(at) else { return None }
  guard digits(range[dash + 1:]) is Some(last) else { return None }
  if last < at {
    return None
  }
  if complete is Some(complete) && complete <= last {
    return None
  }
  Some({ unit, part: Some({ at, last, }), complete, })
}

///|
/// The `Accept-Ranges` field value (RFC 9110 §14.3).
///
/// `none` is not the absence of the field: it says outright that range requests
/// will not be honoured, which stops a client from trying and failing.
pub fn accept(ranges? : Bool = true, unit? : String = unit) -> String {
  if ranges {
    unit
  } else {
    "none"
  }
}

// ---------------------------------------------------------------- conditional

///|
/// Whether an `If-Range` allows the range to be served (RFC 9110 §13.1.5).
///
/// `given` is what the client sent — an entity tag or an HTTP-date. It matches
/// on a *strong* comparison against `etag`, or on an exact match against
/// `modified`; anything else means the representation may have changed since
/// the client last saw it, and §13.1.5 says to send the whole thing rather than
/// a part of a different document.
///
/// A weak entity tag never matches, on either side. A weak tag says two
/// representations are equivalent, not identical, and stitching a range from
/// one onto a copy of the other produces a file that never existed.
pub fn unchanged(
  given : StringView,
  etag? : String,
  modified? : String,
) -> Bool {
  let given = trim(given)
  if given.length() == 0 {
    return false
  }
  if given.length() >= 2 && given[0] == 'W' && given[1] == '/' {
    return false
  }
  if given[0] == '"' {
    return match etag {
      Some(etag) =>
        etag.length() > 0 && etag[0] == '"' && etag == given.to_owned()
      None => false
    }
  }
  match modified {
    Some(modified) => modified == given.to_owned()
    None => false
  }
}

// ----------------------------------------------------------------- multipart

///|
/// The `Content-Type` a multi-range 206 carries (RFC 9110 §14.6).
pub fn multipart(boundary : StringView) -> String {
  "multipart/byteranges; boundary=" + boundary.to_owned()
}

///|
/// The body of a multi-range 206 (RFC 9110 §14.6): one part per range, each
/// with its own `Content-Type` and `Content-Range`, then a closing boundary.
///
/// `parts` pairs each range with its octets — this package does no reading, so
/// the caller fetches them. `kind` is the representation's own media type,
/// which §14.6 repeats in every part because each part is a document in its
/// own right.
pub fn parts(
  parts : ArrayView[(Part, Bytes)],
  boundary~ : String,
  kind~ : String,
  complete? : Int64,
  unit? : String = unit,
) -> Bytes {
  let out = Buffer()
  for one in parts {
    out.write_bytes(b"\r\n--")
    out.write_bytes(ascii(boundary))
    out.write_bytes(b"\r\nContent-Type: ")
    out.write_bytes(ascii(kind))
    out.write_bytes(b"\r\nContent-Range: ")
    out.write_bytes(ascii(Content::new(one.0, complete?, unit~).encode()))
    out.write_bytes(b"\r\n\r\n")
    out.write_bytes(one.1)
  }
  out.write_bytes(b"\r\n--")
  out.write_bytes(ascii(boundary))
  out.write_bytes(b"--\r\n")
  out.to_bytes()
}

///|
/// A boundary, a media type and a `Content-Range` are all ASCII by grammar
/// (RFC 9110 §14.6, §8.3), so this is a cast and not an encoding.
fn ascii(text : StringView) -> Bytes {
  let out : Array[Byte] = []
  for ch in text {
    out.push((ch.to_int() & 0xff).to_byte())
  }
  Bytes::from_array(out)
}
