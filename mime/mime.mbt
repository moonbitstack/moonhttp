// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A named text value from a form.
pub(all) struct Field {
  name : String
  value : String
} derive(Eq, Debug)

///|
pub extend Field with Eq::{equal, not_equal}

///|
pub extend Field with Debug::{to_repr}

///|
/// A file from a `multipart/form-data` body.
///
/// The content is held whole. Streaming a part to disk instead of into memory is
/// what `limits` exists to make unnecessary until it is built.
pub(all) struct Upload {
  name : String
  filename : String
  content_type : String
  content : Bytes
  headers : Array[(String, String)]
} derive(Eq, Debug)

///|
pub extend Upload with Eq::{equal, not_equal}

///|
pub extend Upload with Debug::{to_repr}

///|
/// The size of the uploaded content in bytes.
pub fn Upload::size(self : Upload) -> Int {
  self.content.length()
}

///|
/// One of the part's own headers, by lowercased name.
pub fn Upload::header(self : Upload, name : StringView) -> String? {
  for pair in self.headers {
    if pair.0[:] == name {
      return Some(pair.1)
    }
  }
  None
}

///|
/// A parsed form: its text fields and its files.
struct Form {
  fields : Array[Field]
  files : Array[Upload]
}

///|
/// The first value under this name.
pub fn Form::field(self : Form, name : StringView) -> String? {
  for field in self.fields {
    if field.name[:] == name {
      return Some(field.value)
    }
  }
  None
}

///|
/// Every value under this name — a set of checkboxes sends the same name many
/// times, and taking only the first silently drops the rest.
pub fn Form::values(self : Form, name : StringView) -> Array[String] {
  let out : Array[String] = []
  for field in self.fields {
    if field.name[:] == name {
      out.push(field.value)
    }
  }
  out
}

///|
/// The first file under this name.
pub fn Form::file(self : Form, name : StringView) -> Upload? {
  for upload in self.files {
    if upload.name[:] == name {
      return Some(upload)
    }
  }
  None
}

///|
/// Every field, in the order they were sent.
pub fn Form::entries(self : Form) -> Array[Field] {
  self.fields
}

///|
/// Every file, in the order they were sent.
pub fn Form::uploads(self : Form) -> Array[Upload] {
  self.files
}

///|
/// Whether anything was parsed at all.
pub fn Form::is_empty(self : Form) -> Bool {
  self.fields.length() == 0 && self.files.length() == 0
}

///|
/// What a form is allowed to be.
///
/// A body arrives from whoever sent it, so both bounds are needed: a million
/// empty parts and one enormous part are different ways of asking a server to
/// allocate more than it has.
pub(all) struct Limits {
  parts : Int
  part_size : Int
} derive(Eq, Debug)

///|
pub extend Limits with Eq::{equal, not_equal}

///|
pub extend Limits with Debug::{to_repr}

///|
/// A thousand parts of a megabyte each — what Starlette's `max_files` and
/// `max_fields` default to, with python-multipart's part size. Generous for a
/// form and far from what exhausts a server. A caller that knows its own shape
/// should say so.
pub let limits : Limits = { parts: 1000, part_size: 1 << 20, }

///|
/// Build a bound by naming the parts that differ from the default.
///
/// The same thing can be written `{ ..@mime.limits, parts: 8 }`; this form reads
/// better when several parts differ.
///
/// There is no per-call mirror of these two. A bound belongs to an endpoint
/// rather than to a request — an avatar upload and a spreadsheet import are two
/// endpoints, each with its own — so the record is the only place it comes from,
/// and there is nothing to arbitrate.
pub fn Limits::new(
  parts? : Int = limits.parts,
  part_size? : Int = limits.part_size,
) -> Limits {
  { parts, part_size, }
}

///|
/// Why a body was not read as a form.
///
/// A form over its bounds is refused whole rather than truncated: a handler
/// given the first thousand parts of a larger form would be answering a request
/// nobody sent.
pub(all) suberror Refused {
  /// More parts than allowed.
  Parts(limit~ : Int)
  /// One part longer than allowed.
  Part(limit~ : Int, got~ : Int)
  /// A multipart body that stops making sense at this offset. Only raised under
  /// `strict`; otherwise the parts read so far are returned.
  Malformed(at~ : Int)
  /// A content type that is neither form encoding. Only raised under `strict`;
  /// otherwise the answer is an empty form.
  NotAForm(content_type~ : String)
} derive(Eq, Debug)

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
/// Parse a body by what its `Content-Type` says it is.
///
/// A content type that is neither form encoding yields an empty form rather
/// than an error: "this request carried no form" is an answer, not a failure,
/// and a caller asking for a form on a JSON request wants to hear that. `strict`
/// is for the caller who would rather be told.
pub fn parse(
  body : BytesView,
  content_type : StringView,
  limits? : Limits = limits,
  strict? : Bool = false,
) -> Form raise Refused {
  if starts_with(content_type, "multipart/form-data") {
    match boundary(content_type) {
      Some(edge) => multipart(body, edge[:], limits~, strict~)
      None =>
        if strict {
          raise NotAForm(content_type=content_type.to_owned())
        } else {
          { fields: [], files: [], }
        }
    }
  } else if starts_with(content_type, "application/x-www-form-urlencoded") {
    urlencoded(body, limits~)
  } else if strict {
    raise NotAForm(content_type=content_type.to_owned())
  } else {
    { fields: [], files: [], }
  }
}

///|
/// Parse an `application/x-www-form-urlencoded` body (the WHATWG URL standard's
/// form-urlencoded parsing).
///
/// `+` is a space here and nowhere else in a URL, which is the one thing about
/// this encoding everybody gets wrong.
pub fn urlencoded(
  body : BytesView,
  limits? : Limits = limits,
) -> Form raise Refused {
  let fields : Array[Field] = []
  let n = body.length()
  let mut start = 0
  for i = 0; i <= n; i = i + 1 {
    if i == n || body[i] == b'&' {
      if i > start {
        if fields.length() == limits.parts {
          raise Parts(limit=limits.parts)
        }
        if i - start > limits.part_size {
          raise Part(limit=limits.part_size, got=i - start)
        }
        let mut eq = -1
        for j = start; j < i; j = j + 1 {
          if body[j] == b'=' {
            eq = j
            break
          }
        }
        if eq < 0 {
          fields.push({ name: component(body[start:i]), value: "", })
        } else {
          fields.push({
            name: component(body[start:eq]),
            value: component(body[eq + 1:i]),
          })
        }
      }
      start = i + 1
    }
  }
  { fields, files: [], }
}

///|
/// Parse a `multipart/form-data` body (RFC 7578) given its boundary.
///
/// A part goes into the files when its `Content-Disposition` carries a
/// `filename` and into the fields when it does not, which is the only thing
/// distinguishing them on the wire.
pub fn multipart(
  body : BytesView,
  boundary : StringView,
  limits? : Limits = limits,
  strict? : Bool = false,
) -> Form raise Refused {
  let fields : Array[Field] = []
  let files : Array[Upload] = []
  let dash = ascii("--" + boundary.to_owned())
  let mut pos = index_of(body, dash[:], 0)
  while pos >= 0 {
    let after = pos + dash.length()
    // `--boundary--` closes the body; there is nothing after it but an epilogue.
    if has_at(body, after, b"--"[:]) {
      break
    }
    let head = if has_at(body, after, b"\r\n"[:]) { after + 2 } else { after }
    let blank = index_of(body, b"\r\n\r\n"[:], head)
    let next = index_of(body, dash[:], head)
    if blank < 0 || next < 0 || blank > next {
      // Inventing a structure for the rest would be deciding what the sender
      // meant, so the choice is between stopping with what was read and saying
      // so; `strict` is which.
      if strict {
        raise Malformed(at=head)
      }
      break
    }
    if fields.length() + files.length() == limits.parts {
      raise Parts(limit=limits.parts)
    }
    let headers = part_headers(body[head:blank])
    let from = blank + 4
    // The two bytes before the next delimiter are this part's own trailing
    // CRLF and are not content.
    let to = if next - 2 < from { from } else { next - 2 }
    if to - from > limits.part_size {
      raise Part(limit=limits.part_size, got=to - from)
    }
    let disposition = header(headers, "content-disposition").unwrap_or("")
    let name = param(disposition[:], "name").unwrap_or("")
    let content = body[from:to].to_owned()
    match param(disposition[:], "filename") {
      Some(filename) =>
        files.push({
          name,
          filename,
          content_type: header(headers, "content-type").unwrap_or(""),
          content,
          headers,
        })
      None => fields.push({ name, value: text(content[:]), })
    }
    pos = next
  }
  { fields, files, }
}

///|
/// A parameter out of a header value: `name` from
/// `form-data; name="file"; filename="a.txt"`.
///
/// A quoted value ends at the closing quote; a bare one at the next semicolon.
pub fn param(header : StringView, key : StringView) -> String? {
  let needle = key.to_owned() + "="
  let at = find(header, needle[:], 0)
  if at < 0 {
    return None
  }
  let mut i = at + needle.length()
  let n = header.length()
  let out = StringBuilder()
  if i < n && header.at(i).to_int() == 0x22 {
    i += 1
    while i < n && header.at(i).to_int() != 0x22 {
      out.write_view(header[i:i + 1])
      i += 1
    }
    Some(out.to_string())
  } else {
    while i < n && header.at(i).to_int() != 0x3B {
      out.write_view(header[i:i + 1])
      i += 1
    }
    Some(trim(out.to_string()[:]))
  }
}

///|
/// The `boundary` of a `multipart/form-data` content type.
pub fn boundary(content_type : StringView) -> String? {
  param(content_type, "boundary")
}

///|
/// Undo percent-encoding, leaving `+` alone.
///
/// A `%` that is not followed by two hexadecimal digits stands for itself,
/// which is what browsers do with the malformed URLs they are handed.
pub fn percent_decode(raw : BytesView) -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < raw.length() {
    if raw[i] == b'%' && i + 2 < raw.length() {
      let hi = nibble(raw[i + 1])
      let lo = nibble(raw[i + 2])
      if hi >= 0 && lo >= 0 {
        out.push(((hi << 4) | lo).to_byte())
        i += 3
        continue
      }
    }
    out.push(raw[i])
    i += 1
  }
  Bytes::from_array(out)
}

// ----------------------------------------------------------------- the pieces

///|
/// One component of a form body: `+` is a space, then percent-decoding, then the
/// bytes read as UTF-8.
fn component(raw : BytesView) -> String {
  let spaced : Array[Byte] = []
  for b in raw {
    spaced.push(if b == b'+' { b' ' } else { b })
  }
  text(percent_decode(Bytes::from_array(spaced)[:])[:])
}

///|
/// A part's header block, as lowercased name and value.
///
/// A line with no colon is not a header field and is dropped rather than
/// guessed at.
fn part_headers(block : BytesView) -> Array[(String, String)] {
  let out : Array[(String, String)] = []
  let line = text(block)
  let n = line.length()
  let mut start = 0
  for i = 0; i <= n; i = i + 1 {
    if i == n || line.at(i).to_int() == 0x0A {
      let end = if i > start && line.at(i - 1).to_int() == 0x0D {
        i - 1
      } else {
        i
      }
      let one = line[start:end]
      let mut colon = -1
      for j in 0..<one.length() {
        if one.at(j).to_int() == 0x3A {
          colon = j
          break
        }
      }
      if colon > 0 {
        out.push((trim(one[0:colon]).to_lower(), trim(one[colon + 1:])))
      }
      start = i + 1
    }
  }
  out
}

///|
fn header(headers : Array[(String, String)], name : String) -> String? {
  for pair in headers {
    if pair.0 == name {
      return Some(pair.1)
    }
  }
  None
}

///|
/// Bytes as text, with anything that is not UTF-8 replaced rather than refused:
/// a form field is what a browser sent, and refusing the whole request over one
/// stray byte in one field is not what a server wants to do.
fn text(raw : BytesView) -> String {
  @utf8.decode_lossy(raw)
}

///|
fn ascii(s : String) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<s.length() {
    out.push((s.at(i).to_int() & 0xFF).to_byte())
  }
  Bytes::from_array(out)
}

///|
fn has_at(hay : BytesView, at : Int, needle : BytesView) -> Bool {
  if at < 0 || at + needle.length() > hay.length() {
    return false
  }
  for i in 0..<needle.length() {
    if hay[at + i] != needle[i] {
      return false
    }
  }
  true
}

///|
fn index_of(hay : BytesView, needle : BytesView, from : Int) -> Int {
  let last = hay.length() - needle.length()
  for i = from; i <= last; i = i + 1 {
    if has_at(hay, i, needle) {
      return i
    }
  }
  -1
}

///|
fn find(hay : StringView, needle : StringView, from : Int) -> Int {
  let last = hay.length() - needle.length()
  for i = from; i <= last; i = i + 1 {
    let mut same = true
    for j in 0..<needle.length() {
      if hay.at(i + j) != needle.at(j) {
        same = false
        break
      }
    }
    if same {
      return i
    }
  }
  -1
}

///|
fn starts_with(s : StringView, prefix : String) -> Bool {
  if s.length() < prefix.length() {
    return false
  }
  for i in 0..<prefix.length() {
    let a = s.at(i).to_int()
    let b = prefix.at(i).to_int()
    let lower = if a >= 0x41 && a <= 0x5A { a + 32 } else { a }
    if lower != b {
      return false
    }
  }
  true
}

///|
fn trim(s : StringView) -> String {
  let mut from = 0
  let mut to = s.length()
  while from < to && is_space(s.at(from).to_int()) {
    from += 1
  }
  while to > from && is_space(s.at(to - 1).to_int()) {
    to -= 1
  }
  s[from:to].to_owned()
}

///|
fn is_space(c : Int) -> Bool {
  c == 0x20 || c == 0x09 || c == 0x0D || c == 0x0A
}

///|
fn nibble(b : Byte) -> Int {
  let c = b.to_int()
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
