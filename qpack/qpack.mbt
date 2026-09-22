// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Why a field section or an instruction was refused (RFC 9204 §2.2, §4).
///
/// Each one is a connection error of its own kind in §6, because after it the two ends
/// no longer agree about the dynamic table and nothing further can be read.
pub(all) suberror Refused {
  Malformed(String)
  Index(got~ : Int)
  Exceeded(limit~ : Int, got~ : Int)
} derive(Eq, Debug)

///|
/// A refusal prints as the fault it is.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Malformed(m) => logger.write_string("Malformed(" + m + ")")
    Index(got~) => logger.write_string("Index(got=\{got})")
    Exceeded(limit~, got~) =>
      logger.write_string("Exceeded(limit=\{limit}, got=\{got})")
  }
}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

// QPACK's prefixed-integer codec (RFC 9204 §4.1.1, which adopts RFC 7541 §5.1): an
// integer is carried in the low N bits of the first byte, with the representation's
// pattern flags in the high bits; a value that does not fit in N bits sets those bits
// to all-ones and spills the remainder over continuation bytes, 7 bits each. This is
// the arithmetic every QPACK field-line representation is built from — an index, a
// string length, the field-section prefix's insert count and base.

///|
/// Encode `value` as an RFC 7541 §5.1 `prefix`-prefix integer, OR-ing `flags` into
/// the high `8 - prefix` bits of the first byte (the representation's pattern).
pub fn integer(value : Int, prefix : Int, flags : Int) -> Bytes {
  let buf = Buffer()
  let max_prefix = (1 << prefix) - 1
  if value < max_prefix {
    buf.write_byte((flags | value).to_byte())
  } else {
    buf.write_byte((flags | max_prefix).to_byte())
    let mut remainder = value - max_prefix
    while remainder >= 128 {
      buf.write_byte((remainder % 128 + 128).to_byte())
      remainder = remainder / 128
    }
    buf.write_byte(remainder.to_byte())
  }
  buf.to_bytes()
}

///|
/// Decode an RFC 7541 §5.1 `prefix`-prefix integer from the front of `input` (its
/// first byte holds the value in its low `prefix`, any flags in the high bits are
/// ignored). Returns `(value, bytes-consumed)`, or `None` when a continuation byte has
/// not yet arrived (a partial read).
pub fn read_integer(input : BytesView, prefix : Int) -> (Int, Int)? {
  if input.length() == 0 {
    return None
  }
  let max_prefix = (1 << prefix) - 1
  let mut value = input[0].to_int() & max_prefix
  if value < max_prefix {
    return Some((value, 1))
  }
  let mut shift = 0
  let mut off = 1
  for ;; {
    if off >= input.length() {
      return None
    }
    let b = input[off].to_int()
    value = value + ((b & 127) << shift)
    shift = shift + 7
    off = off + 1
    if (b & 128) == 0 {
      break
    }
  }
  Some((value, off))
}

// The QPACK static table (RFC 9204 Appendix A): 99 predefined (name, value) entries,
// index 0..98, that a field line can reference instead of spelling the header out. The
// entries are transcribed verbatim from the RFC. An encoder looks an exact (name,
// value) up for an indexed field line, or a name alone for a literal-with-name-
// reference; a decoder reads an entry back by index.

///|
/// The 99 static-table entries in index order (RFC 9204 Appendix A).
let ascii_table : Array[(String, String)] = [
  (":authority", ""),
  (":path", "/"),
  ("age", "0"),
  ("content-disposition", ""),
  ("content-length", "0"),
  ("cookie", ""),
  ("date", ""),
  ("etag", ""),
  ("if-modified-since", ""),
  ("if-none-match", ""),
  ("last-modified", ""),
  ("link", ""),
  ("location", ""),
  ("referer", ""),
  ("set-cookie", ""),
  (":method", "CONNECT"),
  (":method", "DELETE"),
  (":method", "GET"),
  (":method", "HEAD"),
  (":method", "OPTIONS"),
  (":method", "POST"),
  (":method", "PUT"),
  (":scheme", "http"),
  (":scheme", "https"),
  (":status", "103"),
  (":status", "200"),
  (":status", "304"),
  (":status", "404"),
  (":status", "503"),
  ("accept", "*/*"),
  ("accept", "application/dns-message"),
  ("accept-encoding", "gzip, deflate, br"),
  ("accept-ranges", "bytes"),
  ("access-control-allow-headers", "cache-control"),
  ("access-control-allow-headers", "content-type"),
  ("access-control-allow-origin", "*"),
  ("cache-control", "max-age=0"),
  ("cache-control", "max-age=2592000"),
  ("cache-control", "max-age=604800"),
  ("cache-control", "no-cache"),
  ("cache-control", "no-store"),
  ("cache-control", "public, max-age=31536000"),
  ("content-encoding", "br"),
  ("content-encoding", "gzip"),
  ("content-type", "application/dns-message"),
  ("content-type", "application/javascript"),
  ("content-type", "application/json"),
  ("content-type", "application/x-www-form-urlencoded"),
  ("content-type", "image/gif"),
  ("content-type", "image/jpeg"),
  ("content-type", "image/png"),
  ("content-type", "text/css"),
  ("content-type", "text/html;charset=utf-8"),
  ("content-type", "text/plain"),
  ("content-type", "text/plain;charset=utf-8"),
  ("range", "bytes=0-"),
  ("strict-transport-security", "max-age=31536000"),
  ("strict-transport-security", "max-age=31536000;includesubdomains"),
  ("strict-transport-security", "max-age=31536000;includesubdomains;preload"),
  ("vary", "accept-encoding"),
  ("vary", "origin"),
  ("x-content-type-options", "nosniff"),
  ("x-xss-protection", "1; mode=block"),
  (":status", "100"),
  (":status", "204"),
  (":status", "206"),
  (":status", "302"),
  (":status", "400"),
  (":status", "403"),
  (":status", "421"),
  (":status", "425"),
  (":status", "500"),
  ("accept-language", ""),
  ("access-control-allow-credentials", "FALSE"),
  ("access-control-allow-credentials", "TRUE"),
  ("access-control-allow-headers", "*"),
  ("access-control-allow-methods", "get"),
  ("access-control-allow-methods", "get, post, options"),
  ("access-control-allow-methods", "options"),
  ("access-control-expose-headers", "content-length"),
  ("access-control-request-headers", "content-type"),
  ("access-control-request-method", "get"),
  ("access-control-request-method", "post"),
  ("alt-svc", "clear"),
  ("authorization", ""),
  (
    "content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'",
  ),
  ("early-data", "1"),
  ("expect-ct", ""),
  ("forwarded", ""),
  ("if-range", ""),
  ("origin", ""),
  ("purpose", "prefetch"),
  ("server", ""),
  ("timing-allow-origin", "*"),
  ("upgrade-insecure-requests", "1"),
  ("user-agent", ""),
  ("x-forwarded-for", ""),
  ("x-frame-options", "deny"),
  ("x-frame-options", "sameorigin"),
]

///|
/// The static table as fields, in the index order Appendix A gives them. Unlike HPACK's,
/// QPACK's static table is indexed from zero (RFC 9204 §3.1).
pub let static_table : Array[@header.Header] = {
  let out : Array[@header.Header] = []
  for e in ascii_table {
    out.push(@header.Header::of(e.0, e.1))
  }
  out
}

///|
/// The entry at `index`, or `None` when the index names nothing.
pub fn entry(index : Int) -> @header.Header? {
  if index < 0 || index >= static_table.length() {
    None
  } else {
    Some(static_table[index])
  }
}

///|
/// The index of the first entry whose name and value both match, for an indexed field
/// line; `None` if no entry matches exactly.
pub fn find(name : Bytes, value : Bytes) -> Int? {
  for i = 0; i < static_table.length(); i = i + 1 {
    let e = static_table[i]
    if e.name == name && e.value == value {
      return Some(i)
    }
  }
  None
}

///|
/// The index of the first entry whose name matches (regardless of value), for a
/// literal field line with a name reference; `None` if no entry has the name.
pub fn find_name(name : Bytes) -> Int? {
  for i = 0; i < static_table.length(); i = i + 1 {
    if static_table[i].name == name {
      return Some(i)
    }
  }
  None
}

// The QPACK Encoded Field Section Prefix (RFC 9204 §4.5.1): every field section opens with
// a Required Insert Count and a Base. The Required Insert Count states how many dynamic
// inserts the section depends on; it is transmitted modulo 2*MaxEntries (§4.5.1) and the
// decoder reconstructs the absolute value from the number of inserts it has already seen
// (§4.5.1.1), which lets a fixed-width field survive the dynamic table wrapping around. The
// Base anchors the section's relative indices and is carried as a sign bit plus a delta from
// the Required Insert Count. This prefix is what a field-line decoder reads before it can
// resolve any dynamic-table reference.

///|
/// The number of entries that fit in a table of `capacity` bytes at the 32-byte minimum
/// entry size — `MaxEntries` in RFC 9204 §4.5.1.1.
pub fn max_entries(capacity : Int) -> Int {
  capacity / 32
}

///|
/// Encode a field-section prefix (RFC 9204 §4.5.1): the Required Insert Count transmitted
/// modulo `2*max_entries`, then the Base as a sign bit (0 when `base >= req_insert_count`)
/// plus the delta.
pub fn prefix(req_insert_count : Int, base : Int, max_entries : Int) -> Bytes {
  let enc_ric = if req_insert_count == 0 {
    0
  } else {
    req_insert_count % (2 * max_entries) + 1
  }
  let buf = Buffer()
  buf.write_bytes(integer(enc_ric, 8, 0))
  if base >= req_insert_count {
    buf.write_bytes(integer(base - req_insert_count, 7, 0))
  } else {
    buf.write_bytes(integer(req_insert_count - base - 1, 7, 0x80))
  }
  buf.to_bytes()
}

///|
/// Reconstruct the absolute Required Insert Count from its encoded form, `max_entries`, and
/// the number of inserts the decoder has processed (RFC 9204 §4.5.1.1).
pub fn insert_count(
  encoded : Int,
  max_entries : Int,
  total_inserts : Int,
) -> Int raise Refused {
  if encoded == 0 {
    return 0
  }
  let full_range = 2 * max_entries
  if encoded > full_range {
    raise Malformed("QPACK encoded Required Insert Count exceeds 2*MaxEntries")
  }
  let max_value = total_inserts + max_entries
  let max_wrapped = max_value / full_range * full_range
  let mut ric = max_wrapped + encoded - 1
  if ric > max_value {
    if ric <= full_range {
      raise Malformed("QPACK Required Insert Count decode underflow")
    }
    ric = ric - full_range
  }
  if ric == 0 {
    raise Malformed("QPACK Required Insert Count of 0 encoded as non-zero")
  }
  ric
}

///|
/// Decode a field-section prefix (RFC 9204 §4.5.1), given `max_entries` and the decoder's
/// total inserts so far. Returns `(req_insert_count, base, bytes-consumed)`, or `None` on a
/// partial read.
pub fn read_prefix(
  input : BytesView,
  max_entries : Int,
  total_inserts : Int,
) -> (Int, Int, Int)? raise Refused {
  let (enc_ric, ric_len) = match read_integer(input, 8) {
    Some(v) => v
    None => return None
  }
  let req_insert_count = insert_count(enc_ric, max_entries, total_inserts)
  if input.length() <= ric_len {
    return None
  }
  let sign = (input[ric_len].to_int() & 0x80) != 0
  let (delta_base, base_len) = match read_integer(input[ric_len:], 7) {
    Some(v) => v
    None => return None
  }
  let base = if sign {
    req_insert_count - delta_base - 1
  } else {
    req_insert_count + delta_base
  }
  Some((req_insert_count, base, ric_len + base_len))
}

// The QPACK dynamic table (RFC 9204 §3.2): a FIFO of name/value entries that the encoder-
// stream instructions drive. Each entry costs `name.length() + value.length() + 32` toward
// the table size (§3.2.1); inserting evicts the oldest entries until the newcomer fits, or
// fails if it can never fit (§3.2.2). Entries keep a stable absolute index across evictions
// (§3.2.4); the encoder stream addresses them by a relative index counted back from the most
// recent insertion (§3.2.5). Applying an instruction resolves its name — from the static
// table, from a dynamic entry, or a literal — and inserts. This is the table the field-line
// decoder will read once dynamic references are enabled.

///|
/// A QPACK dynamic table: the live entries, the bytes they occupy, the capacity, the count
/// of entries ever inserted (the next absolute index), and how many have been evicted.
pub(all) struct Table {
  entries : Array[(Bytes, Bytes)]
  mut used : Int
  mut capacity : Int
  mut insert_count : Int
  mut dropped : Int
}

///|
/// A fresh, empty dynamic table with the given capacity in bytes.
pub fn Table::new(capacity : Int) -> Table {
  { entries: [], used: 0, capacity, insert_count: 0, dropped: 0, }
}

///|
/// The size an entry occupies in the table: its name and value octets plus 32 (RFC 9204
/// §3.2.1).
pub fn cost(name : Bytes, value : Bytes) -> Int {
  name.length() + value.length() + 32
}

///|
/// Evict oldest entries until `incoming` more bytes would fit under the capacity, or the
/// table is empty (RFC 9204 §3.2.2).
fn Table::evict_to_fit(self : Table, incoming : Int) -> Unit {
  while self.used + incoming > self.capacity && self.entries.length() > 0 {
    let (n, v) = self.entries[0]
    self.used = self.used - cost(n, v)
    let _ = self.entries.remove(0)
    self.dropped = self.dropped + 1
  }
}

///|
/// Set the table capacity, evicting whatever no longer fits (RFC 9204 §3.2.3).
pub fn Table::resize(self : Table, capacity : Int) -> Unit {
  self.capacity = capacity
  self.evict_to_fit(0)
}

///|
/// Insert an entry, evicting as needed. Returns `false` (adding nothing) when the entry
/// cannot fit even in an empty table (RFC 9204 §3.2.2).
pub fn Table::insert(self : Table, name : Bytes, value : Bytes) -> Bool {
  let size = cost(name, value)
  self.evict_to_fit(size)
  if self.used + size > self.capacity {
    return false
  }
  self.entries.push((name, value))
  self.used = self.used + size
  self.insert_count = self.insert_count + 1
  true
}

///|
/// The entry at absolute index `abs_index`, or `None` if it has been evicted or never
/// existed (RFC 9204 §3.2.4).
pub fn Table::get(self : Table, abs_index : Int) -> (Bytes, Bytes)? {
  let pos = abs_index - self.dropped
  if pos < 0 || pos >= self.entries.length() {
    None
  } else {
    Some(self.entries[pos])
  }
}

///|
/// The entry at encoder-stream relative index `rel` (0 = most recently inserted, RFC 9204
/// §3.2.5).
pub fn Table::relative(self : Table, rel : Int) -> (Bytes, Bytes)? {
  self.get(self.insert_count - 1 - rel)
}

///|
/// Apply an encoder-stream instruction to the table (RFC 9204 §4.3): set the capacity, or
/// insert an entry whose name comes from the static table, a dynamic entry (by relative
/// index), or a literal. Returns whether the resulting insert fit (always `true` for a
/// capacity change). Raises if a referenced name index is out of range.
pub fn Table::apply(self : Table, inst : Change) -> Bool raise Refused {
  match inst {
    SetCapacity(capacity) => {
      self.resize(capacity)
      true
    }
    InsertLiteral(name~, value~) => self.insert(name, value)
    Insert(is_static~, index~, value~) => {
      let name = if is_static {
        match entry(index) {
          Some(h) => h.name
          None =>
            raise Malformed(
              "static name index out of range: " + index.to_string(),
            )
        }
      } else {
        match self.relative(index) {
          Some((n, _)) => n
          None =>
            raise Malformed(
              "dynamic name index out of range: " + index.to_string(),
            )
        }
      }
      self.insert(name, value)
    }
    Duplicate(index~) =>
      match self.relative(index) {
        Some((n, v)) => self.insert(n, v)
        None =>
          raise Malformed("duplicate index out of range: " + index.to_string())
      }
  }
}

// QPACK field-line encoding (RFC 9204 §4.5): a field section is an encoded-field-
// section prefix followed by a run of field lines, each a header rendered as an indexed
// reference into the static table, a literal value with a static name reference, or a
// fully literal name and value. Strings carry an H bit selecting Huffman coding (RFC
// 7541 Appendix B, the same table HPACK uses — reused from moonrpc). This encoder never
// uses the dynamic table, so it emits a zero insert-count prefix and only static/literal
// representations, which is a complete and interoperable QPACK encoder (RFC 9204 §2.1
// permits an encoder to never index dynamically). The decoder reads those back; a field
// line that references the dynamic table is reported as unsupported (that layer is
// built separately).

///|
/// Encode a QPACK string literal: the `H` bit at position `prefix` (set when the
/// data is Huffman-coded), `pattern` in the bits above it, the octet length as a
/// `prefix`-prefix integer, then the (raw or Huffman) octets.
pub fn string(
  data : Bytes,
  prefix : Int,
  pattern : Int,
  huffman : Bool,
) -> Bytes {
  let payload = if huffman { @huffman.encode(data) } else { data }
  let h_bit = if huffman { 1 << prefix } else { 0 }
  let buf = Buffer()
  buf.write_bytes(integer(payload.length(), prefix, pattern | h_bit))
  buf.write_bytes(payload)
  buf.to_bytes()
}

///|
/// Decode a QPACK string literal whose length uses a `prefix`-prefix integer and
/// whose `H` bit sits at position `prefix`. Returns `(octets, bytes-consumed)`, or
/// `None` when the string has not fully arrived.
pub fn read_string(
  input : BytesView,
  prefix : Int,
) -> (Bytes, Int)? raise Refused {
  if input.length() == 0 {
    return None
  }
  let huffman = ((input[0].to_int() >> prefix) & 1) == 1
  let (length, len_consumed) = match read_integer(input, prefix) {
    Some(v) => v
    None => return None
  }
  if input.length() < len_consumed + length {
    return None
  }
  let raw = input[len_consumed:len_consumed + length].to_owned()
  let data = if huffman {
    @huffman.decode(raw) catch {
      e => raise Malformed("huffman decode: " + e.to_string())
    }
  } else {
    raw
  }
  Some((data, len_consumed + length))
}

///|
/// Encode a header list as a QPACK field section over the static table only: a
/// zero-insert-count / zero-base prefix, then one field line per header — an indexed
/// static entry for an exact match, a static name reference plus a literal value when
/// the name is known, or a fully literal name and value otherwise. `huffman` chooses
/// whether literal strings are Huffman-coded.
pub fn encode(headers : Array[@header.Header], huffman? : Bool = true) -> Bytes {
  let buf = Buffer()
  // Encoded Field Section Prefix (RFC 9204 §4.5.1): Required Insert Count = 0 (no
  // dynamic entries), then S = 0 with Delta Base = 0.
  buf.write_byte(0)
  buf.write_byte(0)
  for header in headers {
    let name = header.name
    let value = header.value
    match find(name, value) {
      // Indexed Field Line (§4.5.2), static table: `1 T=1 | Index(6-bit prefix)`.
      Some(index) => buf.write_bytes(integer(index, 6, 0xc0))
      None =>
        match find_name(name) {
          // Literal Field Line With Name Reference (§4.5.4), static: `0 1 N=0 T=1 |
          // Name Index(4-bit prefix)`, then the value string (7-bit prefix).
          Some(index) => {
            buf.write_bytes(integer(index, 4, 0x50))
            buf.write_bytes(string(value, 7, 0, huffman))
          }
          // Literal Field Line With Literal Name (§4.5.6): `0 0 1 N=0 H | Name
          // Length(3-bit prefix)`, the name, then the value string.
          None => {
            buf.write_bytes(string(name, 3, 0x20, huffman))
            buf.write_bytes(string(value, 7, 0, huffman))
          }
        }
    }
  }
  buf.to_bytes()
}

///|
/// Decode a QPACK field section (encoded over the static table) back into its header
/// list. The prefix's insert count and base are read and required to be zero (this
/// decoder resolves static references only); a field line that references the dynamic
/// table is reported as unsupported.
pub fn decode(input : Bytes) -> Array[@header.Header] raise Refused {
  let view = input[:]
  // Encoded Field Section Prefix: Required Insert Count then S + Delta Base.
  let (insert_count, ric_len) = match read_integer(view, 8) {
    Some(v) => v
    None => raise Malformed("truncated field section prefix (insert count)")
  }
  if insert_count != 0 {
    raise Malformed("non-zero Required Insert Count needs the dynamic table")
  }
  let (_base, base_len) = match read_integer(view[ric_len:], 7) {
    Some(v) => v
    None => raise Malformed("truncated field section prefix (base)")
  }
  let mut off = ric_len + base_len
  let headers : Array[@header.Header] = []
  while off < view.length() {
    let b0 = view[off].to_int()
    if (b0 & 0x80) != 0 {
      // Indexed Field Line (§4.5.2): bit 6 is T (1 = static table).
      if (b0 & 0x40) == 0 {
        raise Malformed("dynamic-table indexed field line unsupported")
      }
      let (index, consumed) = read_integer_at(view, off, 6)
      headers.push(static_entry(index))
      off += consumed
    } else if (b0 & 0x40) != 0 {
      // Literal Field Line With Name Reference (§4.5.4): bit 4 is T.
      if (b0 & 0x10) == 0 {
        raise Malformed("dynamic-table name reference unsupported")
      }
      let (index, name_consumed) = read_integer_at(view, off, 4)
      let name = static_entry(index).name
      off += name_consumed
      let (value, value_consumed) = read_string_at(view, off, 7)
      headers.push({ name, value, })
      off += value_consumed
    } else if (b0 & 0x20) != 0 {
      // Literal Field Line With Literal Name (§4.5.6): name string uses a 3-bit prefix.
      let (name, name_consumed) = read_string_at(view, off, 3)
      off += name_consumed
      let (value, value_consumed) = read_string_at(view, off, 7)
      headers.push({ name, value, })
      off += value_consumed
    } else {
      // 0b0000_xxxx: Indexed / Literal With Post-Base Index — dynamic-table only.
      raise Malformed("post-base (dynamic-table) field line unsupported")
    }
  }
  headers
}

///|
/// The static-table entry at `index`, or raise if the index is out of range.
fn static_entry(index : Int) -> @header.Header raise Refused {
  match entry(index) {
    Some(entry) => entry
    None => raise Malformed("static index out of range: " + index.to_string())
  }
}

///|
/// Decode a prefix integer starting at `off` in `view`, raising on truncation.
fn read_integer_at(
  view : BytesView,
  off : Int,
  prefix : Int,
) -> (Int, Int) raise Refused {
  match read_integer(view[off:], prefix) {
    Some(v) => v
    None => raise Malformed("truncated field-line integer")
  }
}

///|
/// Decode a string starting at `off` in `view`, raising on truncation.
fn read_string_at(
  view : BytesView,
  off : Int,
  prefix : Int,
) -> (Bytes, Int) raise Refused {
  match read_string(view[off:], prefix) {
    Some(v) => v
    None => raise Malformed("truncated field-line string")
  }
}

// Decoding a QPACK field section that references the dynamic table (RFC 9204 §4.5). The
// static-only decoder in field.mbt handles the representations that need no table
// state; this one reads the full section prefix (Required Insert Count and Base) and then
// resolves every representation, including the four that address the dynamic table: an
// indexed line by relative index (§4.5.2, T=0) or post-base index (§4.5.3), and a literal
// line whose name comes from a dynamic entry by relative (§4.5.4, T=0) or post-base
// (§4.5.5) index. A field-line relative index counts back from Base — index 0 is the entry
// at absolute index Base-1 (§3.2.6) — while a post-base index counts up from Base. This is
// the decode path a server uses to read a peer's dynamically indexed headers.

///|
/// The dynamic entry a field-line relative index selects: absolute index `base - 1 - rel`
/// (RFC 9204 §3.2.6), decoded to strings.
fn relative_of(
  table : Table,
  base : Int,
  rel : Int,
) -> @header.Header raise Refused {
  match table.get(base - 1 - rel) {
    Some((n, v)) => { name: n, value: v, }
    None =>
      raise Malformed(
        "QPACK dynamic relative index out of range: " + rel.to_string(),
      )
  }
}

///|
/// The dynamic entry a post-base index selects: absolute index `base + post` (RFC 9204
/// §3.2.6), decoded to strings.
fn postbase(
  table : Table,
  base : Int,
  post : Int,
) -> @header.Header raise Refused {
  match table.get(base + post) {
    Some((n, v)) => { name: n, value: v, }
    None =>
      raise Malformed("QPACK post-base index out of range: " + post.to_string())
  }
}

///|
/// Decode a QPACK field section that may reference the dynamic `table`, given `max_entries`
/// (from the negotiated maximum table capacity). Reads the section prefix, then every field
/// line — static or dynamic, indexed or literal, pre- or post-base — into the header list.
/// Raises if a reference is out of range or the section is malformed.
pub fn decode_with(
  input : Bytes,
  table : Table,
  max_entries : Int,
) -> Array[@header.Header] raise Refused {
  let view = input[:]
  let (_ric, base, prefix_len) = match
    read_prefix(view, max_entries, table.insert_count) {
    Some(v) => v
    None => raise Malformed("truncated field section prefix")
  }
  let headers : Array[@header.Header] = []
  let mut off = prefix_len
  while off < view.length() {
    let b0 = view[off].to_int()
    if (b0 & 0x80) != 0 {
      // Indexed Field Line (§4.5.2): T at bit 6 (1 = static).
      let is_static = (b0 & 0x40) != 0
      let (index, consumed) = read_integer_at(view, off, 6)
      headers.push(
        if is_static {
          static_entry(index)
        } else {
          relative_of(table, base, index)
        },
      )
      off += consumed
    } else if (b0 & 0x40) != 0 {
      // Literal Field Line With Name Reference (§4.5.4): T at bit 4.
      let is_static = (b0 & 0x10) != 0
      let (index, name_consumed) = read_integer_at(view, off, 4)
      let name = if is_static {
        static_entry(index).name
      } else {
        relative_of(table, base, index).name
      }
      off += name_consumed
      let (value, value_consumed) = read_string_at(view, off, 7)
      headers.push({ name, value, })
      off += value_consumed
    } else if (b0 & 0x20) != 0 {
      // Literal Field Line With Literal Name (§4.5.6).
      let (name, name_consumed) = read_string_at(view, off, 3)
      off += name_consumed
      let (value, value_consumed) = read_string_at(view, off, 7)
      headers.push({ name, value, })
      off += value_consumed
    } else if (b0 & 0x10) != 0 {
      // Indexed Field Line With Post-Base Index (§4.5.3): `0001` + index (4-bit prefix).
      let (index, consumed) = read_integer_at(view, off, 4)
      headers.push(postbase(table, base, index))
      off += consumed
    } else {
      // Literal Field Line With Post-Base Name Reference (§4.5.5): `0000 N` + name index
      // (3-bit prefix), then the value.
      let (index, name_consumed) = read_integer_at(view, off, 3)
      let name = postbase(table, base, index).name
      off += name_consumed
      let (value, value_consumed) = read_string_at(view, off, 7)
      headers.push({ name, value, })
      off += value_consumed
    }
  }
  headers
}

// A QPACK encoder that indexes into the dynamic table (RFC 9204 §2.1, §4.5). It pairs the
// two outputs a real encoder produces: the encoder-stream instructions that populate the
// decoder's dynamic table, and the field section that references those entries. The strategy
// here is the simple, always-index one the RFC permits: a header that matches the static
// table exactly is referenced there directly; otherwise the entry is inserted into the
// dynamic table (with a static name reference when the name is known, else a literal name)
// and the field line references it by relative index. An entry too large for the table falls
// back to a literal field line. Sections use Base = the post-insertion insert count, so every
// dynamic reference is a pre-Base relative index. This closes the loop with the dynamic
// decoder: apply the instructions to a peer table, then decode the section against it.

///|
/// How a single header is rendered in the field section.
priv enum Ref {
  RefStatic(Int)
  RefDynamic(Int) // absolute index in the dynamic table
  RefLiteral(Bytes, Bytes)
}

///|
/// Encode `headers` with dynamic indexing over `table` (the encoder's view, mutated by the
/// inserts). Returns the encoder-stream instruction block and the field section. `max_entries`
/// comes from the negotiated maximum table capacity.
pub fn encode_with(
  headers : Array[@header.Header],
  table : Table,
  max_entries : Int,
  huffman? : Bool = true,
) -> (Bytes, Bytes) {
  let instr = Buffer()
  let refs : Array[Ref] = []
  for header in headers {
    let name = header.name
    let value = header.value
    match find(name, value) {
      Some(index) => refs.push(RefStatic(index))
      None => {
        let name_bytes = name
        let value_bytes = value
        if cost(name_bytes, value_bytes) <= table.capacity {
          let inst = match find_name(name) {
            Some(name_index) =>
              Insert(is_static=true, index=name_index, value=value_bytes)
            None => InsertLiteral(name=name_bytes, value=value_bytes)
          }
          instr.write_bytes(Change::encode(inst, huffman~))
          // apply cannot raise here: the name index (if any) is a valid static entry and
          // the value fits the capacity.
          let _ = table.apply(inst) catch { _ => false }
          refs.push(RefDynamic(table.insert_count - 1))
        } else {
          refs.push(RefLiteral(name_bytes, value_bytes))
        }
      }
    }
  }
  let base = table.insert_count
  let section = Buffer()
  section.write_bytes(prefix(base, base, max_entries))
  for r in refs {
    match r {
      RefStatic(index) => section.write_bytes(integer(index, 6, 0xc0))
      RefDynamic(abs) => section.write_bytes(integer(base - 1 - abs, 6, 0x80))
      RefLiteral(name, value) => {
        section.write_bytes(string(name, 3, 0x20, huffman))
        section.write_bytes(string(value, 7, 0, huffman))
      }
    }
  }
  (instr.to_bytes(), section.to_bytes())
}

// QPACK encoder- and decoder-stream instructions (RFC 9204 §4.3, §4.4). The encoder
// stream carries the instructions that mutate the dynamic table — set its capacity, insert
// an entry (by name reference or with a literal name), or duplicate an existing entry — and
// the decoder stream carries the acknowledgements that let the encoder reclaim table space:
// a section acknowledgement, a stream cancellation, and an insert-count increment. Each
// instruction is a pattern in the high bits of its first byte over a QPACK prefixed integer
// (and, for inserts, string literals). This is the wire codec the dynamic-table state
// machine drives; the table itself is built on top of it.

///|
/// An encoder-stream instruction (RFC 9204 §4.3).
pub(all) enum Change {
  /// Set Dynamic Table Capacity (§4.3.1): `001` + capacity (5-bit prefix).
  SetCapacity(Int)
  /// Insert With Name Reference (§4.3.2): `1` + T (static/dynamic) + name index (6-bit
  /// prefix), then the value string.
  Insert(is_static~ : Bool, index~ : Int, value~ : Bytes)
  /// Insert With Literal Name (§4.3.3): `01` + H + name length (5-bit prefix) + name,
  /// then the value string.
  InsertLiteral(name~ : Bytes, value~ : Bytes)
  /// Duplicate (§4.3.4): `000` + index (5-bit prefix).
  Duplicate(index~ : Int)
} derive(Eq, Debug)

///|
/// A decoder-stream instruction (RFC 9204 §4.4).
pub(all) enum Ack {
  /// Section Acknowledgement (§4.4.1): `1` + stream id (7-bit prefix).
  Section(stream_id~ : Int)
  /// Stream Cancellation (§4.4.2): `01` + stream id (6-bit prefix).
  Cancel(stream_id~ : Int)
  /// Insert Count Increment (§4.4.3): `00` + increment (6-bit prefix).
  Increment(increment~ : Int)
} derive(Eq, Debug)

///|
/// Encode an encoder-stream instruction (RFC 9204 §4.3). `huffman` chooses whether the
/// literal strings of the insert instructions are Huffman-coded.
pub fn Change::encode(inst : Change, huffman? : Bool = true) -> Bytes {
  match inst {
    SetCapacity(capacity) => integer(capacity, 5, 0x20)
    Insert(is_static~, index~, value~) => {
      let buf = Buffer()
      buf.write_bytes(
        integer(index, 6, 0x80 | (if is_static { 0x40 } else { 0 })),
      )
      buf.write_bytes(string(value, 7, 0, huffman))
      buf.to_bytes()
    }
    InsertLiteral(name~, value~) => {
      let buf = Buffer()
      buf.write_bytes(string(name, 5, 0x40, huffman))
      buf.write_bytes(string(value, 7, 0, huffman))
      buf.to_bytes()
    }
    Duplicate(index~) => integer(index, 5, 0x00)
  }
}

///|
/// Decode one encoder-stream instruction from the front of `input` (RFC 9204 §4.3),
/// dispatching on the pattern in the first byte's high bits. Returns `(instruction,
/// bytes-consumed)`, or `None` when the instruction has not fully arrived.
pub fn Change::decode(input : BytesView) -> (Change, Int)? raise Refused {
  if input.length() == 0 {
    return None
  }
  let b0 = input[0].to_int()
  if (b0 & 0x80) != 0 {
    let is_static = (b0 & 0x40) != 0
    let (index, ic) = match read_integer(input, 6) {
      Some(v) => v
      None => return None
    }
    match read_string(input[ic:], 7) {
      Some((value, vc)) => Some((Insert(is_static~, index~, value~), ic + vc))
      None => None
    }
  } else if (b0 & 0x40) != 0 {
    let (name, nc) = match read_string(input, 5) {
      Some(v) => v
      None => return None
    }
    match read_string(input[nc:], 7) {
      Some((value, vc)) => Some((InsertLiteral(name~, value~), nc + vc))
      None => None
    }
  } else if (b0 & 0x20) != 0 {
    match read_integer(input, 5) {
      Some((capacity, cc)) => Some((SetCapacity(capacity), cc))
      None => None
    }
  } else {
    match read_integer(input, 5) {
      Some((index, dc)) => Some((Duplicate(index~), dc))
      None => None
    }
  }
}

///|
/// Encode a decoder-stream instruction (RFC 9204 §4.4).
pub fn Ack::encode(inst : Ack) -> Bytes {
  match inst {
    Section(stream_id~) => integer(stream_id, 7, 0x80)
    Cancel(stream_id~) => integer(stream_id, 6, 0x40)
    Increment(increment~) => integer(increment, 6, 0x00)
  }
}

///|
/// Decode one decoder-stream instruction from the front of `input` (RFC 9204 §4.4).
/// Returns `(instruction, bytes-consumed)`, or `None` on a partial read.
pub fn Ack::decode(input : BytesView) -> (Ack, Int)? {
  if input.length() == 0 {
    return None
  }
  let b0 = input[0].to_int()
  if (b0 & 0x80) != 0 {
    match read_integer(input, 7) {
      Some((sid, c)) => Some((Section(stream_id=sid), c))
      None => None
    }
  } else if (b0 & 0x40) != 0 {
    match read_integer(input, 6) {
      Some((sid, c)) => Some((Cancel(stream_id=sid), c))
      None => None
    }
  } else {
    match read_integer(input, 6) {
      Some((inc, c)) => Some((Increment(increment=inc), c))
      None => None
    }
  }
}

///|
pub extend Ack with Debug::{to_repr}

///|
pub extend Ack with Eq::{not_equal, equal}

///|
pub extend Change with Debug::{to_repr}

///|
pub extend Change with Eq::{not_equal, equal}
