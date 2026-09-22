// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Why a header block was refused (RFC 7541 §6): a representation that does not parse,
/// an index naming nothing, or a size update past what the peer allowed.
///
/// Every one of them is a connection error in HTTP/2 (RFC 9113 §4.3), because the two
/// ends' dynamic tables have gone out of step and nothing after this point can be read.
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

///|
/// How many octets a dynamic table holds by default.
///
/// Four kibibytes is the value HTTP/2 gives `SETTINGS_HEADER_TABLE_SIZE` before either
/// end has said otherwise (RFC 9113 §6.5.2), so it is what both tables start at.
pub let limit : Int = 4096

///|
/// The 61-entry HPACK static header table (RFC 7541, Appendix A). Entry `i`
/// (0-based here) carries HPACK index `i + 1`; use `entry` for the
/// 1-based RFC lookup. Values are empty for name-only entries.
let ascii_table : Array[(String, String)] = [
  (":authority", ""),
  (":method", "GET"),
  (":method", "POST"),
  (":path", "/"),
  (":path", "/index.html"),
  (":scheme", "http"),
  (":scheme", "https"),
  (":status", "200"),
  (":status", "204"),
  (":status", "206"),
  (":status", "304"),
  (":status", "400"),
  (":status", "404"),
  (":status", "500"),
  ("accept-charset", ""),
  ("accept-encoding", "gzip, deflate"),
  ("accept-language", ""),
  ("accept-ranges", ""),
  ("accept", ""),
  ("access-control-allow-origin", ""),
  ("age", ""),
  ("allow", ""),
  ("authorization", ""),
  ("cache-control", ""),
  ("content-disposition", ""),
  ("content-encoding", ""),
  ("content-language", ""),
  ("content-length", ""),
  ("content-location", ""),
  ("content-range", ""),
  ("content-type", ""),
  ("cookie", ""),
  ("date", ""),
  ("etag", ""),
  ("expect", ""),
  ("expires", ""),
  ("from", ""),
  ("host", ""),
  ("if-match", ""),
  ("if-modified-since", ""),
  ("if-none-match", ""),
  ("if-range", ""),
  ("if-unmodified-since", ""),
  ("last-modified", ""),
  ("link", ""),
  ("location", ""),
  ("max-forwards", ""),
  ("proxy-authenticate", ""),
  ("proxy-authorization", ""),
  ("range", ""),
  ("referer", ""),
  ("refresh", ""),
  ("retry-after", ""),
  ("server", ""),
  ("set-cookie", ""),
  ("strict-transport-security", ""),
  ("transfer-encoding", ""),
  ("user-agent", ""),
  ("vary", ""),
  ("via", ""),
  ("www-authenticate", ""),
]

///|
/// Look up an HPACK static-table entry by its 1-based RFC index (`1..=61`),
/// returning `(name, value)` or `None` when the index is out of range.
pub fn entry(index : Int) -> Header? {
  if index < 1 || index > static_table.length() {
    None
  } else {
    Some(static_table[index - 1])
  }
}

///|
/// Encode `value` as an HPACK integer with an `prefix`-bit prefix (RFC 7541
/// §5.1). The high `8 - prefix` bits of the first octet are left zero for
/// the caller to OR in any flag bits. Examples: `10` on a 5-bit prefix is
/// `[0x0A]`; `1337` on a 5-bit prefix is `[0x1F, 0x9A, 0x0A]`.
pub fn integer(value : Int, prefix : Int) -> Bytes {
  let buf = Buffer()
  let max_prefix = (1 << prefix) - 1
  if value < max_prefix {
    buf.write_byte(value.to_byte())
  } else {
    buf.write_byte(max_prefix.to_byte())
    let mut rest = value - max_prefix
    while rest >= 128 {
      buf.write_byte((rest % 128 + 128).to_byte())
      rest = rest / 128
    }
    buf.write_byte(rest.to_byte())
  }
  buf.to_bytes()
}

///|
/// Decode an HPACK integer with an `prefix`-bit prefix from `data` starting
/// at `offset` (RFC 7541 §5.1), returning `(value, bytes_consumed)`. Any flag
/// bits above the prefix in the first octet are masked off and ignored.
pub fn read_integer(
  data : BytesView,
  offset : Int,
  prefix : Int,
) -> (Int, Int) raise Refused {
  if offset >= data.length() {
    raise Malformed("truncated HPACK integer prefix")
  }
  let max_prefix = (1 << prefix) - 1
  let first = data[offset].to_int() & max_prefix
  if first < max_prefix {
    (first, 1)
  } else {
    // Accumulate in 64 bits and reject anything that would not fit a positive 32-bit
    // Int (RFC 7541 §5.1), so a truncated or over-long continuation raises instead of
    // reading past the buffer or overflowing.
    let mut value = max_prefix.to_int64()
    let mut shift = 0
    let mut consumed = 1
    for ;; {
      if offset + consumed >= data.length() {
        raise Malformed("truncated HPACK integer")
      }
      if shift >= 35 {
        raise Malformed("HPACK integer too long")
      }
      let octet = data[offset + consumed].to_int()
      consumed = consumed + 1
      value = value + (octet & 127).to_int64() * (1L << shift)
      shift = shift + 7
      if value > 0x7FFFFFFFL {
        raise Malformed("HPACK integer too large")
      }
      if (octet & 128) == 0 {
        break
      }
    }
    (value.to_int(), consumed)
  }
}

///|
/// Whether the string literal at `offset` is Huffman-coded, i.e. the `H` bit
/// (the top bit of the length octet) is set (RFC 7541 §5.2).
pub fn is_huffman(data : BytesView, offset : Int) -> Bool {
  (data[offset].to_int() & 0x80) != 0
}

///|
/// A string literal (RFC 7541 §5.2): the length as a seven-bit-prefix integer, then the
/// octets, with the `H` bit saying whether they are Huffman-coded.
///
/// `huffman` takes the shorter of the two forms, which is what an encoder does; `false`
/// writes the octets as they are, which is what a test with a published block needs.
///
/// A tie goes to the coded form, which is what RFC 7541's own examples do: it costs
/// nothing and leaves less of the value legible to anything reading the connection.
pub fn string(octets : BytesView, huffman? : Bool = true) -> Bytes {
  let plain = octets.to_owned()
  if huffman && @huffman.size(octets) <= octets.length() {
    let coded = @huffman.encode(octets)
    let head = integer(coded.length(), 7)
    let buf = Buffer()
    buf.write_byte((head[0].to_int() | 0x80).to_byte())
    buf.write_bytes(head[1:].to_owned())
    buf.write_bytes(coded)
    buf.to_bytes()
  } else {
    let buf = Buffer()
    buf.write_bytes(integer(plain.length(), 7))
    buf.write_bytes(plain)
    buf.to_bytes()
  }
}

///|
/// Decode an HPACK string literal from `data` at `offset`, returning `(octets,
/// bytes_consumed)`. The length is read as a 7-bit-prefix integer (the `H` bit
/// is masked off); this is the inverse of `string_raw` for `H = 0`.
/// Use `is_huffman` first if the literal may be Huffman-coded, as
/// Huffman decoding is not applied here.
pub fn read_literal(
  data : BytesView,
  offset : Int,
) -> (Bytes, Int) raise Refused {
  let (len, int_len) = read_integer(data, offset, 7)
  let start = offset + int_len
  // Bound the literal against the buffer without recomputing `start + len` (which
  // could wrap), so a length claiming more than remains raises instead of slicing OOB.
  if start > data.length() || len > data.length() - start {
    raise Malformed("HPACK string literal runs past the block")
  }
  (data[start:start + len].to_owned(), int_len + len)
}

// HPACK header compression: the dynamic table with size-bounded eviction
// (RFC 7541 §2.3.2, §4), the six header-field representations (§6.1–6.3), and a
// stateful encoder/decoder pair that share the static (§2.3.1) and dynamic index
// address spaces. Byte-oriented throughout so binary metadata (`-bin`) survives.

///|
/// A decoded header field: `name` and `value` as raw octet strings (HTTP/2 header
/// names and values are byte sequences, and gRPC `-bin` metadata is binary).
pub(all) struct Header {
  name : Bytes
  value : Bytes
} derive(Eq, Debug)

///|
/// ASCII/latin-1 `String` → `Bytes`, one octet per code unit. Used only for the
/// static table, whose entries are all ASCII (RFC 7541 Appendix A).
fn octets(s : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < s.length(); i = i + 1 {
    buf.write_byte((s[i].to_int() & 0xFF).to_byte())
  }
  buf.to_bytes()
}

///|
/// The static table as `(name, value)` octet pairs, in RFC index order (index 1
/// at position 0). Derived once from `static_table`.
pub let static_table : Array[Header] = {
  let out : Array[Header] = []
  for e in ascii_table {
    out.push({ name: octets(e.0), value: octets(e.1), })
  }
  out
}

// -- string literals with Huffman (RFC 7541 §5.2) ---------------------------

///|
/// Read an HPACK string literal at `offset`, resolving Huffman coding when the
/// `H` bit is set, returning `(octets, bytes_consumed)`. Unlike
/// `read_literal`, this applies Huffman decoding. Raises on bad Huffman.
pub fn read_string(
  data : BytesView,
  offset : Int,
) -> (Bytes, Int) raise Refused {
  let huff = is_huffman(data, offset)
  let (raw, consumed) = read_literal(data, offset)
  if huff {
    (
      @huffman.decode(raw[:]) catch {
        e => raise Malformed("a Huffman string literal: \{e}")
      },
      consumed,
    )
  } else {
    (raw, consumed)
  }
}

// -- dynamic table (RFC 7541 §2.3.2, §4) ------------------------------------

///|
/// The HPACK dynamic table: a FIFO of recently seen `(name, value)` entries,
/// newest first (`entries[0]`), bounded by `limit` octets where each entry
/// costs `name.len + value.len + 32` (RFC 7541 §4.1). Adding evicts the oldest
/// entries until the newcomer fits; an entry larger than `limit` empties the
/// table and is not stored (§4.4).
pub(all) struct Table {
  mut entries : Array[(Bytes, Bytes)]
  mut size : Int
  mut limit : Int
}

///|
/// A new empty dynamic table bounded by `limit` octets (default 4096, the
/// HTTP/2 initial `SETTINGS_HEADER_TABLE_SIZE`).
pub fn Table::new(limit? : Int = limit) -> Table {
  { entries: [], size: 0, limit, }
}

///|
fn cost(name : Bytes, value : Bytes) -> Int {
  name.length() + value.length() + 32
}

///|
/// Evict oldest entries until the table is within `limit`.
fn Table::evict(self : Table) -> Unit {
  while self.size > self.limit && self.entries.length() > 0 {
    let old = self.entries.remove(self.entries.length() - 1)
    self.size = self.size - cost(old.0, old.1)
  }
}

///|
/// Resize the table (a dynamic table size update, RFC 7541 §4.2), evicting to fit.
pub fn Table::resize(self : Table, limit : Int) -> Unit {
  self.limit = limit
  self.evict()
}

///|
/// Insert `(name, value)` at the front, evicting oldest entries to make room. If
/// the entry alone exceeds `limit` the table ends up empty (RFC 7541 §4.4).
pub fn Table::add(self : Table, name : Bytes, value : Bytes) -> Unit {
  let sz = cost(name, value)
  while self.size + sz > self.limit && self.entries.length() > 0 {
    let old = self.entries.remove(self.entries.length() - 1)
    self.size = self.size - cost(old.0, old.1)
  }
  if sz <= self.limit {
    self.entries.insert(0, (name, value))
    self.size = self.size + sz
  }
}

///|
/// The field an HPACK index names, across the static and dynamic tables together
/// (RFC 7541 §2.3.3): one through sixty-one are the static table, and everything above
/// is this table, newest first. `None` when the index names nothing.
pub fn Table::get(self : Table, index : Int) -> Header? {
  lookup(self, index)
}

///|
/// The ceiling this table evicts to keep under, in octets.
pub fn Table::limit(self : Table) -> Int {
  self.limit
}

///|
/// The number of entries currently in the dynamic table.
pub fn Table::count(self : Table) -> Int {
  self.entries.length()
}

///|
/// The current total size of the dynamic table in octets (§4.1 accounting).
pub fn Table::size(self : Table) -> Int {
  self.size
}

///|
/// Resolve an HPACK index against the combined static + dynamic address space
/// (RFC 7541 §2.3.3): `1..=61` index the static table; `62..` index the dynamic
/// table newest-first. Returns `None` when out of range.
fn lookup(dt : Table, index : Int) -> Header? {
  let fixed = static_table.length()
  if index >= 1 && index <= fixed {
    Some(static_table[index - 1])
  } else {
    let d = index - fixed - 1
    if d >= 0 && d < dt.entries.length() {
      Some({ name: dt.entries[d].0, value: dt.entries[d].1, })
    } else {
      None
    }
  }
}

///|
/// Encode a dynamic table size update (RFC 7541 §6.3): `001` prefix with the new
/// maximum size as a 5-bit-prefix integer.
pub fn size_update(limit : Int) -> Bytes {
  let e = integer(limit, 5)
  let buf = Buffer()
  buf.write_byte((e[0].to_int() | 0x20).to_byte())
  buf.write_bytes(e[1:].to_owned())
  buf.to_bytes()
}

// -- decoder (RFC 7541 §6) --------------------------------------------------

///|
/// A stateful HPACK decoder: it owns a dynamic table that persists across the
/// header blocks of a connection. `limit` is the peer-agreed hard cap
/// (`SETTINGS_HEADER_TABLE_SIZE`) a size update may not exceed.
pub(all) struct Decoder {
  table : Table
  limit : Int
}

///|
/// A new decoder whose dynamic table is bounded by `limit` octets (also the
/// hard cap enforced on dynamic table size updates).
pub fn Decoder::new(limit? : Int = limit) -> Decoder {
  { table: Table::new(limit~), limit, }
}

///|
/// Read a header-field name that is either indexed (`index != 0`) or a following
/// string literal (`index == 0`).
fn Decoder::read_name(
  self : Decoder,
  block : BytesView,
  index : Int,
  off : Int,
) -> (Bytes, Int) raise Refused {
  if index == 0 {
    read_string(block, off)
  } else {
    match lookup(self.table, index) {
      Some(header) => (header.name, 0)
      None => raise Index(got=index)
    }
  }
}

///|
/// Decode one complete header block into its header list (RFC 7541 §6), mutating
/// the dynamic table for incrementally indexed fields and size updates. Raises
/// `Malformed`/`Malformed` on any malformed representation.
pub fn Decoder::decode(
  self : Decoder,
  block : BytesView,
) -> Array[Header] raise Refused {
  let out : Array[Header] = []
  let mut off = 0
  let n = block.length()
  while off < n {
    let b = block[off].to_int()
    if (b & 0x80) != 0 {
      // §6.1 Indexed Header Field.
      let (index, consumed) = read_integer(block, off, 7)
      off = off + consumed
      if index == 0 {
        raise Malformed("indexed header field with index 0")
      }
      match lookup(self.table, index) {
        Some(header) => out.push(header)
        None => raise Index(got=index)
      }
    } else if (b & 0x40) != 0 {
      // §6.2.1 Literal Header Field with Incremental Indexing.
      let (index, consumed) = read_integer(block, off, 6)
      off = off + consumed
      let (name, name_consumed) = self.read_name(block, index, off)
      off = off + name_consumed
      let (value, value_consumed) = read_string(block, off)
      off = off + value_consumed
      self.table.add(name, value)
      out.push({ name, value, })
    } else if (b & 0x20) != 0 {
      // §6.3 Dynamic Table Size Update.
      let (limit, consumed) = read_integer(block, off, 5)
      off = off + consumed
      if limit > self.limit {
        raise Exceeded(limit=self.limit, got=limit)
      }
      self.table.resize(limit)
    } else {
      // §6.2.2 without indexing (0x00) / §6.2.3 never indexed (0x10); 4-bit prefix.
      let (index, consumed) = read_integer(block, off, 4)
      off = off + consumed
      let (name, name_consumed) = self.read_name(block, index, off)
      off = off + name_consumed
      let (value, value_consumed) = read_string(block, off)
      off = off + value_consumed
      out.push({ name, value, })
    }
  }
  out
}

// -- encoder (RFC 7541 §6) --------------------------------------------------

///|
/// A stateful HPACK encoder: it owns a dynamic table mirroring the decoder's, and
/// prefers indexed representations. `huffman` selects Huffman string literals when
/// they are shorter.
pub(all) struct Encoder {
  table : Table
  mut huffman : Bool
}

///|
/// A new encoder bounded by `limit` octets; `huffman` (default `true`) enables
/// the shorter-of-two string-literal heuristic.
pub fn Encoder::new(limit? : Int = limit, huffman? : Bool = true) -> Encoder {
  { table: Table::new(limit~), huffman, }
}

///|
/// Find the best index for `(name, value)`: an exact `(idx, true)` match, else a
/// name-only `(idx, false)` match, else `(0, false)` for no match at all.
fn Encoder::find(self : Encoder, name : Bytes, value : Bytes) -> (Int, Bool) {
  let fixed = static_table.length()
  let mut name_idx = 0
  for i = 0; i < fixed; i = i + 1 {
    let e = static_table[i]
    let n = e.name
    let v = e.value
    if n == name {
      if v == value {
        return (i + 1, true)
      }
      if name_idx == 0 {
        name_idx = i + 1
      }
    }
  }
  for d = 0; d < self.table.entries.length(); d = d + 1 {
    let (n, v) = self.table.entries[d]
    if n == name {
      let idx = fixed + 1 + d
      if v == value {
        return (idx, true)
      }
      if name_idx == 0 {
        name_idx = idx
      }
    }
  }
  (name_idx, false)
}

///|
fn Encoder::literal(self : Encoder, octets : Bytes) -> Bytes {
  string(octets[:], huffman=self.huffman)
}

///|
/// Write an integer with a flag OR'd into the high bits of its first octet.
fn prefixed(buf : Buffer, value : Int, prefix : Int, flag : Int) -> Unit {
  let e = integer(value, prefix)
  buf.write_byte((e[0].to_int() | flag).to_byte())
  buf.write_bytes(e[1:].to_owned())
}

///|
/// Encode a header list into a header block (RFC 7541 §6), using indexed fields
/// where possible and literal-with-incremental-indexing otherwise (mutating the
/// dynamic table to mirror what the peer decoder will build). The output decodes
/// back to the same header list via `Decoder`.
pub fn Encoder::encode(self : Encoder, headers : ArrayView[Header]) -> Bytes {
  let buf = Buffer()
  for h in headers {
    let (idx, exact) = self.find(h.name, h.value)
    if exact {
      prefixed(buf, idx, 7, 0x80)
    } else {
      if idx != 0 {
        prefixed(buf, idx, 6, 0x40)
      } else {
        buf.write_byte(b'\x40')
        buf.write_bytes(self.literal(h.name))
      }
      buf.write_bytes(self.literal(h.value))
      self.table.add(h.name, h.value)
    }
  }
  buf.to_bytes()
}

///|
pub extend Header with Debug::{to_repr}

///|
pub extend Header with Eq::{not_equal, equal}
