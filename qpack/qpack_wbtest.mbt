// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9204, section by section: the integer codec of §4.1.1, the static table of
// Appendix A, the field section prefix of §4.5.1, the dynamic table of §3.2, the
// field line representations of §4.5, and the instructions of §4.3 and §4.4. The
// instruction vectors are the ones Appendix B prints.

///|
test "qpack int: a value still arriving is None, a value too large is a fault" {
  // The arithmetic is `moonvar`'s and tested there. What is this package's is the
  // reading of a refusal on a stream: 0x1f says the prefix overflowed and 0x9a has its
  // continuation bit set, so another octet is owed and may yet come.
  assert_eq(partial(b""[:], 5), None)
  assert_eq(partial(b""[:], 5), None)
  // Whereas a complete value is a value, flags above the prefix and all.
  assert_eq(partial(b""[:], 6), Some((2, 1)))
  // And one that no `Int` could hold will not improve by waiting, so it is malformed.
  let mut refused = false
  try {
    let _ = partial(b"ÿÿÿÿÿÿÿÿ"[:], 5)
  } catch {
    Malformed(_) => refused = true
    _ => ()
  }
  assert_eq(refused, true)
}

///|
test "qpack static: the table has exactly 99 entries" {
  assert_eq(static_table.length(), 99)
}

///|
test "qpack static: spot-checked entries match RFC 9204 Appendix A" {
  assert_eq(entry(0), Some(@header.Header::of(":authority", "")))
  assert_eq(entry(1), Some(@header.Header::of(":path", "/")))
  assert_eq(entry(17), Some(@header.Header::of(":method", "GET")))
  assert_eq(entry(25), Some(@header.Header::of(":status", "200")))
  assert_eq(
    entry(31),
    Some(@header.Header::of("accept-encoding", "gzip, deflate, br")),
  )
  assert_eq(
    entry(46),
    Some(@header.Header::of("content-type", "application/json")),
  )
  assert_eq(
    entry(98),
    Some(@header.Header::of("x-frame-options", "sameorigin")),
  )
  // Out of range.
  assert_eq(entry(99), None)
  assert_eq(entry(-1), None)
}

///|
test "qpack static: exact (name, value) lookup returns the RFC index" {
  assert_eq(find(b":method", b"GET"), Some(17))
  assert_eq(find(b":status", b"404"), Some(27))
  assert_eq(find(b"content-type", b"text/plain"), Some(53))
  // A name that exists but not with this value.
  assert_eq(find(b":status", b"418"), None)
  // A name absent from the table.
  assert_eq(find(b"x-custom", b"v"), None)
}

///|
test "qpack static: name-only lookup returns the first matching index" {
  // :method first appears at index 15 (CONNECT).
  assert_eq(find_name(b":method"), Some(15))
  // :status first appears at index 24 (103).
  assert_eq(find_name(b":status"), Some(24))
  assert_eq(find_name(b"cookie"), Some(5))
  assert_eq(find_name(b"x-custom"), None)
}

///|
/// Encode a prefix and decode it back, given the decoder's total inserts (defaulting to the
/// Required Insert Count, the usual case).
fn roundtrip_prefix(
  req : Int,
  base : Int,
  max_entries : Int,
  total? : Int = -1,
) -> (Int, Int) raise {
  let total = if total == -1 { req } else { total }
  let wire = prefix(req, base, max_entries)
  match read_prefix(wire[:], max_entries, total) {
    Some((r, b, consumed)) => {
      assert_eq(consumed, wire.length())
      (r, b)
    }
    None => abort("truncated section prefix")
  }
}

///|
test "section prefix: the zero Required Insert Count encodes to two zero bytes" {
  let wire = prefix(0, 0, 128)
  assert_eq(@base16.encode(wire), "0000")
  assert_eq(roundtrip_prefix(0, 0, 128), (0, 0))
}

///|
test "section prefix: Base sign — S=0 when Base >= RIC, S=1 otherwise" {
  // Base above the Required Insert Count: S = 0, delta = Base - RIC.
  let above = prefix(4, 6, 128)
  assert_eq((above[1].to_int() & 0x80) == 0, true) // sign bit clear
  assert_eq(roundtrip_prefix(4, 6, 128), (4, 6))
  // Base below the Required Insert Count: S = 1, delta = RIC - Base - 1.
  let below = prefix(9, 6, 128)
  assert_eq((below[1].to_int() & 0x80) != 0, true) // sign bit set
  assert_eq(roundtrip_prefix(9, 6, 128), (9, 6))
}

///|
test "section prefix: round-trips across ranges, including dynamic-table wraparound" {
  let max_entries = 128 // a 4096-byte table
  // RIC below, at, and well past 2*MaxEntries (=256) so the reconstruction has to unwrap.
  for req in [1, 5, 128, 200, 256, 300, 511] {
    for base in [0, 1, req / 2, req] {
      assert_eq(roundtrip_prefix(req, base, max_entries), (req, base))
    }
  }
}

///|
test "section prefix: reconstructs when the decoder is ahead by up to MaxEntries" {
  // The decoder may have processed up to MaxEntries inserts beyond the section's Required
  // Insert Count; the modular value must still resolve to the exact count the encoder
  // meant. Past that window the reference would be to an evicted entry, so it is out of
  // scope here.
  let me = 128
  assert_eq(roundtrip_prefix(300, 290, me, total=300 + me - 1), (300, 290))
  assert_eq(roundtrip_prefix(9, 0, me, total=9 + me - 1), (9, 0))
}

///|
test "dynamic table: insert, size accounting, eviction, and indexing" {
  let t = Table::new(100)
  assert_eq(t.insert(b"a", b"1"), true) // 1+1+32 = 34
  assert_eq(t.insert(b"bb", b"22"), true) // 2+2+32 = 36, total 70
  // The third entry (3+3+32 = 38) does not fit; the oldest is evicted first.
  assert_eq(t.insert(b"ccc", b"333"), true)
  assert_eq(t.used, 74) // 36 (bb) + 38 (ccc)
  assert_eq(t.insert_count, 3)
  assert_eq(t.dropped, 1)
  assert_eq(t.get(0), None) // evicted
  assert_eq(t.get(1), Some((b"bb", b"22")))
  assert_eq(t.get(2), Some((b"ccc", b"333")))
  // Relative index 0 is the most recently inserted entry (RFC 9204 §3.2.5).
  assert_eq(t.relative(0), Some((b"ccc", b"333")))
  assert_eq(t.relative(1), Some((b"bb", b"22")))
}

///|
test "dynamic table: shrinking the capacity evicts what no longer fits" {
  let t = Table::new(200)
  let _ = t.insert(b"a", b"1") // 34
  let _ = t.insert(b"b", b"2") // 34, total 68
  let _ = t.insert(b"c", b"3") // 34, total 102
  assert_eq(t.used, 102)
  t.resize(40) // room for one 34-byte entry
  assert_eq(t.used, 34)
  assert_eq(t.dropped, 2)
  assert_eq(t.get(2), Some((b"c", b"3")))
}

///|
test "dynamic table: an entry larger than the capacity is not inserted" {
  let t = Table::new(40)
  assert_eq(t.insert(b"x", b"y"), true) // 34
  // 10+10+32 = 52 > 40: evicts everything, still cannot fit, inserts nothing.
  assert_eq(t.insert(b"aaaaaaaaaa", b"bbbbbbbbbb"), false)
  assert_eq(t.used, 0)
  assert_eq(t.entries.length(), 0)
  assert_eq(t.insert_count, 1) // only the successful insert counted
}

///|
test "dynamic table: apply encoder instructions (static/dynamic/duplicate names)" {
  let t = Table::new(4096)
  let _ = t.apply(SetCapacity(220))
  assert_eq(t.capacity, 220)
  // Insert With Name Reference into the static table (index 0 = ":authority").
  let _ = t.apply(Insert(is_static=true, index=0, value=b"www.example.com"))
  assert_eq(t.get(0), Some((b":authority", b"www.example.com")))
  let _ = t.apply(InsertLiteral(name=b"custom-key", value=b"custom-value"))
  // Duplicate the most recent entry (relative index 0).
  let _ = t.apply(Duplicate(index=0))
  assert_eq(t.get(2), Some((b"custom-key", b"custom-value")))
  // Insert With Name Reference into the dynamic table (relative index 0 = the duplicate).
  let _ = t.apply(Insert(is_static=false, index=0, value=b"v2"))
  assert_eq(t.get(3), Some((b"custom-key", b"v2")))
  assert_eq(t.insert_count, 4)
}

///|
test "dynamic table: encode -> decode -> apply reproduces the table" {
  let insts : Array[Change] = [
    SetCapacity(500),
    Insert(is_static=true, index=0, value=b"a.example"),
    InsertLiteral(name=b"k", value=b"v"),
    Duplicate(index=0),
  ]
  // Serialize the whole encoder-stream and parse it back instruction by instruction.
  let wire = Buffer()
  for inst in insts {
    wire.write_bytes(Change::encode(inst, huffman=false))
  }
  let bytes = wire.to_bytes()
  let decoded : Array[Change] = []
  let view = bytes[:]
  let mut off = 0
  while off < bytes.length() {
    match Change::decode(view[off:]) {
      Some((inst, consumed)) => {
        decoded.push(inst)
        off = off + consumed
      }
      None => abort("truncated encoder-stream")
    }
  }
  assert_eq(decoded, insts)
  let t = Table::new(4096)
  for inst in decoded {
    let _ = t.apply(inst)
  }
  assert_eq(t.insert_count, 3) // SetCapacity is not an insert
  assert_eq(t.get(0), Some((b":authority", b"a.example")))
  assert_eq(t.get(1), Some((b"k", b"v")))
  assert_eq(t.get(2), Some((b"k", b"v"))) // the duplicate
}

///|
test "qpack field: an exact static match encodes as an indexed field line" {
  // Prefix (insert count 0, base 0) = 00 00; :method GET is static index 17, so the
  // indexed field line is 0xC0 | 17 = 0xD1.
  assert_eq(
    encode([@header.Header::of(":method", "GET")], huffman=false),
    b"\x00\x00\xd1",
  )
}

///|
test "qpack field: round-trip through all three representations (raw)" {
  let headers = [
    @header.Header::of(":method", "GET"), // indexed static
    @header.Header::of(":path", "/index.html"), // static name (:path), literal value
    @header.Header::of(":scheme", "https"), // indexed static
    @header.Header::of(":status", "200"), // indexed static
    @header.Header::of("x-custom-header", "custom-value"), // literal name and value
    @header.Header::of("content-type", "application/json"), // indexed static
  ]
  let encoded = encode(headers, huffman=false)
  assert_eq(decode(encoded), headers)
}

///|
test "qpack field: round-trip Huffman-coded" {
  let headers = [
    @header.Header::of(":authority", "www.example.com"),
    @header.Header::of("user-agent", "Mozilla/5.0 (compatible)"),
    @header.Header::of("accept", "text/html,application/xhtml+xml"),
  ]
  let encoded = encode(headers, huffman=true)
  // A Huffman-coded body is strictly smaller than the raw one for these values.
  let raw = encode(headers, huffman=false)
  assert_eq(encoded.length() < raw.length(), true)
  assert_eq(decode(encoded), headers)
}

///|
test "qpack field: a static name reference with a novel value round-trips" {
  // :status is a static name (index 24) but 599 is not a static value.
  let headers = [@header.Header::of(":status", "599")]
  assert_eq(decode(encode(headers, huffman=false)), headers)
  assert_eq(decode(encode(headers, huffman=true)), headers)
}

///|
test "qpack field: an empty field section is just the prefix" {
  let encoded = encode([], huffman=false)
  assert_eq(encoded, b"\x00\x00")
  assert_eq(decode(encoded), [])
}

///|
test "qpack field: string literal H bit selects Huffman on decode" {
  // Encode one value both ways; the raw one keeps its bytes, the Huffman one is decoded
  // back through the shared RFC 7541 table.
  let raw = string(b"hello", 7, 0, false)
  let huff = string(b"hello", 7, 0, true)
  match read_string(raw[:], 7) {
    Some((data, _)) => assert_eq(data, b"hello")
    None => abort("expected a complete string")
  }
  match read_string(huff[:], 7) {
    Some((data, _)) => assert_eq(data, b"hello")
    None => abort("expected a complete string")
  }
}

///|
test "qpack field: a dynamic-table reference is rejected" {
  // 0x80 with T=0 (bit 6 clear) is an indexed field line into the dynamic table.
  let rejected = try {
    let _ = decode(b"\x00\x00\x80")
    false
  } catch {
    _ => true
  }
  assert_eq(rejected, true)
}

///|
/// A dynamic table holding two entries: absolute index 0 = (":authority",
/// "www.example.com"), absolute index 1 = @header.Header::of("custom-key", "custom-value").
fn dyn_table_two() -> Table {
  let t = Table::new(4096)
  let _ = t.insert(b":authority", b"www.example.com")
  let _ = t.insert(b"custom-key", b"custom-value")
  t
}

///|
/// Assemble a field section from a prefix and a run of field-line byte fragments.
fn field_section(prefix : Bytes, lines : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(prefix)
  for line in lines {
    buf.write_bytes(line)
  }
  buf.to_bytes()
}

///|
test "dynamic field: indexed lines by relative index (Base above the entries)" {
  let t = dyn_table_two()
  // Required Insert Count 2, Base 2: relative index 0 -> absolute 1, relative 1 -> 0.
  let prefix = prefix(2, 2, 128)
  let wire = field_section(prefix, [
    @prefix.encode(0, prefix=6, flags=0x80), // Indexed, T=0 (dynamic), relative 0
    @prefix.encode(1, prefix=6, flags=0x80), // Indexed, T=0 (dynamic), relative 1
  ])
  assert_eq(decode_with(wire, t, 128), [
    @header.Header::of("custom-key", "custom-value"),
    @header.Header::of(":authority", "www.example.com"),
  ])
}

///|
test "dynamic field: indexed lines by post-base index (Base below the entries)" {
  let t = dyn_table_two()
  // Base 0: post-base index 0 -> absolute 0, post-base index 1 -> absolute 1.
  let prefix = prefix(2, 0, 128)
  let wire = field_section(prefix, [
    @prefix.encode(0, prefix=4, flags=0x10), // Indexed With Post-Base Index 0
    @prefix.encode(1, prefix=4, flags=0x10), // Indexed With Post-Base Index 1
  ])
  assert_eq(decode_with(wire, t, 128), [
    @header.Header::of(":authority", "www.example.com"),
    @header.Header::of("custom-key", "custom-value"),
  ])
}

///|
test "dynamic field: literal with a dynamic name reference" {
  let t = dyn_table_two()
  let prefix = prefix(2, 2, 128)
  // Literal With Name Reference, T=0, relative index 1 -> name at absolute 0 (":authority").
  let name_ref = @prefix.encode(1, prefix=4, flags=0x40)
  let value = string(b"example.org", 7, 0, false)
  let wire = field_section(prefix, [name_ref, value])
  assert_eq(decode_with(wire, t, 128), [
    @header.Header::of(":authority", "example.org"),
  ])
}

///|
test "dynamic field: literal with a post-base name reference" {
  let t = dyn_table_two()
  let prefix = prefix(2, 0, 128)
  // Post-Base Name Reference, post-base index 0 -> name at absolute 0 (":authority").
  let name_ref = @prefix.encode(0, prefix=3, flags=0x00)
  let value = string(b"v", 7, 0, false)
  let wire = field_section(prefix, [name_ref, value])
  assert_eq(decode_with(wire, t, 128), [@header.Header::of(":authority", "v")])
}

///|
test "dynamic field: static and dynamic references mixed in one section" {
  let t = dyn_table_two()
  let prefix = prefix(2, 2, 128)
  let wire = field_section(prefix, [
    @prefix.encode(1, prefix=6, flags=0xc0), // Indexed static, index 1 = @header.Header::of(":path", "/")
    @prefix.encode(0, prefix=6, flags=0x80), // Indexed dynamic, relative 0 = ("custom-key", ...)
  ])
  assert_eq(decode_with(wire, t, 128), [
    @header.Header::of(":path", "/"),
    @header.Header::of("custom-key", "custom-value"),
  ])
}

///|
/// Apply a whole encoder-stream instruction block to `table`.
fn apply_encoder_stream(
  table : Table,
  instructions : Bytes,
) -> Unit raise Refused {
  let view = instructions[:]
  let mut off = 0
  while off < instructions.length() {
    match Change::decode(view[off:]) {
      Some((inst, consumed)) => {
        let _ = table.apply(inst)
        off = off + consumed
      }
      None => abort("truncated encoder stream")
    }
  }
}

///|
test "dynamic encode: round-trips through the dynamic decoder (raw and Huffman)" {
  let headers = [
    @header.Header::of(":authority", "www.example.com"),
    @header.Header::of("custom-key", "custom-value"),
    @header.Header::of(":path", "/"),
    @header.Header::of("x-foo", "bar"),
  ]
  for huff in [false, true] {
    let enc_table = Table::new(4096)
    let (instructions, section) = encode_with(
      headers,
      enc_table,
      128,
      huffman=huff,
    )
    // The three non-static-exact headers were indexed into the dynamic table; ":path: /"
    // matched the static table and was not.
    assert_eq(enc_table.insert_count, 3)
    let dec_table = Table::new(4096)
    apply_encoder_stream(dec_table, instructions)
    assert_eq(decode_with(section, dec_table, 128), headers)
  }
}

///|
test "dynamic encode: an entry too large for the table falls back to a literal line" {
  let headers = [@header.Header::of("x-long-name", "a fairly long value here")]
  let enc = Table::new(40) // 11 + 24 + 32 = 67 > 40, cannot index
  let (instructions, section) = encode_with(headers, enc, 1, huffman=false)
  assert_eq(enc.insert_count, 0)
  assert_eq(instructions.length(), 0)
  let dec = Table::new(40)
  assert_eq(decode_with(section, dec, 1), headers)
}

///|
test "QPACK encoder instructions: RFC 9204 Appendix B vectors" {
  // Set Dynamic Table Capacity = 220 (Appendix B.1).
  assert_eq(@base16.encode(Change::encode(SetCapacity(220))), "3fbd01")
  // Insert With Name Reference, static index 0 (:authority), "www.example.com" (B.1).
  assert_eq(
    @base16.encode(
      Change::encode(
        Insert(is_static=true, index=0, value=b"www.example.com"),
        huffman=false,
      ),
    ),
    "c00f7777772e6578616d706c652e636f6d",
  )
  // Insert With Literal Name "custom-key": "custom-value" (Appendix B.3).
  assert_eq(
    @base16.encode(
      Change::encode(
        InsertLiteral(name=b"custom-key", value=b"custom-value"),
        huffman=false,
      ),
    ),
    "4a637573746f6d2d6b65790c637573746f6d2d76616c7565",
  )
  // Duplicate index 0 (Appendix B.3).
  assert_eq(@base16.encode(Change::encode(Duplicate(index=0))), "00")
}

///|
test "QPACK encoder instructions: round-trip, raw and Huffman" {
  let insts : Array[Change] = [
    SetCapacity(4096),
    Insert(is_static=true, index=15, value=b"application/json"),
    Insert(is_static=false, index=2, value=b"dyn-value"),
    InsertLiteral(name=b"x-custom-header", value=b"a somewhat longer value"),
    Duplicate(index=31),
  ]
  for huff in [false, true] {
    for inst in insts {
      let wire = Change::encode(inst, huffman=huff)
      match Change::decode(wire[:]) {
        Some((got, consumed)) => {
          assert_eq(got, inst)
          assert_eq(consumed, wire.length())
        }
        None => abort("encoder instruction did not fully decode")
      }
    }
  }
}

///|
test "QPACK decoder instructions: vectors and round-trip" {
  // Section Acknowledgement stream 4; Stream Cancellation stream 4; Insert Count
  // Increment 1 (RFC 9204 §4.4).
  assert_eq(@base16.encode(Ack::encode(Section(stream_id=4))), "84")
  assert_eq(@base16.encode(Ack::encode(Cancel(stream_id=4))), "44")
  assert_eq(@base16.encode(Ack::encode(Increment(increment=1))), "01")
  let dinsts : Array[Ack] = [
    Section(stream_id=1000),
    Cancel(stream_id=42),
    Increment(increment=300),
  ]
  for d in dinsts {
    let wire = Ack::encode(d)
    match Ack::decode(wire[:]) {
      Some((got, consumed)) => {
        assert_eq(got, d)
        assert_eq(consumed, wire.length())
      }
      None => abort("decoder instruction did not fully decode")
    }
  }
}

///|
test "QPACK encoder instruction: a partial value string decodes as None" {
  // A valid Insert With Name Reference header byte and length, but the value octets have
  // not all arrived yet.
  let full = Change::encode(
    Insert(is_static=true, index=0, value=b"www.example.com"),
    huffman=false,
  )
  assert_eq(Change::decode(full[0:4]), None)
}
