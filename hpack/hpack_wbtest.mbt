// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Every block below is one RFC 7541 Appendix C prints, lifted from the RFC's own text
// rather than typed out. The three requests of a series share one dynamic table, which
// is what makes them a test of the table and not only of the codec.
// https://www.rfc-editor.org/rfc/rfc7541#appendix-C

///|
/// A hex string as bytes, and back.
fn hexb(h : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < h.length(); i = i + 2 {
    buf.write_byte(
      ((nib(h[i].to_int()) << 4) | nib(h[i + 1].to_int())).to_byte(),
    )
  }
  buf.to_bytes()
}

///|
fn nib(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    0
  }
}

///|
fn hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}

///|
/// A header list from ASCII pairs, which is how the appendix writes them.
fn list(pairs : ArrayView[(String, String)]) -> Array[Header] {
  let out : Array[Header] = []
  for p in pairs {
    out.push({ name: ascii(p.0), value: ascii(p.1), })
  }
  out
}

///|
fn ascii(s : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < s.length(); i = i + 1 {
    buf.write_byte((s[i].to_int() & 0xff).to_byte())
  }
  buf.to_bytes()
}

///|
test "the three requests of RFC 7541 C.3, without Huffman" {
  // One table across all three: the second request indexes what the first added.
  let decoder = Decoder::new()
  let encoder = Encoder::new(huffman=false)

  // C.3.1
  let want = list(
    [
      (":method", "GET"),
      (":scheme", "http"),
      (":path", "/"),
      (":authority", "www.example.com"),
    ][:],
  )
  let block = hexb("828684410f7777772e6578616d706c652e636f6d")
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(
    hex(encoder.encode(want[:])),
    "828684410f7777772e6578616d706c652e636f6d",
  )

  // C.3.2
  let want = list(
    [
      (":method", "GET"),
      (":scheme", "http"),
      (":path", "/"),
      (":authority", "www.example.com"),
      ("cache-control", "no-cache"),
    ][:],
  )
  let block = hexb("828684be58086e6f2d6361636865")
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(hex(encoder.encode(want[:])), "828684be58086e6f2d6361636865")

  // C.3.3
  let want = list(
    [
      (":method", "GET"),
      (":scheme", "https"),
      (":path", "/index.html"),
      (":authority", "www.example.com"),
      ("custom-key", "custom-value"),
    ][:],
  )
  let block = hexb("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565")
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(
    hex(encoder.encode(want[:])),
    "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
  )
}

///|
test "the three requests of RFC 7541 C.4, with Huffman" {
  // The same three, with the string literals Huffman-coded.
  let decoder = Decoder::new()
  let encoder = Encoder::new(huffman=true)

  // C.4.1
  let want = list(
    [
      (":method", "GET"),
      (":scheme", "http"),
      (":path", "/"),
      (":authority", "www.example.com"),
    ][:],
  )
  let block = hexb("828684418cf1e3c2e5f23a6ba0ab90f4ff")
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(hex(encoder.encode(want[:])), "828684418cf1e3c2e5f23a6ba0ab90f4ff")

  // C.4.2
  let want = list(
    [
      (":method", "GET"),
      (":scheme", "http"),
      (":path", "/"),
      (":authority", "www.example.com"),
      ("cache-control", "no-cache"),
    ][:],
  )
  let block = hexb("828684be5886a8eb10649cbf")
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(hex(encoder.encode(want[:])), "828684be5886a8eb10649cbf")

  // C.4.3
  let want = list(
    [
      (":method", "GET"),
      (":scheme", "https"),
      (":path", "/index.html"),
      (":authority", "www.example.com"),
      ("custom-key", "custom-value"),
    ][:],
  )
  let block = hexb("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(
    hex(encoder.encode(want[:])),
    "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
  )
}

///|
test "the three responses of RFC 7541 C.5, evicting as they go" {
  // A table of 256 octets, which the third response overruns — the appendix's point.
  let decoder = Decoder::new(limit=256)
  let encoder = Encoder::new(huffman=false, limit=256)

  // C.5.1
  let want = list(
    [
      (":status", "302"),
      ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
      ("location", "https://www.example.com"),
    ][:],
  )
  let block = hexb(
    "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
  )
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(
    hex(encoder.encode(want[:])),
    "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
  )

  // C.5.2
  let want = list(
    [
      (":status", "307"),
      ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
      ("location", "https://www.example.com"),
    ][:],
  )
  let block = hexb("4803333037c1c0bf")
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(hex(encoder.encode(want[:])), "4803333037c1c0bf")

  // C.5.3
  let want = list(
    [
      (":status", "200"),
      ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
      ("location", "https://www.example.com"),
      ("content-encoding", "gzip"),
      ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
    ][:],
  )
  let block = hexb(
    "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
  )
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(
    hex(encoder.encode(want[:])),
    "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
  )
}

///|
test "the three responses of RFC 7541 C.6, with Huffman and eviction" {
  // The same three under Huffman, where the shorter strings change what fits.
  let decoder = Decoder::new(limit=256)
  let encoder = Encoder::new(huffman=true, limit=256)

  // C.6.1
  let want = list(
    [
      (":status", "302"),
      ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
      ("location", "https://www.example.com"),
    ][:],
  )
  let block = hexb(
    "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
  )
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(
    hex(encoder.encode(want[:])),
    "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
  )

  // C.6.2
  let want = list(
    [
      (":status", "307"),
      ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
      ("location", "https://www.example.com"),
    ][:],
  )
  let block = hexb("4883640effc1c0bf")
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(hex(encoder.encode(want[:])), "4883640effc1c0bf")

  // C.6.3
  let want = list(
    [
      (":status", "200"),
      ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
      ("location", "https://www.example.com"),
      ("content-encoding", "gzip"),
      ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
    ][:],
  )
  let block = hexb(
    "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
  )
  assert_eq(decoder.decode(block[:]), want)
  assert_eq(
    hex(encoder.encode(want[:])),
    "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
  )
}

///|
test "the three integers RFC 7541 C.1 works out" {
  // C.1.1: ten fits the five-bit prefix.
  assert_eq(hex(integer(10, 5)), "0a")
  // C.1.2: 1337 does not, so the prefix is all ones and the rest continues.
  assert_eq(hex(integer(1337, 5)), "1f9a0a")
  // C.1.3: forty-two at an octet boundary, which is an eight-bit prefix.
  assert_eq(hex(integer(42, 8)), "2a")
  // And each reads back, ignoring whatever flag bits sit above the prefix.
  assert_eq(read_integer(hexb("ea")[:], 0, 5), (10, 1))
  assert_eq(read_integer(hexb("ff9a0a")[:], 0, 5), (1337, 3))
  assert_eq(read_integer(hexb("2a")[:], 0, 8), (42, 1))
}

///|
test "an integer that runs off the end, or past what an Int holds, is refused" {
  // The prefix says the value continues but nothing follows.
  assert_eq(refused_integer(hexb("1f")), true)
  assert_eq(refused_integer(hexb("1f80")), true)
  // Ten continuation octets is more than a thirty-one bit value can need.
  assert_eq(refused_integer(hexb("1fffffffffffffffffff7f")), true)
  // An empty buffer has no prefix at all.
  assert_eq(refused_integer(b""), true)
}

///|
fn refused_integer(b : Bytes) -> Bool {
  let mut out = false
  try {
    let _ = read_integer(b[:], 0, 5)
  } catch {
    Malformed(_) => out = true
    _ => ()
  }
  out
}

///|
test "a string literal reads back, Huffman-coded or not" {
  let plain = string(b"www.example.com"[:], huffman=false)
  assert_eq(hex(plain), "0f7777772e6578616d706c652e636f6d")
  assert_eq(is_huffman(plain[:], 0), false)
  let coded = string(b"www.example.com"[:])
  assert_eq(hex(coded), "8cf1e3c2e5f23a6ba0ab90f4ff")
  assert_eq(is_huffman(coded[:], 0), true)
  // Both read back to the same octets, the coded one through the Huffman decoder.
  assert_eq(read_string(plain[:], 0), (b"www.example.com", plain.length()))
  assert_eq(read_string(coded[:], 0), (b"www.example.com", coded.length()))
}

///|
test "a literal claiming more than the block holds is refused" {
  // Length fifteen with three octets behind it.
  let mut refused = false
  try {
    let _ = read_string(hexb("0f414243")[:], 0)
  } catch {
    Malformed(_) => refused = true
    _ => ()
  }
  assert_eq(refused, true)
}

///|
test "an index naming nothing is refused, and index zero is never a field" {
  let decoder = Decoder::new()
  // §6.1: an indexed header field with index 0 is a decoding error.
  assert_eq(refused_block(decoder, hexb("80")) is Malformed(_), true)
  // Sixty-two with an empty dynamic table is one past the static table.
  assert_eq(refused_block(Decoder::new(), hexb("be")), Index(got=62))
}

///|
fn refused_block(decoder : Decoder, block : Bytes) -> Refused {
  let mut out : Refused? = None
  try {
    let _ = decoder.decode(block[:])
  } catch {
    e => out = Some(e)
  }
  match out {
    Some(e) => e
    None => abort("this block should have been refused")
  }
}

///|
test "a size update past what the peer allowed is refused (§6.3)" {
  let decoder = Decoder::new(limit=256)
  // §6.3 writes the new maximum with a 001 prefix; 256 is exactly the cap.
  assert_eq(hex(size_update(256)), "3fe101")
  decoder.decode(size_update(256)[:]) |> ignore
  // One more than the cap is a decoding error.
  assert_eq(
    refused_block(decoder, size_update(257)),
    Exceeded(limit=256, got=257),
  )
}

///|
test "the dynamic table evicts oldest first, and an entry too big empties it (§4.4)" {
  let table = Table::new(limit=100)
  assert_eq(table.count(), 0)
  assert_eq(table.size(), 0)
  // Each entry costs its name and value plus thirty-two octets (§4.1).
  table.add(b"aaaa", b"bbbb")
  assert_eq(table.size(), 40)
  table.add(b"cccc", b"dddd")
  assert_eq(table.count(), 2)
  assert_eq(table.size(), 80)
  // The third pushes the oldest out.
  table.add(b"eeee", b"ffff")
  assert_eq(table.count(), 2)
  assert_eq(table.size(), 80)
  assert_eq(table.get(62), Some({ name: b"eeee", value: b"ffff", }))
  assert_eq(table.get(63), Some({ name: b"cccc", value: b"dddd", }))
  assert_eq(table.get(64), None)
  // An entry larger than the whole table leaves it empty rather than half full.
  table.add(Bytes::make(200, b'x'), b"")
  assert_eq(table.count(), 0)
  assert_eq(table.size(), 0)
}

///|
test "the static table is RFC 7541 Appendix A's, by its own indices" {
  assert_eq(static_table.length(), 61)
  assert_eq(entry(1), Some({ name: b":authority", value: b"", }))
  assert_eq(entry(2), Some({ name: b":method", value: b"GET", }))
  assert_eq(entry(8), Some({ name: b":status", value: b"200", }))
  assert_eq(entry(61), Some({ name: b"www-authenticate", value: b"", }))
  // Zero is not an index, and sixty-two belongs to the dynamic table.
  assert_eq(entry(0), None)
  assert_eq(entry(62), None)
}

///|
test "the table limit is a knob with a public preset" {
  assert_eq(limit, 4096)
  assert_eq(Table::new().limit(), 4096)
  assert_eq(Table::new(limit=512).limit(), 512)
  // Resizing evicts to fit, which is what a size update does (§4.2).
  let table = Table::new(limit=100)
  table.add(b"aaaa", b"bbbb")
  table.add(b"cccc", b"dddd")
  assert_eq(table.count(), 2)
  table.resize(40)
  assert_eq(table.count(), 1)
  assert_eq(table.limit(), 40)
}
