// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The coded strings below are the ones RFC 7541 Appendix C.4 and C.6 print inside their
// header blocks, so the table and the padding are checked against what the working group
// published rather than against a round trip of our own.
// https://www.rfc-editor.org/rfc/rfc7541#appendix-C.4

///|
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
test "the strings RFC 7541 Appendix C codes, both ways" {
  let cases = [
    ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
    ("no-cache", "a8eb10649cbf"),
    ("custom-key", "25a849e95ba97d7f"),
    ("custom-value", "25a849e95bb8e8b4bf"),
    ("private", "aec3771a4b"),
    (
      "Mon, 21 Oct 2013 20:13:21 GMT", "d07abe941054d444a8200595040b8166e082a62d1bff",
    ),
    ("https://www.example.com", "9d29ad171863c78f0b97c8e9ae82ae43d3"),
    ("gzip", "9bd9ab"),
  ]
  for one in cases {
    let (plain, coded) = one
    assert_eq(hex(encode(ascii(plain)[:])), coded)
    assert_eq(decode(hexb(coded)[:]), ascii(plain))
    // The length is answered without building the output, because an encoder asks it
    // to decide whether coding is worth it at all.
    assert_eq(size(ascii(plain)[:]), coded.length() / 2)
  }
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
test "every octet round-trips, one at a time and all at once" {
  let all = Buffer()
  for i = 0; i < 256; i = i + 1 {
    all.write_byte(i.to_byte())
    let one = Bytes::make(1, i.to_byte())
    assert_eq(decode(encode(one[:])[:]), one)
  }
  let whole = all.to_bytes()
  assert_eq(decode(encode(whole[:])[:]), whole)
  // The empty string codes to nothing and reads back as nothing.
  assert_eq(encode(b""[:]), b"")
  assert_eq(decode(b""[:]), b"")
}

///|
test "the end-of-string symbol must not appear in the input (§5.2)" {
  // EOS is thirty ones, so four octets of ones carry it and then some.
  let mut refused = false
  try {
    let _ = decode(hexb("ffffffff")[:])
  } catch {
    Eos => refused = true
    _ => ()
  }
  assert_eq(refused, true)
}

///|
test "padding must be a short run of ones (§5.2)" {
  // Eight bits of padding is one bit too many: the octet should not be there at all.
  let mut long = false
  try {
    let _ = decode(hexb("f1e3c2e5f23a6ba0ab90f4ffff")[:])
  } catch {
    Padding(_) => long = true
    Eos => long = true
    _ => ()
  }
  assert_eq(long, true)

  // Padding that is not ones: "a" codes to five bits, so three pad bits follow.
  let good = encode(b"a"[:])
  assert_eq(decode(good[:]), b"a")
  let bad = Bytes::make(1, (good[0].to_int() & 0xf8).to_byte())
  let mut zeros = false
  try {
    let _ = decode(bad[:])
  } catch {
    Padding(_) => zeros = true
    _ => ()
  }
  assert_eq(zeros, true)
}

///|
test "a refusal says which of the three it was" {
  assert_eq(Eos.to_string(), "Eos")
  assert_eq(Padding("x").to_string(), "Padding(x)")
  assert_eq(Malformed("y").to_string(), "Malformed(y)")
}
