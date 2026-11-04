// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A message that does not repeat is carried in stored blocks (RFC 1951 §3.2.4).
// That is faster than coding every octet and is still a stream any reader takes,
// which is what `deflate_test.mbt` does not otherwise exercise from this side.

///|
fn stored_noise(n : Int32) -> Bytes {
  let out : Array[Byte] = []
  let mut x : UInt32 = 99991U
  for _ in 0..<n {
    x = x * 1103515245U + 12345U
    out.push(((x >> 16) & 0xFFU).reinterpret_as_int().to_byte())
  }
  Bytes::from_array(out)
}

///|
fn stored_text(n : Int32) -> Bytes {
  let buf = Buffer()
  while buf.length() < n {
    buf.write_bytes(b"the quick brown fox. "[:])
  }
  buf.to_bytes()[:n].to_owned()
}

///|
test "a message that does not repeat is stored, and reads back" {
  let payload = stored_noise(20000)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  // One stored block, whose five-octet header is the whole overhead.
  assert_true(wire.length() >= payload.length())
  assert_true(wire.length() <= payload.length() + 16)
  let back = @deflate.Inflater::new(takeover=false).decompress(wire[:]) catch {
    e => fail(e.to_string())
  }
  assert_eq(back, payload)
}

///|
test "a message of several stored blocks reads back, across the 16-bit length" {
  // 200000 octets is four stored blocks, so the LEN field is written more than
  // once and a reader has to walk past each header.
  let payload = stored_noise(200000)
  let back = @deflate.Inflater::new(takeover=false).decompress(
    @deflate.Deflater::new(takeover=false).compress(payload[:])[:],
  ) catch {
    e => fail(e.to_string())
  }
  assert_eq(back, payload)
  // And moonzip, which this package did not write, takes the closed stream too.
  let whole = @deflate.Deflater::new(takeover=false).compress(
    payload[:],
    finish=true,
  )
  let again = @zip.inflate(whole[:]) catch {
    _ => fail("moonzip refused a stored stream")
  }
  assert_eq(again, payload)
}

///|
/// Octets drawn from ninety-five symbols — printable ASCII, which is the shape a
/// token, a base64 blob or a line of JSON has when it carries no repeat at all.
fn stored_printable(n : Int32) -> Bytes {
  let out : Array[Byte] = []
  let mut x : UInt32 = 20250101U
  for _ in 0..<n {
    x = x * 1103515245U + 12345U
    out.push((0x20 + ((x >> 16) % 95U).reinterpret_as_int()).to_byte())
  }
  Bytes::from_array(out)
}

///|
test "a wide alphabet is coded even where nothing in it repeats" {
  // Six and a half bits an octet against the eight stored costs: the code pays for
  // its header many times over on a message this long. Nothing here repeats, so a
  // test that looked only for repeats read it as noise and copied it byte for byte.
  let payload = stored_printable(20000)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  assert_eq(block_type(wire), 2)
  assert_true(wire.length() * 10 < payload.length() * 9)
  let back = @deflate.Inflater::new(takeover=false).decompress(wire[:]) catch {
    e => fail("a coded wide alphabet did not read back: \{e}")
  }
  assert_eq(back, payload)
  let whole = @deflate.Deflater::new(takeover=false).compress(
    payload[:],
    finish=true,
  )
  let again = @zip.inflate(whole[:]) catch {
    _ => fail("moonzip refused a coded wide alphabet")
  }
  assert_eq(again, payload)
}

///|
test "a message that repeats is still coded, not stored" {
  let payload = stored_text(20000)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  assert_true(wire.length() < payload.length() / 4)
}
