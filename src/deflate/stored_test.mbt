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
test "a message that repeats is still coded, not stored" {
  let payload = stored_text(20000)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  assert_true(wire.length() < payload.length() / 4)
}
