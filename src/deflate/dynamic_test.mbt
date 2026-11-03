// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The dynamic block, checked the way the fixed one is: what this encoder writes
// is read back by this decoder and by moonzip, and the choice between the two
// block types is pinned to a case on each side of it.

///|
/// Octets drawn from sixteen symbols, which is the shape a message has to have
/// before a code of its own pays for its header: many symbols, few of them.
fn sparse(n : Int32) -> Bytes {
  let out : Array[Byte] = []
  let mut x : UInt32 = 99991U
  for _ in 0..<n {
    x = x * 1103515245U + 12345U
    let v = ((x >> 16) & 0xFU).reinterpret_as_int()
    let byte = if v < 10 { 0x30 + v } else { 0xE0 + v }
    out.push(byte.to_byte())
  }
  Bytes::from_array(out)
}

///|
/// The block type a wire segment begins with: `BFINAL` in bit 0, `BTYPE` in bits 1
/// and 2 (§3.2.3).
fn block_type(wire : Bytes) -> Int32 {
  (wire[0].to_int() >> 1) & 3
}

///|
test "a block of many symbols carries its own codes" {
  let payload = sparse(4096)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  assert_eq(block_type(wire), 2)
  let back = @deflate.Inflater::new().decompress(wire[:]) catch {
    e => fail("a dynamic block did not read back: \{e}")
  }
  assert_eq(back, payload)
}

///|
test "a block that carries its own codes is shorter than the fixed one" {
  // The savings this exists for: sixteen symbols of five bits are cheaper than the
  // fixed code's eight, and the header is a few dozen octets against four thousand.
  let payload = sparse(4096)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  assert_true(wire.length() < payload.length() * 2 / 3)
}

///|
test "a message too short to pay for a header keeps the fixed codes" {
  // Eight octets are one fixed block of nine; a header of its own would be three
  // times the message.
  let wire = @deflate.Deflater::new(takeover=false).compress(text(8)[:])
  assert_eq(block_type(wire), 1)
}

///|
test "moonzip reads a block that carries its own codes" {
  let payloads = [sparse(3000), sparse(9000), text(4096)]
  for payload in payloads {
    let stream = @deflate.Deflater::new(takeover=false).compress(
      payload[:],
      finish=true,
    )
    let back = @zip.inflate(stream[:]) catch {
      _ => fail("moonzip refused a stream with a dynamic block")
    }
    assert_eq(back, payload)
  }
}

///|
test "a block that carries its own codes reads in fragments" {
  // A message split across frames is one stream, and a dynamic block's tables are
  // part of it: the reader has to stop inside them and pick up again.
  let payload = sparse(3000)
  let whole = @deflate.Deflater::new(takeover=false).compress(payload[:])
  for cut in [0, 1, 3, 40, whole.length() / 2, whole.length() - 1] {
    let inflater = @deflate.Inflater::new(takeover=false)
    let first = inflater.decompress(whole[0:cut], more=true) catch {
      e => fail("cut at \{cut}: the first fragment was refused: \{e}")
    }
    let second = inflater.decompress(whole[cut:]) catch {
      e => fail("cut at \{cut}: the second fragment was refused: \{e}")
    }
    assert_eq(first + second, payload)
  }
}

///|
test "the codes a block carries survive a message boundary" {
  // Context takeover means the next message may point into this one, so a dynamic
  // block has to leave the window where the next message's search expects it.
  let payload = sparse(2000)
  let deflater = @deflate.Deflater::new(takeover=true)
  let inflater = @deflate.Inflater::new(takeover=true)
  let first = deflater.compress(payload[:])
  let second = deflater.compress(payload[:])
  let one = inflater.decompress(first[:]) catch {
    _ => fail("the first message did not read back")
  }
  let two = inflater.decompress(second[:]) catch {
    _ => fail("the second message did not read back")
  }
  assert_eq(one, payload)
  assert_eq(two, payload)
  // The second message is one long match against the first, which no header of its
  // own could pay for.
  assert_eq(block_type(second), 1)
}
