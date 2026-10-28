// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 1951 defines a format rather than printing vectors, and the streams a
// WebSocket endpoint actually has to read are zlib's, so the vectors in
// `vectors.mbt` were produced by zlib — `scripts/gen_deflate_vectors.py` made
// them, and CI only replays them. Both directions are checked: what zlib wrote
// is read here, and what is written here is read back by moonzip, an
// implementation this package did not write.

///|
/// Text that repeats, so the match finder has something to find.
fn text(n : Int32) -> Bytes {
  let words : Array[Bytes] = [
    b"alpha ", b"bravo ", b"charlie ", b"delta ", b"echo ", b"foxtrot ",
  ]
  let buf = Buffer()
  let mut i = 0
  while buf.length() < n {
    buf.write_bytes(words[i % 6][:])
    i += 1
  }
  buf.to_bytes()[:n].to_owned()
}

///|
/// Octets that barely repeat, so the compressor has to write them out.
fn noise(n : Int32) -> Bytes {
  let out : Array[Byte] = []
  let mut x : UInt32 = 12345U
  for _ in 0..<n {
    x = x * 1103515245U + 12345U
    out.push(((x >> 16) & 0xFFU).reinterpret_as_int().to_byte())
  }
  Bytes::from_array(out)
}

///|
/// The case with that name, which is how a test names a shape rather than an
/// index into a generated file.
fn case(name : String) -> (Int32, Bool, Array[Bytes], Array[Bytes]) {
  for vector in @deflate.vectors {
    let (label, bits, takeover, segments, messages) = vector
    if label == name {
      return (bits, takeover, segments, messages)
    }
  }
  abort("no such case: " + name)
}

///|
/// What reading this stream refuses with, or `None` when it reads as it should.
fn refused(
  stream : Bytes,
  bits~ : Int32 = 15,
  limit~ : Int32 = -1,
) -> @deflate.Refused? {
  let inflater = @deflate.Inflater::new(bits~, limit~)
  let mut out : @deflate.Refused? = None
  try {
    let _ = inflater.decompress(stream[:])
  } catch {
    e => out = Some(e)
  }
  out
}

///|
test "every stream zlib wrote reads back as the message it compressed" {
  for vector in @deflate.vectors {
    let (name, bits, takeover, segments, messages) = vector
    let inflater = @deflate.Inflater::new(bits~, takeover~)
    for i in 0..<segments.length() {
      let got = inflater.decompress(segments[i][:]) catch {
        e => fail(name + ": " + e.to_string())
      }
      if got != messages[i] {
        fail(name + ": segment \{i} is not the message that went in")
      }
    }
  }
}

///|
test "the two directions are inverses, at every window and both ways round" {
  let payloads = [b"", b"a", b"Hello", text(64), text(1000), noise(300)]
  for bits in [8, 9, 12, 15] {
    for takeover in [true, false] {
      let deflater = @deflate.Deflater::new(bits~, takeover~)
      let inflater = @deflate.Inflater::new(bits~, takeover~)
      for payload in payloads {
        let wire = deflater.compress(payload[:])
        let back = inflater.decompress(wire[:]) catch {
          e => fail("bits=\{bits} takeover=\{takeover}: " + e.to_string())
        }
        assert_eq(back, payload)
      }
    }
  }
}

///|
test "the Hello example of RFC 7692 §7.2.3.1" {
  // The section prints eleven octets for the flushed stream and seven for what
  // goes on the wire, and the seven are what the encoder here writes.
  let wire = @deflate.Deflater::new(takeover=false).compress(b"Hello"[:])
  assert_eq(hex(wire), "f248cdc9c90700")
  // §7.2.3.1 prints the flushed stream before the tail comes off, which is those
  // seven octets with `00 00 ff ff` still on.
  assert_eq(hex(wire + b"\x00\x00\xff\xff"), "f248cdc9c907000000ffff")
  // Closing the stream instead sets `BFINAL` on that empty block, at the bit the
  // section's example leaves clear.
  let whole = @deflate.Deflater::new(takeover=false).compress(
    b"Hello"[:],
    finish=true,
  )
  assert_eq(hex(whole), "f248cdc9c907040000ffff")
}

///|
/// The octets as hexadecimal, which is how the vector files and the RFC print
/// them.
fn hex(bytes : Bytes) -> String {
  let out = StringBuilder()
  for b in bytes {
    let v = b.to_int()
    out.write_char(digit((v >> 4) & 0x0F))
    out.write_char(digit(v & 0x0F))
  }
  out.to_string()
}

///|
fn digit(v : Int32) -> Char {
  if v < 10 {
    (0x30 + v).unsafe_to_char()
  } else {
    (0x61 + v - 10).unsafe_to_char()
  }
}

///|
test "moonzip reads what this encoder writes" {
  // The stream only has a beginning and an end once the last message closes it,
  // and a decompressor that expects a file needs both.
  let payloads = [b"", b"x", text(300), text(5000), noise(400)]
  for payload in payloads {
    let deflater = @deflate.Deflater::new()
    let stream = deflater.compress(payload[:], finish=true)
    let back = @zip.inflate(stream[:]) catch {
      _ => fail("moonzip refused what was written")
    }
    assert_eq(back, payload)
  }
}

///|
test "a message that stops inside a block is refused" {
  // The first three octets of the Hello stream: the block header and half a
  // literal, and then nothing.
  assert_true(refused(b"\xf2\x48\xcd") is Some(@deflate.Truncated(..)))
}

///|
test "a block type DEFLATE does not define is refused" {
  assert_eq(refused(b"\x07"), Some(@deflate.Block(at=1, got=3)))
}

///|
test "a message that expands past the ceiling is refused" {
  let hello = b"\xf2\x48\xcd\xc9\xc9\x07\x00"
  assert_eq(refused(hello, limit=4), Some(@deflate.Exceeded(limit=4, got=5)))
  // The same message passes a ceiling it fits under.
  assert_true(refused(hello, limit=5) is None)
}

///|
test "a distance past the negotiated window is refused" {
  // The thousand-octet case reaches further back than a nine-bit window holds,
  // which is the point of negotiating one down.
  let (_, _, segments, _) = case("one text message of 1024 octets")
  assert_true(refused(segments[0], bits=9) is Some(@deflate.Distance(..)))
  assert_true(refused(segments[0], bits=15) is None)
}

///|
test "the window survives a message boundary only while that is agreed" {
  // Two messages that share nothing: with the window kept, the second is one
  // long match against the first; without it, the second is written out again.
  let shared = noise(200)
  let kept = @deflate.Deflater::new(takeover=true)
  let first = kept.compress(shared[:])
  let second = kept.compress(shared[:])
  assert_true(first.length() > 180)
  assert_true(second.length() < 32)
  let apart = @deflate.Deflater::new(takeover=false)
  let _ = apart.compress(shared[:])
  let again = apart.compress(shared[:])
  assert_true(again.length() > 180)
  // And a reset drops the window as `*_no_context_takeover` asks.
  let dropped = @deflate.Deflater::new(takeover=true)
  let _ = dropped.compress(shared[:])
  dropped.reset()
  assert_true(dropped.compress(shared[:]).length() > 180)
}

///|
test "a reader that drops the window cannot read a stream that used it" {
  // The four-message case only decodes while the window is kept, which is what
  // RFC 7692 §7.2.2 makes a receiver do when takeover was not refused.
  let (bits, takeover, segments, _) = case("four messages sharing one window")
  let inflater = @deflate.Inflater::new(bits~, takeover~)
  let _ = inflater.decompress(segments[0][:])
  inflater.reset()
  let mut out : @deflate.Refused? = None
  try {
    let _ = inflater.decompress(segments[1][:])
  } catch {
    e => out = Some(e)
  }
  assert_true(out is Some(@deflate.Distance(..)))
}

///|
test "a message compresses when it repeats itself" {
  let payload = text(4096)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  assert_true(wire.length() < payload.length() / 8)
}

///|
test "panic a window outside what DEFLATE allows" {
  let _ = @deflate.Deflater::new(bits=16)
}

///|
test "a message read in two pieces reads the same as in one" {
  // A compressed message may be split anywhere, including inside a block, and a
  // reader that stops in the middle of one has to carry what it was in the middle
  // of into the next call. Every split of a message is tried here, so every bit
  // offset a boundary can fall on is.
  let payload = text(300)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  for cut in 0..<=wire.length() {
    let inflater = @deflate.Inflater::new(takeover=false)
    let head = inflater.decompress(wire[:cut], more=true) catch {
      e => fail("the first piece at \{cut} was refused: " + e.to_string())
    }
    let tail = inflater.decompress(wire[cut:]) catch {
      e => fail("the second piece at \{cut} was refused: " + e.to_string())
    }
    assert_eq(head + tail, payload)
  }
}

///|
test "a message that stops inside a block and never continues is refused" {
  let wire = @deflate.Deflater::new(takeover=false).compress(text(300)[:])
  let inflater = @deflate.Inflater::new(takeover=false)
  let mut out : @deflate.Refused? = None
  try {
    let _ = inflater.decompress(wire[:wire.length() / 2])
  } catch {
    e => out = Some(e)
  }
  assert_true(out is Some(@deflate.Truncated(..)))
}
