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
  room? : Int32,
) -> @deflate.Refused? {
  let inflater = @deflate.Inflater::new(bits~)
  let mut out : @deflate.Refused? = None
  try {
    let _ = inflater.decompress(stream[:], room?)
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
test "moonzip reads what the retuned encoder writes at the measured sizes" {
  // The encoder was retuned at these sizes (RFC 7692's periodic prose and
  // incompressible noise, the inputs the speedup is measured on). A shorter
  // match chain changes the bytes it emits, but they are still DEFLATE a
  // reference decoder reads back as the message that went in.
  let payloads = [text(131072), noise(131072)]
  for payload in payloads {
    let deflater = @deflate.Deflater::new()
    let stream = deflater.compress(payload[:], finish=true)
    let back = @zip.inflate(stream[:]) catch {
      _ => fail("moonzip refused what the retuned encoder wrote")
    }
    assert_eq(back, payload)
  }
}

///|
/// English prose with its own word frequencies, repeated to `n`: the shape a text
/// frame on a real connection has, and one of the two shapes the encoder's
/// throughput is measured on.
fn prose(n : Int32) -> Bytes {
  let para = b"WE THE PEOPLE of the United States, in Order to form a more perfect Union, establish Justice, insure domestic Tranquility, provide for the common defence, promote the general Welfare, and secure the Blessings of Liberty to ourselves and our Posterity, do ordain and establish this Constitution for the United States of America. Article I. Section 1. All legislative Powers herein granted shall be vested in a Congress of the United States, which shall consist of a Senate and House of Representatives. Section 2. The House of Representatives shall be composed of Members chosen every second Year by the People of the several States, and the Electors in each State shall have the Qualifications requisite for Electors of the most numerous Branch of the State Legislature. No Person shall be a Representative who shall not have attained to the Age of twenty five Years, and been seven Years a Citizen of the United States, and who shall not, when elected, be an Inhabitant of that State in which he shall be chosen."
  let buf = Buffer()
  while buf.length() < n {
    buf.write_bytes(para[:])
  }
  buf.to_bytes()[:n].to_owned()
}

///|
/// Text with a thirteen-octet period: the other shape, where every match is as
/// long as DEFLATE allows and at one distance.
fn periodic(n : Int32) -> Bytes {
  let buf = Buffer()
  while buf.length() < n {
    buf.write_bytes(b"Hello World! ")
  }
  buf.to_bytes()[:n].to_owned()
}

///|
test "the three payloads the encoder is measured on read back through another decoder" {
  // A hundred and twenty-eight kilobytes of each shape Autobahn's 12.2.10 sends:
  // one long run, English, and octets with nothing to find.
  for payload in [periodic(131072), prose(131072), noise(131072)] {
    let wire = @deflate.Deflater::new(takeover=false).compress(
      payload[:],
      finish=true,
    )
    let back = @zip.inflate(wire[:]) catch {
      _ => fail("moonzip refused what the encoder wrote")
    }
    assert_eq(back, payload)
  }
}

///|
test "the parse on the measured payloads spends the octets it should" {
  // The encoder's choices — which positions are hashed, when a short match waits
  // for a longer one, and whether a message is coded at all — show up as the size
  // of what it writes. These are the sizes on the payloads the throughput is
  // measured on: a parse that stops deferring, or a hash that puts a text's keys
  // in one bucket, changes them.
  let sizes = [735, 1927, 131088]
  let payloads = [periodic(131072), prose(131072), noise(131072)]
  for i in 0..<sizes.length() {
    let wire = @deflate.Deflater::new(takeover=false).compress(payloads[i][:])
    assert_eq(wire.length(), sizes[i])
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
test "an expansion past the room it is given is refused" {
  let hello = b"\xf2\x48\xcd\xc9\xc9\x07\x00"
  assert_eq(refused(hello, room=4), Some(@deflate.Exceeded(limit=4, got=5)))
  // The same message fits in the room it needs, and without a room at all.
  assert_true(refused(hello, room=5) is None)
  assert_true(refused(hello) is None)
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
test "a stored message leaves its window for the one after it" {
  // The first message is octets with nothing to find, so it is copied; the second
  // begins with the same octets and ends in text, so it is coded, and the copy of
  // the first message in it is a set of matches only if that message's window
  // survived.
  let stored = noise(8192)
  let next = stored + text(2048)
  let deflater = @deflate.Deflater::new(takeover=true)
  let first = deflater.compress(stored[:])
  assert_true(first.length() >= stored.length())
  let second = deflater.compress(next[:])
  assert_true(second.length() < 1024)
  let inflater = @deflate.Inflater::new(takeover=true)
  let one = inflater.decompress(first[:]) catch {
    e => fail("the stored message was refused: " + e.to_string())
  }
  let two = inflater.decompress(second[:]) catch {
    e => fail("the message after it was refused: " + e.to_string())
  }
  assert_eq(one, stored)
  assert_eq(two, next)
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

///|
test "every stream zlib wrote reads the same fed an octet at a time" {
  // Every block type zlib writes, fixed, dynamic and stored, with the window
  // carried from message to message: each fragment ends inside a symbol, a header
  // or a stored run somewhere, and decoding has to pick up exactly there.
  for vector in @deflate.vectors {
    let (name, bits, takeover, segments, messages) = vector
    let inflater = @deflate.Inflater::new(bits~, takeover~)
    for i in 0..<segments.length() {
      let segment = segments[i]
      let got = Buffer()
      for at in 0..<segment.length() {
        let piece = inflater.decompress(segment[at:at + 1], more=true) catch {
          e => fail("\{name}: octet \{at} of segment \{i}: " + e.to_string())
        }
        got.write_bytes(piece)
      }
      let rest = inflater.decompress(b""[:]) catch {
        e => fail("\{name}: the end of segment \{i}: " + e.to_string())
      }
      got.write_bytes(rest)
      if got.to_bytes() != messages[i] {
        fail("\{name}: segment \{i} read an octet at a time differs")
      }
    }
  }
}

///|
test "a message split into two hundred and fifty-six-octet pieces reads the same" {
  // The shape a compressed WebSocket message has when the peer fragments it: one
  // DEFLATE stream chopped at fixed offsets, so most pieces end inside a symbol
  // and a few end inside a block header or a stored run. A hundred and twenty
  // eight kilobytes is the size Autobahn's 12.2.10 sends a thousand of.
  let payload = text(131072)
  let wire = @deflate.Deflater::new(takeover=false).compress(payload[:])
  assert_true(wire.length() < payload.length())
  let inflater = @deflate.Inflater::new(takeover=false)
  let got = Buffer()
  let mut at = 0
  while at < wire.length() {
    let piece = if wire.length() - at < 256 {
      wire[at:]
    } else {
      wire[at:at + 256]
    }
    let part = inflater.decompress(piece, more=true) catch {
      e => fail("the piece at \{at} was refused: " + e.to_string())
    }
    got.write_bytes(part)
    at += 256
  }
  let rest = inflater.decompress(b""[:]) catch {
    e => fail("the end of the message was refused: " + e.to_string())
  }
  got.write_bytes(rest)
  assert_eq(got.to_bytes(), payload)
}
