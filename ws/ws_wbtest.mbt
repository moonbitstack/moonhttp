// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Every frame in the first five tests is one RFC 6455 §5.7 prints, so the codec is
// checked against what the working group published rather than against itself.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.7

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
test "a single-frame unmasked text message is §5.7's first example" {
  let wire = hexb("810548656c6c6f")
  let frame : Frame = { fin: true, opcode: Text, payload: b"Hello", }
  assert_eq(hex(frame.encode()), hex(wire))
  guard decode(wire[:], client=false) is Some((got, n)) else {
    fail("the published frame should decode")
  }
  assert_eq(got, frame)
  assert_eq(n, wire.length())
}

///|
test "a single-frame masked text message is §5.7's second example" {
  let wire = hexb("8185" + "37fa213d" + "7f9f4d5158")
  let mask = hexb("37fa213d")
  let frame : Frame = { fin: true, opcode: Text, payload: b"Hello", }
  assert_eq(hex(frame.encode(mask~)), hex(wire))
  // A server reads it with the masking it requires, and gets the plain payload back.
  guard decode(wire[:]) is Some((got, n)) else {
    fail("the published masked frame should decode")
  }
  assert_eq(got, frame)
  assert_eq(n, wire.length())
}

///|
test "a fragmented unmasked text message is §5.7's third example" {
  let first = hexb("0103" + "48656c")
  let last = hexb("8002" + "6c6f")
  let head : Frame = { fin: false, opcode: Text, payload: b"Hel", }
  let tail : Frame = { fin: true, opcode: Continuation, payload: b"lo", }
  assert_eq(hex(head.encode()), hex(first))
  assert_eq(hex(tail.encode()), hex(last))
  let reader = Reader::new()
  let one = reader.feed(head)
  assert_eq(one.message, None)
  assert_eq(reader.pending(), 3)
  let two = reader.feed(tail)
  assert_eq(two.message, Some(Text("Hello")))
  assert_eq(reader.pending(), 0)
}

///|
test "an unmasked ping and a masked pong are §5.7's fourth example" {
  let ping = hexb("890548656c6c6f")
  let pong = hexb("8a85" + "37fa213d" + "7f9f4d5158")
  let frame : Frame = { fin: true, opcode: Ping, payload: b"Hello", }
  assert_eq(hex(frame.encode()), hex(ping))
  // A ping owes a pong carrying the same body, which the reader answers with; masking
  // it is the client's, because only the client has the randomness for a key.
  let reader = Reader::new()
  let step = reader.feed(frame)
  assert_eq(step.message, None)
  guard step.reply is Some(reply) else { fail("a ping owes a pong") }
  assert_eq(reply.opcode, Pong)
  assert_eq(reply.payload, b"Hello")
  assert_eq(hex(reply.encode(mask=hexb("37fa213d"))), hex(pong))
}

///|
test "the two long length forms are §5.7's last two examples" {
  // 256 bytes takes the sixteen-bit form, 65536 the sixty-four-bit one.
  let small = (
    { fin: true, opcode: Binary, payload: Bytes::make(256, b'\x07'), } : Frame).encode()
  assert_eq(hex(small[0:4].to_owned()), "827e0100")
  assert_eq(small.length(), 4 + 256)
  let large = (
    { fin: true, opcode: Binary, payload: Bytes::make(65536, b'\x07'), } : Frame).encode()
  assert_eq(hex(large[0:10].to_owned()), "827f0000000000010000")
  assert_eq(large.length(), 10 + 65536)
  // And both read back.
  guard decode(small[:], client=false) is Some((got, _)) else {
    fail("the sixteen-bit form should decode")
  }
  assert_eq(got.payload.length(), 256)
  guard decode(large[:], client=false) is Some((got, _)) else {
    fail("the sixty-four-bit form should decode")
  }
  assert_eq(got.payload.length(), 65536)
}

///|
test "the length takes the shortest form that fits" {
  for n in [0, 1, 125] {
    let b = (
      { fin: true, opcode: Binary, payload: Bytes::make(n, b'\x00'), } : Frame).encode()
    assert_eq(b[1].to_int(), n)
    assert_eq(b.length(), 2 + n)
  }
  // 126 is the first that does not fit in seven bits.
  let b = (
    { fin: true, opcode: Binary, payload: Bytes::make(126, b'\x00'), } : Frame).encode()
  assert_eq(b[1].to_int(), 126)
  assert_eq(b.length(), 4 + 126)
}

///|
test "a short buffer answers None rather than a violation" {
  let wire = hexb("8185" + "37fa213d" + "7f9f4d5158")
  for cut = 0; cut < wire.length(); cut = cut + 1 {
    assert_eq(decode(wire[0:cut]) is None, true)
  }
  assert_eq(decode(wire[:]) is None, false)
}

///|
test "every opcode round-trips through its wire value, and the rest are reserved" {
  let named : Array[Opcode] = [Continuation, Text, Binary, Close, Ping, Pong]
  for op in named {
    assert_eq(Opcode::of(op.code()), Some(op))
  }
  assert_eq(named.map(op => op.code()), [0, 1, 2, 8, 9, 10])
  for code in [3, 4, 5, 6, 7, 11, 12, 13, 14, 15] {
    assert_eq(Opcode::of(code), None)
  }
  assert_eq(named.map(op => op.is_control()), [
    false, false, false, true, true, true,
  ])
}

///|
test "the framing rules §5.2 and §5.5 lay down are enforced" {
  // An RSV bit with no extension negotiated.
  assert_eq(refused(hexb("c18548656c6c6f")).status(), 1002)
  // A reserved opcode.
  assert_eq(refused(hexb("838000000000")).status(), 1002)
  // A client frame that is not masked.
  assert_eq(refused(hexb("810548656c6c6f")).status(), 1002)
  // A control frame carrying more than 125 bytes: 126 announced in the short form is
  // the sixteen-bit escape, so the long form is what says it.
  assert_eq(refused(hexb("89fe0080" + "00000000")).status(), 1002)
  // A fragmented control frame.
  assert_eq(refused(hexb("098500000000")).status(), 1002)
}

///|
/// The refusal decoding these bytes raises, so the tests above read as a list.
///
/// `abort` rather than `fail` for the case that does not raise, because a `fail` inside
/// the try would widen what is caught to `Error` and lose the code.
fn refused(wire : Bytes, client? : Bool = true) -> Refused {
  let mut out : Refused? = None
  try {
    let _ = decode(wire[:], client~)
  } catch {
    e => out = Some(e)
  }
  match out {
    Some(e) => e
    None => abort("these bytes should have been refused")
  }
}

///|
test "a length past the ceiling is refused before anything is allocated" {
  // The sixty-four-bit form announcing four gibibytes, with no payload behind it.
  let header = hexb("827f" + "0000000100000000")
  let e = refused(header, client=false)
  assert_eq(e.status(), 1009)
  assert_eq(e is Exceeded(_), true)
  // And the sign bit §5.2 reserves is refused too, rather than read as negative.
  assert_eq(
    refused(hexb("827f" + "ffffffffffffffff"), client=false).status(),
    1009,
  )
}

///|
test "a message is bounded across its fragments, not only within one" {
  // Eight frames of two bytes against a ceiling of ten: the seventh is what exceeds it,
  // and no single frame ever comes near the limit.
  let reader = Reader::new(limit=10)
  let mut refused = false
  try {
    for i = 0; i < 8; i = i + 1 {
      let frame : Frame = {
        fin: false,
        opcode: if i == 0 {
          Text
        } else {
          Continuation
        },
        payload: b"ab",
      }
      let _ = reader.feed(frame)
    }
  } catch {
    Exceeded(limit~, got~) => {
      assert_eq(limit, 10)
      assert_eq(got, 12L)
      refused = true
    }
    _ => ()
  }
  assert_eq(refused, true)
}

///|
test "a stray continuation and an interrupted message are violations (§5.4)" {
  let reader = Reader::new()
  let mut stray = false
  try {
    let _ = reader.feed({ fin: true, opcode: Continuation, payload: b"x", })
  } catch {
    Protocol(_) => stray = true
    _ => ()
  }
  assert_eq(stray, true)

  // A data frame arriving before the last message finished.
  let other = Reader::new()
  let _ = other.feed({ fin: false, opcode: Text, payload: b"a", })
  let mut interrupted = false
  try {
    let _ = other.feed({ fin: true, opcode: Binary, payload: b"b", })
  } catch {
    Protocol(_) => interrupted = true
    _ => ()
  }
  assert_eq(interrupted, true)
}

///|
test "a control frame passes between the fragments of a message (§5.5)" {
  let reader = Reader::new()
  let _ = reader.feed({ fin: false, opcode: Text, payload: b"Hel", })
  // A ping in the middle is answered and changes nothing about the message.
  let ping = reader.feed({ fin: true, opcode: Ping, payload: b"?", })
  assert_eq(ping.message, None)
  assert_eq(ping.reply, Some({ fin: true, opcode: Pong, payload: b"?", }))
  assert_eq(reader.pending(), 3)
  // A pong is dropped.
  let pong = reader.feed({ fin: true, opcode: Pong, payload: b"?", })
  assert_eq(pong.message, None)
  assert_eq(pong.reply, None)
  let done = reader.feed({ fin: true, opcode: Continuation, payload: b"lo", })
  assert_eq(done.message, Some(Text("Hello")))
}

///|
test "a text message that is not UTF-8 fails with 1007 (§8.1)" {
  let reader = Reader::new()
  let mut refused = false
  try {
    let _ = reader.feed({
      fin: true,
      opcode: Text,
      payload: hexb("48656c6cff"),
    })
  } catch {
    Payload(_) => refused = true
    _ => ()
  }
  assert_eq(refused, true)
  // The same bytes as binary are nobody's business but the application's.
  let other = Reader::new()
  let step = other.feed({
    fin: true,
    opcode: Binary,
    payload: hexb("48656c6cff"),
  })
  assert_eq(step.message, Some(Binary(hexb("48656c6cff"))))
}

///|
test "a close carries its status and reason, and is echoed (§5.5.1)" {
  let reader = Reader::new()
  let payload = close(1000, reason="bye")
  assert_eq(hex(payload), "03e8627965")
  let step = reader.feed({ fin: true, opcode: Close, payload, })
  assert_eq(step.message, Some(Close(status=1000, reason=b"bye")))
  // The echo carries the status but not the reason.
  assert_eq(
    step.reply,
    Some({ fin: true, opcode: Close, payload: close(1000), }),
  )
}

///|
test "a close with no status reads as 1005 and is echoed with none" {
  let reader = Reader::new()
  let step = reader.feed({ fin: true, opcode: Close, payload: b"", })
  assert_eq(step.message, Some(Close(status=1005, reason=b"")))
  // 1005 is a local sentinel: it must not go back onto the wire.
  assert_eq(step.reply, Some({ fin: true, opcode: Close, payload: b"", }))
  assert_eq(status(b""[:]), 1005)
  assert_eq(reason(b""[:]), b"")
}

///|
test "only the statuses §7.4.1 allows may arrive on the wire" {
  for ok in [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 4999] {
    assert_eq(allowed(ok), true)
  }
  // Reserved, and the three an endpoint only ever sets for itself.
  for bad in [999, 1004, 1005, 1006, 1015, 1016, 2999, 5000] {
    assert_eq(allowed(bad), false)
  }
  // 1012 to 1014 were registered after RFC 6455 and are real.
  for later in [1012, 1013, 1014] {
    assert_eq(allowed(later), true)
  }
  // A peer that sends one of the forbidden ones has broken the protocol.
  let reader = Reader::new()
  let mut refused = false
  try {
    let _ = reader.feed({ fin: true, opcode: Close, payload: close(1005), })
  } catch {
    Payload(_) => refused = true
    _ => ()
  }
  assert_eq(refused, true)
}

///|
test "a close reason that is not UTF-8 is refused" {
  let reader = Reader::new()
  let payload = Buffer()
  payload.write_bytes(hexb("03e8"))
  payload.write_bytes(hexb("ff"))
  let mut refused = false
  try {
    let _ = reader.feed({
      fin: true,
      opcode: Close,
      payload: payload.to_bytes(),
    })
  } catch {
    Payload(_) => refused = true
    _ => ()
  }
  assert_eq(refused, true)
}

///|
test "the ceiling is a knob on both sides" {
  assert_eq(limit, 16 * 1024 * 1024)
  // A frame under the default and over a tighter one.
  let wire = (
    { fin: true, opcode: Binary, payload: Bytes::make(200, b'\x00'), } : Frame).encode()
  assert_eq(decode(wire[:], client=false) is Some(_), true)
  let mut refused = false
  try {
    let _ = decode(wire[:], client=false, limit=100)
  } catch {
    Exceeded(limit~, got~) => {
      assert_eq(limit, 100)
      assert_eq(got, 200L)
      refused = true
    }
    _ => ()
  }
  assert_eq(refused, true)
}

///|
test "a server's frames are read with masking not required" {
  let wire = ({ fin: true, opcode: Text, payload: b"Hello", } : Frame).encode()
  // As a client reading a server: unmasked is what §5.1 requires of it.
  guard decode(wire[:], client=false) is Some((got, _)) else {
    fail("a server frame should decode")
  }
  assert_eq(got.payload, b"Hello")
  // The same bytes read as if from a client are a violation.
  assert_eq(refused(wire).status(), 1002)
}
