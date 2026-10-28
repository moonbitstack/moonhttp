// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 7692 prints one compressed message and its octets (§7.2.3.1) and states the
// rest as rules, so the cases here follow the rules the way Autobahn's 12.x and
// 13.x groups probe them: every data message compressed and uncompressed, split
// across fragments, with and without the window carried over, plus the three ways
// a compressed message is refused — a stream that does not decompress (1007), one
// that expands too far (1009), and an RSV1 where §6.1 does not allow it (1002).
// The payloads themselves are zlib's, from `deflate`'s vectors.

///|
/// Text that repeats, so compression has something to work with.
fn text(n : Int32) -> Bytes {
  let buf = Buffer()
  let words : Array[Bytes] = [b"alpha ", b"bravo ", b"charlie ", b"delta "]
  let mut i = 0
  while buf.length() < n {
    buf.write_bytes(words[i % 4][:])
    i += 1
  }
  buf.to_bytes()[:n].to_owned()
}

///|
/// Hand a frame to a reader the way a connection does: written with its RSV1 bit,
/// read back out of the octets, then fed.
fn send(
  reader : @pmd.Reader,
  frame : @ws.Frame,
  rsv1~ : Bool = true,
) -> @ws.Step raise @ws.Refused {
  let wire = frame.encode_extension(rsv1~)
  // These frames are written the way a server writes them, unmasked: masking is
  // the client's, and belongs to whichever end owns the socket.
  let (decoded, _, compressed) = match
    @ws.decode_extension(wire[:], client=false) {
    Some(triple) => triple
    None => abort("the frame that was just written did not read back")
  }
  reader.feed(decoded, compressed~)
}

///|
/// The status a feed fails with, or zero when it does not fail.
fn failed(
  reader : @pmd.Reader,
  frame : @ws.Frame,
  rsv1~ : Bool = true,
) -> Int32 {
  let mut out = 0
  try {
    let _ = send(reader, frame, rsv1~)
  } catch {
    e => out = e.status()
  }
  out
}

///|
test "the four parameters read the way §7.1 writes them" {
  // Nothing named is everything at its default.
  assert_eq(@pmd.Extension::decode("permessage-deflate"), Some(@pmd.defaults))
  // A window named without a value: the offer leaves the choice to the server.
  assert_eq(
    @pmd.Extension::decode("permessage-deflate; client_max_window_bits"),
    Some({ ..@pmd.defaults, client_window_named: true, }),
  )
  // All four, in the order §7.1 lists them.
  assert_eq(
    @pmd.Extension::decode(
      "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=10; client_max_window_bits=12",
    ),
    Some(
      @pmd.Extension::new(
        server_takeover=false,
        client_takeover=false,
        server_window=10,
        client_window=12,
        client_window_named=true,
      ),
    ),
  )
  // Case-insensitive names, and space around the semicolons.
  assert_true(
    @pmd.Extension::decode("Permessage-Deflate ;  SERVER_max_window_bits = 9")
    is Some(terms) &&
    terms.server_window == 9,
  )
  // A quoted value means what the bare token means (§5.6.6).
  assert_true(
    @pmd.Extension::decode("permessage-deflate; server_max_window_bits=\"9\"")
    is Some(terms) &&
    terms.server_window == 9,
  )
}

///|
test "a value the grammar forbids is not read as a default" {
  for
    value in [
      "permessage-deflate; server_max_window_bits=7", "permessage-deflate; server_max_window_bits=16",
      "permessage-deflate; server_max_window_bits=010", "permessage-deflate; server_max_window_bits",
      "permessage-deflate; server_no_context_takeover=1", "permessage-deflate; client_max_window_bits=0",
      "permessage-deflate; x-frames=2", "x-webkit-deflate-frame", "deflate",
    ] {
    assert_eq(@pmd.Extension::decode(value[:]), None)
  }
}

///|
test "the parameters are written the way they were read" {
  let all = @pmd.Extension::new(
    server_takeover=false,
    client_takeover=false,
    server_window=10,
    client_window=12,
    client_window_named=true,
  )
  assert_eq(
    all.encode(role=Server),
    "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=10; client_max_window_bits=12",
  )
  // A client names a window it cannot improve on with no value, which is how it
  // says "I understand the parameter".
  let ask = @pmd.Extension::new(client_window_named=true)
  assert_eq(
    ask.encode(role=Client),
    "permessage-deflate; client_max_window_bits",
  )
  // Whatever either side writes, it reads back as the terms it wrote.
  for terms in [@pmd.defaults, all, ask] {
    for role in [@pmd.Role::Client, @pmd.Role::Server] {
      assert_eq(@pmd.Extension::decode(terms.encode(role~)[:]), Some(terms))
    }
  }
}

///|
test "a header with several offers keeps the ones this extension answers" {
  let header = "permessage-deflate; client_max_window_bits=10, x-other; a=1, permessage-deflate; server_no_context_takeover"
  let offers = @pmd.offers(header[:])
  assert_eq(offers.length(), 2)
  assert_eq(offers[0].client_window, 10)
  assert_false(offers[1].server_takeover)
}

///|
test "the first offer this endpoint can accept is the one it answers" {
  let header = "permessage-deflate; server_max_window_bits=9, permessage-deflate; client_max_window_bits=11"
  let offers = @pmd.offers(header[:])
  // The client's order is its preference, so the first offer this endpoint can
  // accept is the one it answers. The first names only the server's window, so
  // there is nothing to say about the client's.
  match @pmd.Extension::agree(offers[:]) {
    Some(terms) => {
      assert_eq(terms.server_window, 9)
      assert_false(terms.client_window_named)
      assert_eq(terms.client_window, 15)
    }
    None => fail("an offer with two acceptable values was declined")
  }
  // Declining the first leaves the second to be answered: a server that can only
  // decompress a small window cannot take an offer that leaves the client on the
  // full 32 KiB, but can take one that names a window it can read.
  let small = @pmd.Extension::new(client_window=9)
  let two = @pmd.offers(
    "permessage-deflate, permessage-deflate; client_max_window_bits"[:],
  )
  match @pmd.Extension::agree(two[:], support=small) {
    Some(terms) => {
      assert_true(terms.client_window_named)
      assert_eq(terms.client_window, 9)
    }
    None => fail("an offer naming a window the server can read was declined")
  }
  // A server that can only decompress a small window cannot accept an offer that
  // leaves the client on the full 32 KiB.
  assert_eq(
    @pmd.Extension::agree(
      @pmd.offers("permessage-deflate"[:])[:],
      support=small,
    ),
    None,
  )
  // The same server accepts an offer that names a window it can read.
  match
    @pmd.Extension::agree(
      @pmd.offers("permessage-deflate; client_max_window_bits=9"[:])[:],
      support=small,
    ) {
    Some(terms) => assert_eq(terms.client_window, 9)
    None => fail("a window the server can read was declined")
  }
  // A client asking for no context takeover gets no context takeover.
  let quiet = @pmd.offers(
    "permessage-deflate; server_no_context_takeover; client_no_context_takeover"[:],
  )
  match @pmd.Extension::agree(quiet[:]) {
    Some(terms) => {
      assert_false(terms.server_takeover)
      assert_false(terms.client_takeover)
    }
    None => fail("an offer with nothing wrong with it was declined")
  }
}

///|
test "a client refuses an answer that names more than it offered" {
  let offer = @pmd.Extension::new(server_window=10)
  assert_true(offer.accepts({ ..@pmd.defaults, server_window: 10, }))
  // A wider window than the offer named.
  assert_false(offer.accepts(@pmd.defaults))
  // `client_max_window_bits` in the answer when the offer did not name it.
  assert_false(offer.accepts(@pmd.Extension::new(client_window_named=true)))
  // A takeover the server refused on its own initiative is still an answer.
  assert_true(
    offer.accepts({
      ..@pmd.defaults,
      server_window: 10,
      server_takeover: false,
    }),
  )
}

///|
test "a compressed message round-trips at every size the frame forms change at" {
  for size in [0, 1, 125, 126, 127, 128, 65535] {
    let payload = text(size)
    let reader = @pmd.Reader::new()
    let (frame, compressed) = @pmd.Writer::new().frame(
      @ws.Opcode::Text,
      payload[:],
    )
    assert_true(compressed)
    // Anything long enough to compress does compress; a byte or two does not.
    assert_true(size < 64 || frame.payload.length() < payload.length())
    let step = send(reader, frame)
    match step.message {
      Some(@ws.Message::Text(got)) => assert_eq(got, @utf8.decode(payload[:]))
      Some(_) => fail("a text message came back as something else")
      None => fail("a whole message was not reported")
    }
  }
}

///|
test "a compressed message arrives in fragments" {
  // The compressed octets are split, not the message: whichever frame holds the
  // first part carries RSV1 and the rest are continuations (§6).
  let payload = text(500)
  let (frame, _) = @pmd.Writer::new().frame(@ws.Opcode::Text, payload[:])
  let wire = frame.payload
  let cut = wire.length() / 2
  let reader = @pmd.Reader::new()
  let first : @ws.Frame = {
    fin: false,
    opcode: @ws.Opcode::Text,
    payload: wire[:cut].to_owned(),
  }
  assert_true(send(reader, first).message is None)
  let second : @ws.Frame = {
    fin: true,
    opcode: @ws.Opcode::Continuation,
    payload: wire[cut:].to_owned(),
  }
  match send(reader, second, rsv1=false).message {
    Some(@ws.Message::Text(got)) => assert_eq(got, @utf8.decode(payload[:]))
    Some(_) => fail("a fragmented text message came back as something else")
    None => fail("the last fragment did not finish the message")
  }
}

///|
test "the window carries across messages when the terms allow it" {
  // zlib's own stream from `deflate`'s vectors: four messages where the later
  // ones only decode if the window of the first survived.
  let name = "four messages sharing one window"
  let mut segments : Array[Bytes] = []
  let mut messages : Array[Bytes] = []
  for vector in @deflate.vectors {
    let (label, _, _, segs, msgs) = vector
    if label == name {
      segments = segs
      messages = msgs
    }
  }
  assert_eq(segments.length(), 4)
  let reader = @pmd.Reader::new()
  for i in 0..<segments.length() {
    let frame : @ws.Frame = {
      fin: true,
      opcode: @ws.Opcode::Binary,
      payload: segments[i],
    }
    match send(reader, frame).message {
      Some(@ws.Message::Binary(got)) => assert_eq(got, messages[i])
      Some(_) => fail("a binary message came back as something else")
      None => fail("a whole message was not reported")
    }
  }
}

///|
test "no takeover means each message stands alone" {
  let terms = @pmd.Extension::new(server_takeover=false)
  let payload = text(300)
  let writer = @pmd.Writer::new(extension=terms)
  let reader = @pmd.Reader::new(extension=terms)
  for _ in 0..<2 {
    let (frame, _) = writer.frame(@ws.Opcode::Binary, payload[:])
    match send(reader, frame).message {
      Some(@ws.Message::Binary(got)) => assert_eq(got, payload)
      Some(_) => fail("a binary message came back as something else")
      None => fail("a whole message was not reported")
    }
  }
}

///|
test "a control frame between fragments is answered and changes nothing" {
  let payload = text(400)
  let (frame, _) = @pmd.Writer::new().frame(@ws.Opcode::Binary, payload[:])
  let wire = frame.payload
  let cut = wire.length() / 3
  let reader = @pmd.Reader::new()
  let first : @ws.Frame = {
    fin: false,
    opcode: @ws.Opcode::Binary,
    payload: wire[:cut].to_owned(),
  }
  assert_true(send(reader, first).message is None)
  let ping : @ws.Frame = {
    fin: true,
    opcode: @ws.Opcode::Ping,
    payload: b"hi",
  }
  let step = reader.feed(ping, compressed=false)
  match step.reply {
    Some(pong) => {
      assert_eq(pong.opcode, @ws.Opcode::Pong)
      assert_eq(pong.payload, b"hi")
    }
    None => fail("a ping was not answered")
  }
  let rest : @ws.Frame = {
    fin: true,
    opcode: @ws.Opcode::Continuation,
    payload: wire[cut:].to_owned(),
  }
  match send(reader, rest, rsv1=false).message {
    Some(@ws.Message::Binary(got)) => assert_eq(got, payload)
    Some(_) => fail("a binary message came back as something else")
    None => fail("the last fragment did not finish the message")
  }
}

///|
test "a stream that does not decompress fails the connection with 1007" {
  let reader = @pmd.Reader::new()
  let frame : @ws.Frame = {
    fin: true,
    opcode: @ws.Opcode::Text,
    payload: b"\xff\xff\xff\xff",
  }
  assert_eq(failed(reader, frame), 1007)
}

///|
test "a message that expands past the limit fails with 1009" {
  // A thousand zero octets compress to a few, which is the shape of the attack
  // the ceiling exists for.
  let zeros = Bytes::from_array(Array::make(1000, b'\x00'))
  let (frame, _) = @pmd.Writer::new().frame(@ws.Opcode::Binary, zeros[:])
  assert_true(frame.payload.length() < 100)
  let reader = @pmd.Reader::new(limit=100)
  assert_eq(failed(reader, frame), 1009)
  // The same message under a ceiling it fits within.
  let roomy = @pmd.Reader::new(limit=1000)
  match send(roomy, frame).message {
    Some(@ws.Message::Binary(got)) => assert_eq(got, zeros)
    Some(_) => fail("a binary message came back as something else")
    None => fail("a whole message was not reported")
  }
}

///|
test "RSV1 where §6.1 does not allow it is a protocol error" {
  // A continuation is never the first frame of a message, so it never carries the
  // bit; a control frame cannot be compressed at all.
  let continuation : @ws.Frame = {
    fin: true,
    opcode: @ws.Opcode::Continuation,
    payload: b"\x00",
  }
  assert_eq(check(continuation.encode_extension(rsv1=true)), 1002)
  let ping : @ws.Frame = { fin: true, opcode: @ws.Opcode::Ping, payload: b"", }
  assert_eq(check(ping.encode_extension(rsv1=true)), 1002)
}

///|
/// The status decoding these octets raises, or zero when they decode.
fn check(wire : Bytes) -> Int32 {
  let mut out = 0
  try {
    let _ = @ws.decode_extension(wire[:])
  } catch {
    e => out = e.status()
  }
  out
}

///|
test "a frame with RSV1 on a connection without the extension is refused" {
  let frame : @ws.Frame = {
    fin: true,
    opcode: @ws.Opcode::Text,
    payload: b"x",
  }
  let wire = frame.encode_extension(rsv1=true)
  // The frame layer knows nothing of the bit, so reading it there is the same
  // failure as a peer that set it with no extension negotiated (§5.2).
  let mut status = 0
  try {
    let _ = @ws.decode(wire[:])
  } catch {
    e => status = e.status()
  }
  assert_eq(status, 1002)
}

///|
test "an uncompressed message passes through a connection that agreed" {
  let reader = @pmd.Reader::new()
  let step = reader.feed(
    { fin: true, opcode: @ws.Opcode::Text, payload: b"plain", },
    compressed=false,
  )
  match step.message {
    Some(@ws.Message::Text(got)) => assert_eq(got, "plain")
    Some(_) => fail("a text message came back as something else")
    None => fail("a whole message was not reported")
  }
}

///|
test "a control frame is never compressed" {
  let (frame, compressed) = @pmd.Writer::new().frame(
    @ws.Opcode::Ping,
    b"ping-payload"[:],
  )
  assert_false(compressed)
  assert_eq(frame.payload, b"ping-payload")
  // A data message under a threshold a caller set is left alone too.
  let (quiet, compressed) = @pmd.Writer::new(threshold=64).frame(
    @ws.Opcode::Text,
    text(16)[:],
  )
  assert_false(compressed)
  assert_eq(quiet.payload, text(16))
}
