// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9114 section by section: the frames of §7.1 and §7.2, the placement rules of
// §7.2 that say which frame belongs on which stream, the settings of §7.2.4, the
// unidirectional stream types of §6.2, and a request and response as field sections.

///|
test "http3 frame encode: DATA, HEADERS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID" {
  assert_eq((Data(b"\x68\x69") : Frame).encode(), b"\x00\x02\x68\x69")
  assert_eq((Headers(b"\xab\xcd") : Frame).encode(), b"\x01\x02\xab\xcd")
  assert_eq((GoAway(0) : Frame).encode(), b"\x07\x01\x00")
  assert_eq((CancelPush(5) : Frame).encode(), b"\x03\x01\x05")
  assert_eq((MaxPushId(5) : Frame).encode(), b"\x0d\x01\x05")
}

///|
test "http3 frame encode: SETTINGS pairs and PUSH_PROMISE" {
  // SETTINGS with two 1-byte-varint pairs: (0x06, 0x00), (0x01, 0x00).
  assert_eq(
    (Settings([(0x06, 0x00), (0x01, 0x00)]) : Frame).encode(),
    b"\x04\x04\x06\x00\x01\x00",
  )
  // PUSH_PROMISE: push id 3 then the field block.
  assert_eq(
    (PushPromise(3, b"\xff\xee") : Frame).encode(),
    b"\x05\x03\x03\xff\xee",
  )
}

///|
test "http3 frame decode: each frame round-trips to its typed form" {
  let cases : Array[Frame] = [
    Data(b"\x68\x69"),
    Headers(b"\xab\xcd"),
    GoAway(0),
    CancelPush(5),
    MaxPushId(5),
    Settings([(0x06, 0x00), (0x01, 0x00)]),
    PushPromise(3, b"\xff\xee"),
  ]
  for frame in cases {
    let encoded = (frame : Frame).encode()
    match decode(encoded[:]) {
      Some((decoded, consumed)) => {
        assert_eq(decoded, frame)
        assert_eq(consumed, encoded.length())
      }
      None => abort("expected a complete frame")
    }
  }
}

///|
test "http3 frame decode: multi-byte varint settings values round-trip" {
  // Values that need 2- and 4-byte QUIC varints exercise the length fields.
  let frame = Settings([(0x01, 4096), (0x06, 16384)])
  let encoded = (frame : Frame).encode()
  match decode(encoded[:]) {
    Some((decoded, _)) => assert_eq(decoded, frame)
    None => abort("expected a complete frame")
  }
}

///|
test "http3 frame decode: reserved HTTP/2 types and grease types" {
  // 0x06 (HTTP/2 PING) is reused with no HTTP/3 meaning -> a connection error signal.
  match decode(b"\x06\x00"[:]) {
    Some((decoded, consumed)) => {
      assert_eq(decoded, ReservedHttp2(0x06))
      assert_eq(consumed, 2)
    }
    None => abort("expected a complete frame")
  }
  // An unknown/grease type is preserved as Reserved for the receiver to ignore.
  match decode(b"\x21\x01\x00"[:]) {
    Some((decoded, _)) => assert_eq(decoded, Reserved(0x21, b"\x00"))
    None => abort("expected a complete frame")
  }
}

///|
test "http3 frame decode: an incomplete frame yields None" {
  // Length says 4 payload octets but only 2 are present.
  assert_eq(decode(b"\x00\x04\x68\x69"[:]), None)
  // The length varint itself has not arrived.
  assert_eq(decode(b"\x00"[:]), None)
  // Empty input.
  assert_eq(decode(b""[:]), None)
}

///|
test "http3 frame decode_all: consumes whole frames, leaves a partial tail" {
  // Two complete frames followed by the start of a third.
  let stream = b"\x00\x02\x68\x69\x07\x01\x00\x00\x04\x68"
  let (frames, consumed) = decode_all(stream)
  assert_eq(frames.length(), 2)
  assert_eq(frames[0], Data(b"\x68\x69"))
  assert_eq(frames[1], GoAway(0))
  // The trailing partial DATA frame (needs 4 payload octets, has 1) is left unconsumed.
  assert_eq(consumed, 7)
}

///|
test "http3 frame decode: a truncated SETTINGS pair raises" {
  // SETTINGS length 3: identifier 0x06, value 0x00, then a dangling identifier 0x01.
  let bad = try {
    let _ = decode(b"\x04\x03\x06\x00\x01"[:])
    false
  } catch {
    _ => true
  }
  assert_eq(bad, true)
}

///|
test "http3 frame validation: DATA and HEADERS ride request/push streams, not control" {
  assert_eq(allowed(Data(b"x"), Request), true)
  assert_eq(allowed(Headers(b"x"), Push), true)
  assert_eq(allowed(Data(b"x"), Control), false)
  assert_eq(allowed(Headers(b"x"), Control), false)
}

///|
test "http3 frame validation: SETTINGS/GOAWAY/MAX_PUSH_ID/CANCEL_PUSH ride only the control stream" {
  assert_eq(allowed(Settings([(0x01UL, 4096UL)]), Control), true)
  assert_eq(allowed(GoAway(4UL), Control), true)
  assert_eq(allowed(MaxPushId(9UL), Control), true)
  assert_eq(allowed(CancelPush(2UL), Control), true)
  assert_eq(allowed(Settings([]), Request), false)
  assert_eq(allowed(GoAway(4UL), Request), false)
}

///|
test "http3 frame validation: PUSH_PROMISE rides a request stream; greased reserved rides anywhere" {
  assert_eq(allowed(PushPromise(1UL, b"h"), Request), true)
  assert_eq(allowed(PushPromise(1UL, b"h"), Control), false)
  assert_eq(allowed(Reserved(0x21UL, b""), Control), true)
  assert_eq(allowed(Reserved(0x21UL, b""), Request), true)
}

///|
test "http3 frame validation: HTTP/2-reserved frame types are a connection error on any stream" {
  for ctx in [Control, Request, Push] {
    assert_eq(allowed(ReservedHttp2(0x02UL), ctx), false)
    assert_eq(allowed(ReservedHttp2(0x06UL), ctx), false)
  }
}

///|
test "http3 frame validation: check raises on a misplaced frame" {
  // A well-placed frame passes.
  check(Data(b"x"), Request)
  // SETTINGS on a request stream is rejected.
  let rejected = try {
    check(Settings([]), Request)
    false
  } catch {
    _ => true
  }
  assert_eq(rejected, true)
}

///|
test "http3 settings: the named settings map to their RFC 9114 identifiers" {
  let s = Settings::new(4096UL, 16384UL, 100UL)
  assert_eq(s.pairs(), [(0x01UL, 4096UL), (0x06UL, 16384UL), (0x07UL, 100UL)])
}

///|
test "http3 settings: an endpoint's settings round-trip through its control stream" {
  let s = Settings::new(4096UL, 16384UL, 100UL)
  let ctrl = control(s.pairs())
  // The control stream opens with the control-stream type 0x00.
  assert_eq(ctrl[0], b'\x00')
  let back = match read_control(ctrl[:]) {
    Some(v) => v
    None => abort("expected a control stream with SETTINGS")
  }
  assert_eq(back.qpack_max_table_capacity, 4096UL)
  assert_eq(back.max_field_section_size, 16384UL)
  assert_eq(back.qpack_blocked_streams, 100UL)
}

///|
test "http3 settings: unknown settings are ignored and absent ones default to zero" {
  // A peer sends a known setting plus a greased/unknown identifier; the unknown is dropped and
  // the absent QPACK settings default to zero.
  let s = Settings::of_pairs([(0x06UL, 8192UL), (0x1fUL, 999UL)])
  assert_eq(s.max_field_section_size, 8192UL)
  assert_eq(s.qpack_max_table_capacity, 0UL)
  assert_eq(s.qpack_blocked_streams, 0UL)
}

///|
/// Encode a stream's opening bytes and decode them back.
fn roundtrip_stream(s : Stream) -> Stream raise {
  let wire = (s : Stream).encode()
  match Stream::decode(wire[:]) {
    Some((got, consumed)) => {
      assert_eq(consumed, wire.length())
      got
    }
    None => abort("incomplete stream type")
  }
}

///|
test "http3 stream: every unidirectional type round-trips" {
  assert_eq(roundtrip_stream(ControlKind), ControlKind)
  assert_eq(roundtrip_stream(PushKind(42)), PushKind(42))
  assert_eq(roundtrip_stream(EncoderKind), EncoderKind)
  assert_eq(roundtrip_stream(DecoderKind), DecoderKind)
  // A greased/reserved type (0x21 = 0x1f*1 + 2) and a large one.
  assert_eq(roundtrip_stream(ReservedKind(0x21)), ReservedKind(0x21))
  assert_eq(roundtrip_stream(ReservedKind(1000000)), ReservedKind(1000000))
}

///|
test "http3 stream: a push stream carries its push id" {
  let wire = (PushKind(0x4000) : Stream).encode() // 2-byte varint push id
  match Stream::decode(wire[:]) {
    Some((PushKind(id), _)) => assert_eq(id, 0x4000)
    _ => abort("expected a push stream")
  }
}

///|
test "http3 stream: a control stream opens with its type then SETTINGS" {
  let settings : Array[(UInt64, UInt64)] = [(0x06, 16384), (0x07, 100)]
  let wire = control(settings)
  match Stream::decode(wire[:]) {
    Some((ControlKind, consumed)) => {
      let (frames, _) = decode_all(wire[consumed:].to_owned())
      assert_eq(frames, [Settings(settings)])
    }
    _ => abort("expected a control stream")
  }
}

///|
test "http3 message: a GET request round-trips" {
  let wire = request(
    "GET",
    "https",
    "example.com",
    "/index.html",
    [
      @header.Header::of("user-agent", "mooncat"),
      @header.Header::of("accept", "text/html"),
    ],
    b"",
  )
  let (headers, body) = read_message(wire)
  assert_eq(headers, [
    @header.Header::of(":method", "GET"),
    @header.Header::of(":scheme", "https"),
    @header.Header::of(":authority", "example.com"),
    @header.Header::of(":path", "/index.html"),
    @header.Header::of("user-agent", "mooncat"),
    @header.Header::of("accept", "text/html"),
  ])
  assert_eq(body, b"")
}

///|
test "http3 message: a POST request carries a body" {
  let payload = b"{\"name\":\"mooncat\"}"
  let wire = request(
    "POST",
    "https",
    "api.example.com",
    "/submit",
    [@header.Header::of("content-type", "application/json")],
    payload,
  )
  let (headers, body) = read_message(wire)
  assert_eq(headers, [
    @header.Header::of(":method", "POST"),
    @header.Header::of(":scheme", "https"),
    @header.Header::of(":authority", "api.example.com"),
    @header.Header::of(":path", "/submit"),
    @header.Header::of("content-type", "application/json"),
  ])
  assert_eq(body, payload)
}

///|
test "http3 message: a response round-trips with status and body" {
  let wire = response(
    "200",
    [
      @header.Header::of("content-type", "text/html"),
      @header.Header::of("server", "mooncat"),
    ],
    b"<h1>ok</h1>",
  )
  let (headers, body) = read_message(wire)
  assert_eq(headers, [
    @header.Header::of(":status", "200"),
    @header.Header::of("content-type", "text/html"),
    @header.Header::of("server", "mooncat"),
  ])
  assert_eq(body, b"<h1>ok</h1>")
}

///|
test "http3 message: a body split across multiple DATA frames reassembles" {
  // Hand-build a stream: HEADERS, then two DATA frames.
  let buf = Buffer()
  buf.write_bytes(
    (Headers(@qpack.encode([@header.Header::of(":status", "200")])) : Frame).encode(),
  )
  buf.write_bytes((Data(b"hello ") : Frame).encode())
  buf.write_bytes((Data(b"world") : Frame).encode())
  let (headers, body) = read_message(buf.to_bytes())
  assert_eq(headers, [@header.Header::of(":status", "200")])
  assert_eq(body, b"hello world")
}

///|
test "http3 conn: the peer control stream establishes its SETTINGS" {
  let conn = Conn::new(Server, Settings::new(4096UL, 16384UL, 100UL))
  assert_eq(conn.settings_established(), false)
  let peer = Settings::new(8192UL, 65536UL, 32UL)
  let event = conn.accept_uni_stream(control(peer.pairs()))
  assert_eq(event, ControlEstablished(peer))
  assert_eq(conn.settings_established(), true)
  assert_eq(conn.peer_settings(), Some(peer))
}

///|
test "http3 conn: our own control stream round-trips our settings" {
  let mine = Settings::new(4096UL, 16384UL, 100UL)
  let conn = Conn::new(Client, mine)
  let peer = Conn::new(Server, Settings::new(0UL, 0UL, 0UL))
  assert_eq(
    peer.accept_uni_stream(conn.open_control_stream()),
    ControlEstablished(mine),
  )
}

///|
test "http3 conn: a second control stream is a connection error" {
  let conn = Conn::new(Server, Settings::new(4096UL, 16384UL, 100UL))
  let ctrl = control(Settings::new(1UL, 2UL, 3UL).pairs())
  conn.accept_uni_stream(ctrl) |> ignore
  let failed = try {
    conn.accept_uni_stream(ctrl) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(failed, true)
}

///|
test "http3 conn: QPACK streams classify, and a server rejects a push stream" {
  let conn = Conn::new(Server, Settings::new(4096UL, 16384UL, 100UL))
  assert_eq(
    conn.accept_uni_stream((EncoderKind : Stream).encode()),
    QpackEncoder,
  )
  assert_eq(
    conn.accept_uni_stream((DecoderKind : Stream).encode()),
    QpackDecoder,
  )
  let pushed_to_server = try {
    conn.accept_uni_stream((PushKind(7UL) : Stream).encode()) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(pushed_to_server, true)
  // A client, by contrast, accepts a push stream and reads its id.
  let client = Conn::new(Client, Settings::new(0UL, 0UL, 0UL))
  assert_eq(
    client.accept_uni_stream((PushKind(7UL) : Stream).encode()),
    Push(7UL),
  )
}

///|
fn h3_header(headers : Array[@header.Header], name : String) -> String {
  for h in headers {
    let (n, v) = h.ascii()
    if n == name {
      return v
    }
  }
  ""
}

///|
test "http3 server: parses a request stream into its pseudo-headers, headers, and body" {
  let stream = request(
    "POST",
    "https",
    "lfanke.example",
    "/submit",
    [@header.Header::of("content-type", "text/plain")],
    b"payload",
  )
  let req = match read_request(stream) {
    Some(r) => r
    None => abort("expected a valid request")
  }
  assert_eq(req.meth, "POST")
  assert_eq(req.scheme, "https")
  assert_eq(req.authority, "lfanke.example")
  assert_eq(req.path, "/submit")
  assert_eq(req.headers, [@header.Header::of("content-type", "text/plain")]) // pseudo-headers stripped
  assert_eq(req.body, b"payload")
}

///|
test "http3 server: routes a request through a handler and encodes the response" {
  let stream = request("GET", "https", "lfanke.example", "/hello", [], b"")
  let handler = fn(r : Request) -> Response {
    if r.path == "/hello" {
      Response::{
        status: "200",
        headers: [@header.Header::of("content-type", "text/plain")],
        body: b"hi from mooncat",
      }
    } else {
      Response::{ status: "404", headers: [], body: b"", }
    }
  }
  let resp = serve(stream, handler)
  let (headers, body) = read_message(resp)
  assert_eq(h3_header(headers, ":status"), "200")
  assert_eq(body, b"hi from mooncat")
}

///|
test "http3 server: a request stream without pseudo-headers is answered 400" {
  let stream = message([@header.Header::of("x-custom", "y")], b"") // no :method / :path
  let resp = serve(stream, fn(_r) {
    Response::{ status: "200", headers: [], body: b"", }
  })
  let (headers, _) = read_message(resp)
  assert_eq(h3_header(headers, ":status"), "400")
}

///|
test "http3 request strict: a well-formed request parses, a control frame on it is rejected" {
  let req = request(
    "GET",
    "https",
    "example",
    "/x",
    [@header.Header::of("k", "v")],
    b"hi",
  )
  match read_request(req) {
    Some(r) => {
      assert_eq(r.meth, "GET")
      assert_eq(r.scheme, "https")
      assert_eq(r.authority, "example")
      assert_eq(r.path, "/x")
      assert_eq(r.headers, [@header.Header::of("k", "v")])
      assert_eq(r.body, b"hi")
    }
    None => abort("expected a parsed request")
  }
  // A SETTINGS frame belongs on the control stream; on a request stream it is H3_FRAME_UNEXPECTED.
  let tampered = join(req, (Settings([]) : Frame).encode())
  let rejected = try {
    read_request(tampered, strict=true) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(rejected, true)
}

///|
/// Two byte strings joined.
fn join(a : Bytes, b : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(a)
  buf.write_bytes(b)
  buf.to_bytes()
}
