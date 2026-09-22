// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The key and its proof are the pair RFC 6455 §1.3 prints, so the one computation in
// this package is checked against what the working group published.
// https://www.rfc-editor.org/rfc/rfc6455#section-1.3

///|
/// §1.3's client key.
let sample : String = "dGhlIHNhbXBsZSBub25jZQ=="

///|
/// The `Sec-WebSocket-Accept` §1.3 prints for it.
let proof : String = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

///|
test "the proof for RFC 6455 §1.3's key is the one it publishes" {
  assert_eq(accept(sample), proof)
  // The GUID is what makes a server that merely echoed the key fail this.
  assert_eq(guid, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
  assert_eq(accept(sample) == sample, false)
}

///|
test "a key is sixteen random bytes in base64" {
  // §1.3's key decodes to the sixteen bytes "the sample nonce".
  assert_eq(key(b"the sample nonce"[:]), sample)
  assert_eq(key(b""[:]), "")
}

///|
test "the client's handshake asks for the upgrade §4.1 describes" {
  let wire = @utf8.decode_lossy(request(host="example.com", key=sample)[:])
  assert_eq(
    wire,
    "GET / HTTP/1.1\r\n" +
    "Host: example.com\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Key: " +
    sample +
    "\r\n" +
    "Sec-WebSocket-Version: 13\r\n" +
    "\r\n",
  )
}

///|
test "the optional parts of the request are written only when given" {
  let full = @utf8.decode_lossy(
    request(
      host="example.com",
      key=sample,
      path="/chat",
      protocols=["chat", "superchat"][:],
      origin="http://example.com",
      extra=[("X-Trace", "1")][:],
    )[:],
  )
  assert_eq(full.contains("GET /chat HTTP/1.1"), true)
  assert_eq(full.contains("Sec-WebSocket-Protocol: chat, superchat"), true)
  assert_eq(full.contains("Origin: http://example.com"), true)
  assert_eq(full.contains("X-Trace: 1"), true)
  // And an empty protocol list writes no header at all, rather than an empty one.
  let bare = @utf8.decode_lossy(request(host="h", key=sample)[:])
  assert_eq(bare.contains("Sec-WebSocket-Protocol"), false)
  assert_eq(bare.contains("Origin"), false)
}

///|
test "the server's 101 carries the proof and the subprotocol it chose" {
  let wire = @utf8.decode_lossy(response(sample, protocol="chat")[:])
  assert_eq(
    wire,
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Accept: " +
    proof +
    "\r\n" +
    "Sec-WebSocket-Protocol: chat\r\n" +
    "\r\n",
  )
  // No subprotocol negotiated, no header.
  let bare = @utf8.decode_lossy(response(sample)[:])
  assert_eq(bare.contains("Sec-WebSocket-Protocol"), false)
}

///|
test "the client's order decides which subprotocol is selected" {
  assert_eq(
    subprotocol(["chat", "superchat"][:], ["superchat", "chat"][:]),
    Some("chat"),
  )
  assert_eq(
    subprotocol(["superchat", "chat"][:], ["superchat", "chat"][:]),
    Some("superchat"),
  )
  assert_eq(subprotocol(["mqtt"][:], ["chat"][:]), None)
  assert_eq(subprotocol([][:], ["chat"][:]), None)
  assert_eq(subprotocol(["chat"][:], [][:]), None)
}

///|
test "a server reads the key and the subprotocols a client offered" {
  let headers = [
    ("Host", "example.com"),
    ("Upgrade", "websocket"),
    ("Connection", "Upgrade"),
    ("Sec-WebSocket-Key", sample),
    ("Sec-WebSocket-Version", "13"),
    ("Sec-WebSocket-Protocol", "chat, superchat"),
  ]
  let (got, offered) = read(headers[:])
  assert_eq(got, sample)
  assert_eq(offered, ["chat", "superchat"])
  // Names are matched without regard to case, and a proxy may have added to Connection.
  let odd = [
    ("UPGRADE", "WebSocket"),
    ("connection", "keep-alive, Upgrade"),
    ("sec-websocket-key", " " + sample + " "),
    ("Sec-Websocket-Version", "13"),
  ]
  let (got, offered) = read(odd[:])
  assert_eq(got, sample)
  assert_eq(offered, [])
}

///|
test "a request that is not a WebSocket upgrade is refused with the reason" {
  let base = [
    ("Upgrade", "websocket"),
    ("Connection", "Upgrade"),
    ("Sec-WebSocket-Key", sample),
    ("Sec-WebSocket-Version", "13"),
  ]
  assert_eq(read(base[:]) is (_, _), true)
  assert_eq(refused([("Connection", "Upgrade")][:]) is NotAnUpgrade(_), true)
  assert_eq(
    refused([("Upgrade", "h2c"), ("Connection", "Upgrade")][:])
    is NotAnUpgrade(_),
    true,
  )
  assert_eq(refused([("Upgrade", "websocket")][:]) is NotAnUpgrade(_), true)
  assert_eq(
    refused([("Upgrade", "websocket"), ("Connection", "close")][:])
    is NotAnUpgrade(_),
    true,
  )
}

///|
test "only version 13 is accepted, which is what §4.4 asks a server to answer" {
  let of = (v : String) => {
    [
      ("Upgrade", "websocket"),
      ("Connection", "Upgrade"),
      ("Sec-WebSocket-Key", sample),
      ("Sec-WebSocket-Version", v),
    ]
  }
  assert_eq(read(of("13")[:]) is (_, _), true)
  assert_eq(refused(of("8")[:]), Version(got="8"))
  assert_eq(refused(of("")[:]), Version(got=""))
  // Absent altogether.
  let without = [
    ("Upgrade", "websocket"),
    ("Connection", "Upgrade"),
    ("Sec-WebSocket-Key", sample),
  ]
  assert_eq(refused(without[:]), Version(got=""))
}

///|
test "a key that is not sixteen bytes of base64 is refused" {
  let of = (k : String) => {
    [
      ("Upgrade", "websocket"),
      ("Connection", "Upgrade"),
      ("Sec-WebSocket-Key", k),
      ("Sec-WebSocket-Version", "13"),
    ]
  }
  assert_eq(refused(of("not base64!")[:]) is Key(_), true)
  // Well-formed base64 of the wrong length.
  assert_eq(refused(of("aGVsbG8=")[:]) is Key(_), true)
  let missing = [
    ("Upgrade", "websocket"),
    ("Connection", "Upgrade"),
    ("Sec-WebSocket-Version", "13"),
  ]
  assert_eq(refused(missing[:]) is Key(_), true)
}

///|
/// What reading these headers refuses with.
fn refused(headers : ArrayView[(String, String)]) -> Refused {
  let mut out : Refused? = None
  try {
    let _ = read(headers)
  } catch {
    e => out = Some(e)
  }
  match out {
    Some(e) => e
    None => abort("these headers should have been refused")
  }
}

///|
test "a client checks the proof, and a wrong one is the case §4.2.2 rules out" {
  let good = [
    ("Upgrade", "websocket"),
    ("Connection", "Upgrade"),
    ("Sec-WebSocket-Accept", proof),
  ]
  check(sample, good[:])
  // A server that echoed the key instead of proving it.
  let echoed = [
    ("Upgrade", "websocket"),
    ("Connection", "Upgrade"),
    ("Sec-WebSocket-Accept", sample),
  ]
  assert_eq(checked(sample, echoed[:]), Proof(want=proof, got=sample))
  // And one that sent no proof at all.
  let none = [("Upgrade", "websocket"), ("Connection", "Upgrade")]
  assert_eq(checked(sample, none[:]), Proof(want=proof, got=""))
  // The request this package writes and the response it writes agree.
  assert_eq(
    @utf8.decode_lossy(response(sample)[:]).contains(
      "Sec-WebSocket-Accept: " + proof,
    ),
    true,
  )
}

///|
/// What checking this response refuses with.
fn checked(key : String, headers : ArrayView[(String, String)]) -> Refused {
  let mut out : Refused? = None
  check(key, headers) catch {
    e => out = Some(e)
  }
  match out {
    Some(e) => e
    None => abort("this response should have been refused")
  }
}
