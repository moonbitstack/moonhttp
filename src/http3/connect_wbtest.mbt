// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9220: the setting that enables extended CONNECT over HTTP/3, the request a
// client sends for a WebSocket, the pseudo-header rules such a request must keep,
// and the verdicts a server gives on one.

///|
fn has_pair(
  pairs : Array[(UInt64, UInt64)],
  id : UInt64,
  value : UInt64,
) -> Bool {
  for pair in pairs {
    if pair.0 == id && pair.1 == value {
      return true
    }
  }
  false
}

///|
test "http3 settings: the connect switch is 0x08, written only when on" {
  assert_eq(enable_connect, 0x08UL)
  let on = Settings::new(4096UL, 16384UL, 100UL, enable_connect_protocol=true)
  assert_eq(has_pair(on.pairs(), enable_connect, 1UL), true)
  assert_eq(on.connect_protocol(), true)
  // Turning it off says nothing: 0 is the registry default, so the three QPACK
  // values are all a settings frame carries.
  let off = Settings::new(4096UL, 16384UL, 100UL)
  assert_eq(off.pairs().length(), 3)
  assert_eq(off.connect_protocol(), false)
}

///|
test "http3 settings: the connect switch round-trips through the control stream" {
  let mine = Settings::new(0UL, 0UL, 0UL, enable_connect_protocol=true)
  let back = match read_control(control(mine.pairs())[:]) {
    Some(s) => s
    None => abort("expected a control stream with SETTINGS")
  }
  assert_eq(back.connect_protocol(), true)
}

///|
test "http3 websocket: the client's extended CONNECT carries the five pseudo-headers" {
  let wire = websocket_request("https", "example.com", "/chat", [
    @header.Header::of("sec-websocket-version", "13"),
    @header.Header::of("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
  ])
  let req = match read_request(wire) {
    Some(r) => r
    None => abort("expected an extended CONNECT")
  }
  assert_eq(req.meth, "CONNECT")
  assert_eq(req.protocol, "websocket")
  assert_eq(req.scheme, "https")
  assert_eq(req.authority, "example.com")
  assert_eq(req.path, "/chat")
  // The pseudo-headers are pulled out; the RFC 6455 fields stay as ordinary ones.
  assert_eq(req.headers.length(), 2)
  assert_eq(is_websocket(req), true)
}

///|
test "http3 websocket: a classic CONNECT names only an authority" {
  let wire = message(
    [
      @header.Header::of(":method", "CONNECT"),
      @header.Header::of(":authority", "proxy.example:443"),
    ],
    b"",
  )
  let req = match read_request(wire) {
    Some(r) => r
    None => abort("expected a classic CONNECT")
  }
  assert_eq(req.protocol, "")
  assert_eq(req.authority, "proxy.example:443")
  assert_eq(req.path, "")
  assert_eq(is_websocket(req), false)
}

///|
test "http3 websocket: a CONNECT with :scheme and :path but no :protocol is malformed" {
  let wire = message(
    [
      @header.Header::of(":method", "CONNECT"),
      @header.Header::of(":scheme", "https"),
      @header.Header::of(":authority", "example.com"),
      @header.Header::of(":path", "/x"),
    ],
    b"",
  )
  let parsed = match read_request(wire) {
    Some(_) => true
    None => false
  }
  assert_eq(parsed, false)
}

///|
test "http3 websocket: :protocol on a request that is not CONNECT is malformed" {
  let wire = message(
    [
      @header.Header::of(":method", "GET"),
      @header.Header::of(":scheme", "https"),
      @header.Header::of(":authority", "example.com"),
      @header.Header::of(":path", "/x"),
      @header.Header::of(":protocol", "websocket"),
    ],
    b"",
  )
  let parsed = match read_request(wire) {
    Some(_) => true
    None => false
  }
  assert_eq(parsed, false)
}

///|
test "http3 websocket: an extended CONNECT without :path is malformed" {
  let wire = message(
    [
      @header.Header::of(":method", "CONNECT"),
      @header.Header::of(":protocol", "websocket"),
      @header.Header::of(":scheme", "https"),
      @header.Header::of(":authority", "example.com"),
    ],
    b"",
  )
  let parsed = match read_request(wire) {
    Some(_) => true
    None => false
  }
  assert_eq(parsed, false)
}

///|
/// The request an extended CONNECT parses to, for the verdict tests below.
fn upgrade_request(protocol : String) -> Request {
  Request::{
    meth: "CONNECT",
    scheme: "https",
    authority: "example.com",
    path: "/chat",
    protocol,
    headers: [],
    body: b"",
  }
}

///|
test "http3 websocket: a server that enabled the method accepts a websocket" {
  let settings = Settings::new(0UL, 0UL, 0UL, enable_connect_protocol=true)
  let req = upgrade_request("websocket")
  assert_eq(Upgrade::of(req, settings~), Accept)
  let resp = websocket_response(req, settings~)
  assert_eq(resp.status, "200")
}

///|
test "http3 websocket: an unknown :protocol is answered 501" {
  let settings = Settings::new(0UL, 0UL, 0UL, enable_connect_protocol=true)
  let req = upgrade_request("moonchat")
  assert_eq(Upgrade::of(req, settings~), Unsupported("moonchat"))
  assert_eq(websocket_response(req, settings~).status, "501")
}

///|
test "http3 websocket: a :protocol before the setting is refused" {
  let settings = Settings::new(0UL, 0UL, 0UL) // switch off
  let req = upgrade_request("websocket")
  match Upgrade::of(req, settings~) {
    Refused(_) => ()
    _ => abort("expected a refusal")
  }
  assert_eq(websocket_response(req, settings~).status, "400")
}

///|
test "http3 websocket: a plain CONNECT is not an upgrade" {
  let settings = Settings::new(0UL, 0UL, 0UL, enable_connect_protocol=true)
  let req = Request::{
    meth: "CONNECT",
    scheme: "",
    authority: "proxy.example:443",
    path: "",
    protocol: "",
    headers: [],
    body: b"",
  }
  match Upgrade::of(req, settings~) {
    Refused(_) => ()
    _ => abort("expected a refusal")
  }
}
