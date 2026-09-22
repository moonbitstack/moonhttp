// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Text as the octets a socket would carry.
fn raw(s : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < s.length(); i = i + 1 {
    buf.write_byte((s[i].to_int() & 0xff).to_byte())
  }
  buf.to_bytes()
}

///|
test "a request line and its fields" {
  let (r, used) = request(
    raw("GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")[:],
  )
  assert_eq(r.verb, "GET")
  assert_eq(r.target, "/path?q=1")
  assert_eq(r.version, "HTTP/1.1")
  assert_eq(r.fields.length(), 2)
  // Names are lowercased, because HTTP says they are case-insensitive.
  assert_eq(r.field("host"), Some(b"example.com"))
  assert_eq(r.field("HOST"), None)
  assert_eq(r.body, Empty)
  assert_eq(r.keep_alive, true)
  // The count is the head only; a body would begin here.
  assert_eq(used, 58)
}

///|
test "a head that has not all arrived is partial, not malformed" {
  let whole = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
  for cut = 1; cut < whole.length(); cut = cut + 1 {
    let part = raw(whole[0:cut].to_owned())
    let out = try {
      let _ = request(part[:])
      "read"
    } catch {
      Partial => "partial"
      e => "refused: \{e}"
    }
    assert_eq(out, "partial")
  }
  // And the whole thing reads.
  let _ = request(raw(whole)[:])
}

///|
test "the body framing is read once and carried" {
  let sized = request(raw("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n")[:]).0
  assert_eq(sized.body, Sized(5))
  let none = request(raw("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")[:]).0
  assert_eq(none.body, Empty)
  let chunked = request(
      raw("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")[:],
    ).0
  assert_eq(chunked.body, Chunked)
  // A request with neither has no body; it may not run to the close.
  let bare = request(raw("GET / HTTP/1.1\r\n\r\n")[:]).0
  assert_eq(bare.body, Empty)
}

///|
test "the ways a request is smuggled are refused rather than resolved" {
  // Both a length and a chunked coding: §6.1 says ignore the length, but two
  // parsers disagreeing about which to believe is the whole attack.
  assert_eq(
    smuggled(
      "POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
    ),
    true,
  )
  // Two different lengths.
  assert_eq(
    smuggled(
      "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
    ),
    true,
  )
  // A length that is not a number, including the forms that look like one.
  assert_eq(smuggled("POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\n"), true)
  assert_eq(smuggled("POST / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n"), true)
  assert_eq(
    smuggled("POST / HTTP/1.1\r\nContent-Length: 5 \r\n\r\n") == false,
    true,
  )
  // Whitespace before the colon.
  assert_eq(smuggled("GET / HTTP/1.1\r\nHost : x\r\n\r\n"), true)
  // An obsolete folded line.
  assert_eq(smuggled("GET / HTTP/1.1\r\nHost: x\r\n  more\r\n\r\n"), true)
  // A transfer coding that does not delimit.
  assert_eq(
    smuggled("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n"),
    true,
  )
  // Two identical lengths agree, so there is nothing to disagree about.
  assert_eq(
    smuggled(
      "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
    ),
    false,
  )
}

///|
test "a malformed line is refused with what was wrong" {
  assert_eq(refused("GET\r\n\r\n"), true)
  assert_eq(refused("GET /\r\n\r\n"), true)
  assert_eq(refused("GET  HTTP/1.1\r\n\r\n"), true)
  assert_eq(refused("GET / HTTP/11\r\n\r\n"), true)
  assert_eq(refused("GET / SPDY/1.1\r\n\r\n"), true)
  assert_eq(refused("GE T / HTTP/1.1\r\n\r\n"), true)
  assert_eq(refused("GET / HTTP/1.1\r\n: nothing\r\n\r\n"), true)
}

///|
test "a head past the limit is refused with the status it deserves" {
  let big = StringBuilder()
  big.write_string("GET / HTTP/1.1\r\n")
  for i = 0; i < 200; i = i + 1 {
    big.write_string("x-pad-\{i}: 0123456789\r\n")
  }
  big.write_string("\r\n")
  let src = raw(big.to_string())
  // Too many fields.
  let out = try {
    let _ = request(src[:])
    0
  } catch {
    e => e.status()
  }
  assert_eq(out, 431)
  // And too many octets, checked before the blank line arrives so a peer cannot
  // hold a connection open by never sending one.
  let endless = raw("GET / HTTP/1.1\r\nx: " + "y".repeat(20000))
  let out2 = try {
    let _ = request(endless[:])
    0
  } catch {
    Exceeded(..) => 431
    _ => 0
  }
  assert_eq(out2, 431)
}

///|
test "keep-alive defaults by version, which is where a server hangs" {
  assert_eq(request(raw("GET / HTTP/1.1\r\n\r\n")[:]).0.keep_alive, true)
  assert_eq(request(raw("GET / HTTP/1.0\r\n\r\n")[:]).0.keep_alive, false)
  assert_eq(
    request(raw("GET / HTTP/1.1\r\nConnection: close\r\n\r\n")[:]).0.keep_alive,
    false,
  )
  assert_eq(
    request(raw("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")[:]).0.keep_alive,
    true,
  )
}

///|
test "a request may say it is waiting to be told to send its body" {
  let r = request(
      raw(
        "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
      )[:],
    ).0
  assert_eq(r.expects, true)
  assert_eq(request(raw("POST / HTTP/1.1\r\n\r\n")[:]).0.expects, false)
  assert_eq(continue_, b"HTTP/1.1 100 Continue\r\n\r\n")
}

///|
test "a response's framing depends on the request that asked for it" {
  let head = raw("HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n")
  assert_eq(response(head[:]).0.body, Sized(42))
  // A response to HEAD has no body however its fields read.
  assert_eq(response(head[:], verb="HEAD").0.body, Empty)
  // Nor has a 204 or a 304.
  assert_eq(
    response(raw("HTTP/1.1 204 No Content\r\nContent-Length: 42\r\n\r\n")[:]).0.body,
    Empty,
  )
  assert_eq(response(raw("HTTP/1.1 304 Not Modified\r\n\r\n")[:]).0.body, Empty)
  // A response with neither runs to the close, which a request may never do.
  assert_eq(response(raw("HTTP/1.1 200 OK\r\n\r\n")[:]).0.body, Closed)
}

///|
test "a status line reads, reason phrase or not" {
  let (r, _) = response(raw("HTTP/1.1 404 Not Found\r\n\r\n")[:])
  assert_eq(r.status, 404)
  assert_eq(r.reason, "Not Found")
  assert_eq(r.version, "HTTP/1.1")
  // §4 says a client must not act on the phrase, so an empty one is legal.
  assert_eq(response(raw("HTTP/1.1 200 \r\n\r\n")[:]).0.reason, "")
  assert_eq(response(raw("HTTP/1.1 200\r\n\r\n")[:]).0.status, 200)
  assert_eq(refused_response("HTTP/1.1 20 OK\r\n\r\n"), true)
  assert_eq(refused_response("HTTP/1.1 abc OK\r\n\r\n"), true)
}

///|
test "a bare newline ends a line too, which is what a hand-written client sends" {
  let (r, _) = request(raw("GET / HTTP/1.1\nHost: x\n\n")[:])
  assert_eq(r.verb, "GET")
  assert_eq(r.field("host"), Some(b"x"))
}

///|
test "what is written reads back as what it was" {
  let out = Request::of("POST", "/things", host="example.com", body=Sized(11), fields=[
    @header.Header::of("content-type", "text/plain"),
  ])
  let wire = out.encode()
  let (back, _) = request(wire[:])
  assert_eq(back.verb, "POST")
  assert_eq(back.target, "/things")
  assert_eq(back.field("host"), Some(b"example.com"))
  assert_eq(back.field("content-type"), Some(b"text/plain"))
  assert_eq(back.body, Sized(11))
}

///|
test "a response by name works its own framing out" {
  // A sized body says how long it is.
  let sized = Response::of(200, body=Sized(5))
  assert_eq(response(sized.encode()[:]).0.body, Sized(5))
  // An empty one says zero, so a client does not wait for a body that never comes.
  let empty = Response::of(200)
  assert_eq(empty.field("content-length"), Some(b"0"))
  // Except where a body is not allowed at all.
  assert_eq(Response::of(204).field("content-length"), None)
  assert_eq(Response::of(304).field("content-length"), None)
  // A chunked one says so.
  assert_eq(
    Response::of(200, body=Chunked).field("transfer-encoding"),
    Some(b"chunked"),
  )
  // And one that runs to the close says that.
  assert_eq(Response::of(200, body=Closed).field("connection"), Some(b"close"))
  // The phrase comes free.
  assert_eq(Response::of(404).reason, "Not Found")
  assert_eq(Response::of(599).reason, "Unknown")
}

///|
test "a chunked body is written and read back" {
  let buf = Buffer()
  buf.write_bytes(chunk(b"hello"[:]))
  buf.write_bytes(chunk(b" world"[:]))
  buf.write_bytes(last_chunk())
  let wire = buf.to_bytes()
  // The size is hexadecimal, which is the one thing a hand-rolled writer gets wrong.
  assert_eq(chunk(b"hello"[:]), b"5\r\nhello\r\n")
  assert_eq(chunk(b"0123456789abcdef"[:])[0], b'1')
  assert_eq(chunk(b"0123456789abcdef"[:])[1], b'0')
  let body = Buffer()
  let mut at = 0
  for ;; {
    match chunked(wire[at:]) {
      Piece(part, used) => {
        body.write_bytes(part)
        at = at + used
      }
      Done(trailers, used) => {
        at = at + used
        assert_eq(trailers.length(), 0)
        break
      }
    }
  }
  assert_eq(body.to_bytes(), b"hello world")
  assert_eq(at, wire.length())
}

///|
test "a chunked body carries trailer fields, and an extension is ignored" {
  let buf = Buffer()
  buf.write_bytes(raw("5;half=true\r\nhello\r\n"))
  buf.write_bytes(last_chunk(trailers=[@header.Header::of("x-sum", "42")]))
  let wire = buf.to_bytes()
  match chunked(wire[:]) {
    Piece(part, used) => {
      assert_eq(part, b"hello")
      match chunked(wire[used:]) {
        Done(trailers, _) => {
          assert_eq(trailers.length(), 1)
          assert_eq(trailers[0].ascii().0, "x-sum")
          assert_eq(trailers[0].ascii().1, "42")
        }
        _ => fail("the body ended")
      }
    }
    _ => fail("a chunk came first")
  }
}

///|
test "a chunk that has not all arrived is partial" {
  let whole = raw("5\r\nhello\r\n0\r\n\r\n")
  for cut = 1; cut < whole.length(); cut = cut + 1 {
    let out = try {
      match chunked(whole[0:cut]) {
        Piece(_, used) =>
          // The first chunk may be complete before the last one is.
          if used <= cut {
            "read"
          } else {
            "over"
          }
        Done(_, _) => "read"
      }
    } catch {
      Partial => "partial"
      e => "refused: \{e}"
    }
    assert_eq(out == "partial" || out == "read", true)
  }
}

///|
test "a chunk size that is not one is refused" {
  assert_eq(refused_chunk("zz\r\nhello\r\n"), true)
  assert_eq(refused_chunk("\r\nhello\r\n"), true)
  assert_eq(refused_chunk("11111111111111111\r\n"), true)
}

///|
fn refused(src : String) -> Bool {
  try {
    let _ = request(raw(src)[:])
    false
  } catch {
    Partial => false
    _ => true
  }
}

///|
fn refused_response(src : String) -> Bool {
  try {
    let _ = response(raw(src)[:])
    false
  } catch {
    Partial => false
    _ => true
  }
}

///|
fn smuggled(src : String) -> Bool {
  try {
    let _ = request(raw(src)[:])
    false
  } catch {
    Smuggled(_) => true
    _ => false
  }
}

///|
fn refused_chunk(src : String) -> Bool {
  try {
    let _ = chunked(raw(src)[:])
    false
  } catch {
    Partial => false
    _ => true
  }
}
