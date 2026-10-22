// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Text as the octets a socket would carry.
fn raw(s : StringView) -> Bytes {
  let buf = Buffer()
  for i = 0; i < s.length(); i = i + 1 {
    buf.write_byte((s[i].to_int() & 0xff).to_byte())
  }
  buf.to_bytes()
}

///|
fn text(b : BytesView) -> String {
  let out = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    out.write_char(b[i].to_int().unsafe_to_char())
  }
  out.to_string()
}

///|
fn show(e : @http1.Event) -> String {
  match e {
    Request(r) => "request \{r.verb} \{r.target}"
    Response(r) => "response \{r.status}"
    Informational(r) => "informational \{r.status}"
    Data(d) => "data \{text(d)}"
    End([]) => "end"
    End(t) =>
      "end " + t.map(f => text(f.name) + ": " + text(f.value)).join(", ")
    NeedData => "need data"
    Paused => "paused"
    Closed => "closed"
  }
}

///|
/// Every event the connection gives now, up to and including the first that
/// waits on something: more octets, the next exchange, or the close.
fn drain(c : @http1.Conn) -> String raise @http1.Refused {
  let out = []
  for ;; {
    let e = c.next()
    out.push(show(e))
    if e is (NeedData | Paused | Closed) {
      return out.join("\n")
    }
  }
}

///|
/// A whole response with a sized body, as the octets the connection writes.
fn answer(c : @http1.Conn, body : String) -> String raise @http1.Refused {
  let head = c.send(
    Response(@http1.Response::of(200, body=Sized(body.length()))),
  )
  let data = c.send(Data(raw(body)))
  let end = c.send(End([]))
  text(head) + text(data) + text(end)
}

///|
/// The refusal `f` raises, as text, or `none`.
fn refused(f : () -> Unit raise @http1.Refused) -> String {
  try f() catch {
    e => e.to_string()
  } noraise {
    _ => "none"
  }
}

///|
test "a request, its response, and the next on the same connection" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
  inspect(
    drain(c),
    content=(
      #|request GET /a
      #|end
      #|need data
    ),
  )
  assert_eq(c.theirs(), Done)
  assert_eq(c.ours(), SendResponse)
  inspect(
    answer(c, "hi"),
    content="HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi",
  )
  assert_eq(c.ours(), Done)
  c.start_next()
  assert_eq(c.ours(), Idle)
  assert_eq(c.theirs(), Idle)
  c.receive(raw("GET /b HTTP/1.1\r\nHost: x\r\n\r\n"))
  inspect(
    drain(c),
    content=(
      #|request GET /b
      #|end
      #|need data
    ),
  )
}

///|
test "a head that arrives an octet at a time is read once it is whole" {
  let wire = "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n"
  let c = @http1.Conn::new(Server)
  let seen = []
  for i = 0; i < wire.length(); i = i + 1 {
    c.receive(raw(wire[i:i + 1]))
    for e in drain(c).split("\n") {
      if e != "need data" {
        seen.push(e)
      }
    }
  }
  inspect(
    seen.join("\n"),
    content=(
      #|request GET /slow
      #|end
    ),
  )
}

///|
test "a pipelined request waits for the exchange before it" {
  let c = @http1.Conn::new(Server)
  c.receive(
    raw("GET /1 HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n"),
  )
  inspect(
    drain(c),
    content=(
      #|request GET /1
      #|end
      #|paused
    ),
  )
  // Still paused however often it is asked, until the exchange is over.
  inspect(
    drain(c),
    content=(
      #|paused
    ),
  )
  let _ = answer(c, "one")
  c.start_next()
  inspect(
    drain(c),
    content=(
      #|request GET /2
      #|end
      #|need data
    ),
  )
}

///|
test "a chunked request body comes out as it arrives, trailers and all" {
  let wire = "POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nx-sum: 9\r\n\r\n"
  let whole = @http1.Conn::new(Server)
  whole.receive(raw(wire))
  inspect(
    drain(whole),
    content=(
      #|request POST /u
      #|data hello
      #|data  world
      #|end x-sum: 9
      #|need data
    ),
  )
  // The same octets one at a time give the same body and the same trailers.
  let c = @http1.Conn::new(Server)
  let body = StringBuilder()
  let rest = []
  for i = 0; i < wire.length(); i = i + 1 {
    c.receive(raw(wire[i:i + 1]))
    for ;; {
      match c.next() {
        Data(d) => body.write_string(text(d))
        NeedData => break
        e => rest.push(show(e))
      }
    }
  }
  inspect(body, content="hello world")
  inspect(
    rest.join("\n"),
    content=(
      #|request POST /u
      #|end x-sum: 9
    ),
  )
}

///|
test "a sized request body stops at its length, and the rest is the next request" {
  let c = @http1.Conn::new(Server)
  c.receive(
    raw(
      "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET /q HTTP/1.1\r\nHost: x\r\n\r\n",
    ),
  )
  inspect(
    drain(c),
    content=(
      #|request POST /p
      #|data abc
      #|end
      #|paused
    ),
  )
  let _ = answer(c, "")
  c.start_next()
  inspect(
    drain(c),
    content=(
      #|request GET /q
      #|end
      #|need data
    ),
  )
}

///|
test "a body of unknown length is chunked to HTTP/1.1" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(c)
  let head = c.send(Response(@http1.Response::of(200, body=Chunked)))
  inspect(
    text(head),
    content="HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
  )
  inspect(text(c.send(Data(b"ab"))), content="2\r\nab\r\n")
  // An empty piece is not the last chunk.
  inspect(text(c.send(Data(b""))), content="")
  inspect(text(c.send(End([]))), content="0\r\n\r\n")
  assert_eq(c.ours(), Done)
}

///|
test "a chunked response carries trailer fields" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(c)
  let _ = c.send(Response(@http1.Response::of(200, body=Chunked)))
  let end = c.send(End([@header.Header::of("grpc-status", "0")]))
  inspect(text(end), content="0\r\ngrpc-status: 0\r\n\r\n")
}

///|
test "a body of unknown length runs to the close for HTTP/1.0" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.0\r\n\r\n"))
  inspect(
    drain(c),
    content=(
      #|request GET /
      #|end
      #|need data
    ),
  )
  let head = c.send(Response(@http1.Response::of(200, body=Chunked)))
  inspect(text(head), content="HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n")
  inspect(text(c.send(Data(b"part1"))), content="part1")
  inspect(text(c.send(End([]))), content="")
  assert_eq(c.ours(), MustClose)
  assert_eq(c.theirs(), MustClose)
  inspect(
    refused(() => c.start_next()),
    content="Order(a new exchange before both sides are done)",
  )
}

///|
test "an HTTP/1.0 client that asks to keep the connection is told it is kept" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"))
  let _ = drain(c)
  inspect(
    answer(c, "hi"),
    content="HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nhi",
  )
  c.start_next()
}

///|
test "a client that says close is answered with close, and the connection ends" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
  let _ = drain(c)
  inspect(
    answer(c, "hi"),
    content="HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi",
  )
  assert_eq(c.ours(), MustClose)
}

///|
test "a server that says close keeps the other connection options" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
  let _ = drain(c)
  let head = c.send(
    Response(
      @http1.Response::of(204, fields=[
        @header.Header::of("connection", "keep-alive, x-trace"),
      ]),
    ),
  )
  inspect(
    text(head),
    content="HTTP/1.1 204 No Content\r\nconnection: x-trace, close\r\n\r\n",
  )
}

///|
test "a response to HEAD keeps a GET's fields and drops the body" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(c)
  inspect(
    answer(c, "hi"),
    content="HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n",
  )
  c.start_next()
  // Of unknown length, it says chunked as a GET's would, with no last chunk.
  c.receive(raw("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(c)
  let head = c.send(Response(@http1.Response::of(200, body=Chunked)))
  inspect(
    text(head),
    content="HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
  )
  inspect(text(c.send(Data(b"hi"))), content="")
  inspect(text(c.send(End([]))), content="")
  assert_eq(c.ours(), Done)
}

///|
test "204 and 304 may not carry a body" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(c)
  let _ = c.send(Response(@http1.Response::of(304)))
  inspect(
    refused(() => ignore(c.send(Data(b"x")))),
    content="Order(more body than the message declared)",
  )
  assert_eq(c.ours(), Error)
}

///|
test "100-continue: the client is told to send, then sends" {
  let c = @http1.Conn::new(Server)
  c.receive(
    raw(
      "POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n",
    ),
  )
  guard c.next() is Request(r) else { fail("a request comes first") }
  assert_true(r.expects)
  inspect(
    drain(c),
    content=(
      #|need data
    ),
  )
  let go = c.send(Informational(@http1.Response::of(100)))
  assert_eq(go, @http1.continue_)
  assert_eq(c.ours(), SendResponse)
  c.receive(raw("ping"))
  inspect(
    drain(c),
    content=(
      #|data ping
      #|end
      #|need data
    ),
  )
}

///|
test "an upgrade switches both sides, and what came after the head is handed on" {
  let c = @http1.Conn::new(Server)
  c.receive(
    raw(
      "GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nframe",
    ),
  )
  inspect(
    drain(c),
    content=(
      #|request GET /chat
      #|end
      #|paused
    ),
  )
  assert_eq(c.theirs(), MightSwitch)
  let head = c.send(
    Informational(
      @http1.Response::of(101, fields=[
        @header.Header::of("upgrade", "websocket"),
        @header.Header::of("connection", "Upgrade"),
      ]),
    ),
  )
  inspect(
    text(head),
    content="HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n",
  )
  assert_eq(c.ours(), Switched)
  assert_eq(c.theirs(), Switched)
  inspect(
    drain(c),
    content=(
      #|paused
    ),
  )
  inspect(text(c.trailing()), content="frame")
}

///|
test "an upgrade the server declines leaves an ordinary exchange" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\n\r\n"))
  let _ = drain(c)
  assert_eq(c.theirs(), MightSwitch)
  let _ = answer(c, "no")
  assert_eq(c.theirs(), Done)
  c.start_next()
}

///|
test "a 101 to a request that did not ask is refused" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(c)
  inspect(
    refused(() => ignore(c.send(Informational(@http1.Response::of(101))))),
    content="Order(a 101 to a request that did not ask to upgrade)",
  )
}

///|
test "a peer that leaves partway through a body is refused, and may still be answered" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabcd"))
  inspect(
    drain(c),
    content=(
      #|request POST /
      #|data abcd
      #|need data
    ),
  )
  c.receive(b"")
  inspect(
    refused(() => ignore(c.next())),
    content="Malformed(the peer closed partway through a message)",
  )
  assert_eq(c.theirs(), Error)
  inspect(
    answer(c, ""),
    content="HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
  )
  assert_eq(c.ours(), MustClose)
}

///|
test "a peer that leaves between requests is a close, not a fault" {
  let fresh = @http1.Conn::new(Server)
  fresh.receive(b"")
  inspect(
    drain(fresh),
    content=(
      #|closed
    ),
  )
  assert_eq(fresh.ours(), MustClose)
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(c)
  let _ = answer(c, "hi")
  c.receive(b"")
  inspect(
    drain(c),
    content=(
      #|closed
    ),
  )
  assert_eq(c.ours(), MustClose)
  inspect(
    refused(() => c.receive(b"late")),
    content="Order(octets received after the peer closed)",
  )
}

///|
test "a head that does not read is refused with its status and answered from idle" {
  let c = @http1.Conn::new(Server)
  c.receive(raw("GET / HTTP/1.1\r\n\r\n"))
  let status = try {
    let _ = c.next()
    0
  } catch {
    e => e.status()
  } noraise {
    _ => 0
  }
  assert_eq(status, 400)
  assert_eq(c.ours(), Idle)
  let head = c.send(Response(@http1.Response::of(400)))
  inspect(
    text(head),
    content="HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
  )
  inspect(
    refused(() => ignore(c.next())),
    content="Order(reading from a peer whose stream already failed)",
  )
}

///|
test "the reader's checks still hold inside a connection" {
  let refusal = (wire : String) => {
    let c = @http1.Conn::new(Server)
    c.receive(raw(wire))
    refused(() => ignore(drain(c)))
  }
  inspect(
    refusal(
      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
    ),
    content="Smuggled(both a Content-Length and a chunked Transfer-Encoding)",
  )
  inspect(
    refusal("GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n"),
    content="Malformed(more than one Host field)",
  )
  // HTTP/1.0 needs no Host.
  inspect(refusal("GET / HTTP/1.0\r\n\r\n"), content="none")
  inspect(
    refusal(
      "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX",
    ),
    content="Malformed(a chunk not terminated by a break)",
  )
  inspect(
    refusal(
      "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\nGET / HTTP/1.1\r\n",
    ),
    content="Malformed(octets after the last message)",
  )
}

///|
test "what is held before a message completes is bounded by the head limit" {
  let small = @http1.Limits::new(head=64)
  let c = @http1.Conn::new(Server, limits=small)
  c.receive(raw("GET /" + "a".repeat(80)))
  inspect(refused(() => ignore(c.next())), content="Exceeded(limit=64, got=85)")
  // A chunk-size line that never ends is held to the same bound.
  let d = @http1.Conn::new(Server, limits=small)
  d.receive(
    raw("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"),
  )
  let _ = drain(d)
  d.receive(raw("1;" + "x".repeat(70)))
  inspect(refused(() => ignore(d.next())), content="Exceeded(limit=64, got=72)")
  // A body is not: it is handed over as it comes.
  let e = @http1.Conn::new(Server, limits=small)
  e.receive(raw("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n"))
  let _ = drain(e)
  e.receive(raw("b".repeat(100)))
  assert_true(drain(e).has_suffix("\nend\nneed data"))
}

///|
test "events out of order are this side's fault" {
  let c = @http1.Conn::new(Server)
  inspect(
    refused(() => ignore(c.send(Data(b"x")))),
    content="Order(body data out of order)",
  )
  assert_eq(c.ours(), Error)
  inspect(
    refused(() => ignore(c.send(End([])))),
    content="Order(sending after this side already failed)",
  )
  let d = @http1.Conn::new(Server)
  inspect(
    refused(() => ignore(d.send(Request(@http1.Request::of("GET", "/"))))),
    content="Order(a server does not send requests)",
  )
  let e = @http1.Conn::new(Server)
  e.receive(raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(e)
  let _ = e.send(Response(@http1.Response::of(200, body=Sized(1))))
  inspect(
    refused(() => ignore(e.send(Data(b"xy")))),
    content="Order(more body than the message declared)",
  )
  let f = @http1.Conn::new(Server)
  f.receive(raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
  let _ = drain(f)
  let _ = f.send(Response(@http1.Response::of(200, body=Sized(3))))
  let _ = f.send(Data(b"x"))
  inspect(
    refused(() => ignore(f.send(End([])))),
    content="Order(a body that ended short of its Content-Length)",
  )
  inspect(
    refused(() => ignore(f.send(NeedData))),
    content="Order(sending after this side already failed)",
  )
}

///|
test "a client sends a request and reads a chunked response" {
  let c = @http1.Conn::new(Client)
  let out = c.send(Request(@http1.Request::of("GET", "/", host="x")))
  inspect(text(out), content="GET / HTTP/1.1\r\nhost: x\r\n\r\n")
  inspect(text(c.send(End([]))), content="")
  assert_eq(c.theirs(), SendResponse)
  c.receive(
    raw(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    ),
  )
  inspect(
    drain(c),
    content=(
      #|response 200
      #|data abc
      #|end
      #|need data
    ),
  )
  c.start_next()
}

///|
test "a client sends a body by its own fields" {
  let c = @http1.Conn::new(Client)
  let _ = c.send(
    Request(@http1.Request::of("POST", "/", host="x", body=Sized(2))),
  )
  inspect(text(c.send(Data(b"hi"))), content="hi")
  let _ = c.send(End([]))
  let d = @http1.Conn::new(Client)
  let _ = d.send(
    Request(@http1.Request::of("POST", "/", host="x", body=Chunked)),
  )
  inspect(text(d.send(Data(b"hi"))), content="2\r\nhi\r\n")
  inspect(text(d.send(End([]))), content="0\r\n\r\n")
}

///|
test "a client reads a response that runs to the close" {
  let c = @http1.Conn::new(Client)
  let _ = c.send(Request(@http1.Request::of("GET", "/", host="x")))
  let _ = c.send(End([]))
  c.receive(raw("HTTP/1.1 200 OK\r\n\r\nabc"))
  inspect(
    drain(c),
    content=(
      #|response 200
      #|data abc
      #|need data
    ),
  )
  c.receive(b"")
  inspect(
    drain(c),
    content=(
      #|end
      #|closed
    ),
  )
  assert_eq(c.ours(), MustClose)
}

///|
test "a client reads no body in a response to HEAD" {
  let c = @http1.Conn::new(Client)
  let _ = c.send(Request(@http1.Request::of("HEAD", "/", host="x")))
  let _ = c.send(End([]))
  c.receive(raw("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"))
  inspect(
    drain(c),
    content=(
      #|response 200
      #|end
      #|need data
    ),
  )
}

///|
test "a client reads 100 Continue, and a 101 it asked for" {
  let c = @http1.Conn::new(Client)
  let _ = c.send(
    Request(
      @http1.Request::of("POST", "/", host="x", body=Sized(2), fields=[
        @header.Header::of("expect", "100-continue"),
      ]),
    ),
  )
  c.receive(raw("HTTP/1.1 100 Continue\r\n\r\n"))
  inspect(
    drain(c),
    content=(
      #|informational 100
      #|need data
    ),
  )
  let up = @http1.Conn::new(Client)
  let _ = up.send(
    Request(
      @http1.Request::of("GET", "/chat", host="x", fields=[
        @header.Header::of("upgrade", "websocket"),
      ]),
    ),
  )
  let _ = up.send(End([]))
  up.receive(
    raw("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nframe"),
  )
  inspect(
    drain(up),
    content=(
      #|informational 101
      #|paused
    ),
  )
  assert_eq(up.ours(), Switched)
  inspect(text(up.trailing()), content="frame")
  // A 101 nobody asked for is the server's fault.
  let plain = @http1.Conn::new(Client)
  let _ = plain.send(Request(@http1.Request::of("GET", "/", host="x")))
  let _ = plain.send(End([]))
  plain.receive(raw("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
  inspect(
    refused(() => ignore(plain.next())),
    content="Malformed(a 101 to a request that did not ask to upgrade)",
  )
}

///|
test "a server that closes before answering is refused" {
  let c = @http1.Conn::new(Client)
  let _ = c.send(Request(@http1.Request::of("GET", "/", host="x")))
  let _ = c.send(End([]))
  c.receive(b"")
  inspect(
    refused(() => ignore(c.next())),
    content="Malformed(the peer closed partway through a message)",
  )
}
