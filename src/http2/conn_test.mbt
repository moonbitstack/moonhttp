// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn text(b : BytesView) -> String {
  let out = StringBuilder()
  for c in b {
    out.write_char(c.to_int().unsafe_to_char())
  }
  out.to_string()
}

///|
fn h(name : String, value : String) -> @header.Header {
  @header.Header::of(name, value)
}

///|
fn get(path : String) -> Array[@header.Header] {
  [
    h(":method", "GET"),
    h(":scheme", "https"),
    h(":path", path),
    h(":authority", "x"),
  ]
}

///|
fn status(code : String) -> Array[@header.Header] {
  [h(":status", code)]
}

///|
fn listed(fields : Array[@header.Header]) -> String {
  fields.map(f => text(f.name) + "=" + text(f.value)).join(" ")
}

///|
fn show(e : @http2.Event) -> String {
  match e {
    Request(stream~, fields~) => "request \{stream} \{listed(fields)}"
    Response(stream~, fields~) => "response \{stream} \{listed(fields)}"
    Informational(stream~, fields~) =>
      "informational \{stream} \{listed(fields)}"
    Trailers(stream~, fields~) => "trailers \{stream} \{listed(fields)}"
    Data(stream~, data~) =>
      if data.length() > 16 {
        "data \{stream} (\{data.length()} octets)"
      } else {
        "data \{stream} \{text(data)}"
      }
    End(stream~) => "end \{stream}"
    Reset(stream~, code~, remote~) =>
      "reset \{stream} code=\{code}" + (if remote { " remote" } else { "" })
    Pushed(stream~, promised~, fields~) =>
      "pushed \{stream} -> \{promised} \{listed(fields)}"
    WindowUpdated(stream~, delta~) => "window \{stream} +\{delta}"
    Settings(_) => "settings"
    SettingsAcked(_) => "settings acked"
    Ping(_) => "ping"
    PingAcked(_) => "ping acked"
    GoAway(code~, last~, ..) => "goaway code=\{code} last=\{last}"
    NeedData => "need data"
    Closed => "closed"
  }
}

///|
/// Every event the connection gives now, one a line, up to the first `NeedData`.
fn drain(c : @http2.Conn) -> String raise @http2.Refused {
  let out = []
  for ;; {
    match c.next() {
      NeedData => return out.join("\n")
      Closed => {
        out.push("closed")
        return out.join("\n")
      }
      e => out.push(show(e))
    }
  }
}

///|
/// Carry what `a` queued over to `b`.
fn pump(a : @http2.Conn, b : @http2.Conn) -> Unit raise @http2.Refused {
  let octets = a.take()
  if octets.length() > 0 {
    b.receive(octets)
  }
}

///|
/// A client and a server that have exchanged and acknowledged their settings.
fn pair(
  client~ : @http2.Settings = @http2.settings,
  server~ : @http2.Settings = @http2.settings,
) -> (@http2.Conn, @http2.Conn) raise @http2.Refused {
  let c = @http2.Conn::new(Client, settings=client)
  let s = @http2.Conn::new(Server, settings=server)
  pump(c, s)
  let _ = drain(s)
  pump(s, c)
  let _ = drain(c)
  pump(c, s)
  let _ = drain(s)
  (c, s)
}

///|
/// The frames in `octets`, one a line, by type and stream.
fn frames(octets : Bytes) -> String raise @http2.Refused {
  let out = []
  let mut at = 0
  while at < octets.length() {
    let (frame, used) = @http2.decode(octets, offset=at)
    at = at + used
    out.push(
      match frame {
        Data(stream_id~, data~, end_stream~, ..) =>
          "DATA \{stream_id} \{data.length()}" +
          (if end_stream { " END_STREAM" } else { "" })
        Headers(stream_id~, end_stream~, end_headers~, ..) =>
          "HEADERS \{stream_id}" +
          (if end_stream { " END_STREAM" } else { "" }) +
          (if end_headers { " END_HEADERS" } else { "" })
        Continuation(stream_id~, end_headers~, ..) =>
          "CONTINUATION \{stream_id}" +
          (if end_headers { " END_HEADERS" } else { "" })
        RstStream(stream_id~, error_code~) =>
          "RST_STREAM \{stream_id} \{error_code}"
        Settings(params~, ack~) =>
          if ack {
            "SETTINGS ACK"
          } else {
            "SETTINGS " + params.map(p => "\{p.0}=\{p.1}").join(" ")
          }
        Ping(ack~, ..) => if ack { "PING ACK" } else { "PING" }
        GoAway(last_stream_id~, error_code~, debug~) =>
          "GOAWAY \{last_stream_id} \{error_code} \{text(debug)}"
        WindowUpdate(stream_id~, increment~) =>
          "WINDOW_UPDATE \{stream_id} \{increment}"
        PushPromise(stream_id~, promised_id~, ..) =>
          "PUSH_PROMISE \{stream_id} \{promised_id}"
        Priority(stream_id~, ..) => "PRIORITY \{stream_id}"
        Unknown(ftype~, ..) => "UNKNOWN \{ftype}"
      },
    )
  }
  out.join("\n")
}

///|
/// The refusal `f` raises, as text, or `none`.
fn refused(f : () -> Unit raise @http2.Refused) -> String {
  try f() catch {
    e => e.to_string()
  } noraise {
    _ => "none"
  }
}

///|
/// A server that has read the client preface and an empty SETTINGS, ready for
/// hand-made frames.
fn server() -> @http2.Conn raise @http2.Refused {
  let s = @http2.Conn::new(Server)
  let _ = s.take()
  let opening = Buffer()
  opening.write_bytes(@http2.preface)
  opening.write_bytes(@http2.Frame::Settings(params=[], ack=false).encode())
  opening.write_bytes(@http2.Frame::Settings(params=[], ack=true).encode())
  s.receive(opening.to_bytes())
  let _ = drain(s)
  let _ = s.take()
  s
}

///|
/// A HEADERS frame carrying `fields`, compressed by a fresh encoder.
fn headers_frame(
  stream : Int32,
  fields : Array[@header.Header],
  end~ : Bool = false,
) -> Bytes {
  @http2.Frame::Headers(
    stream_id=stream,
    fragment=@hpack.Encoder::new().encode(fields[:]),
    end_stream=end,
    end_headers=true,
    priority=None,
    padding=0,
  ).encode()
}

///|
test "the opening: preface and settings both ways, then both acknowledged" {
  let c = @http2.Conn::new(Client)
  let s = @http2.Conn::new(Server)
  let hello = c.take()
  assert_eq(hello[0:24].to_owned(), @http2.preface)
  inspect(frames(hello[24:].to_owned()), content="SETTINGS 3=100 6=65536")
  s.receive(hello)
  inspect(drain(s), content="settings")
  let back = s.take()
  inspect(
    frames(back),
    content=(
      #|SETTINGS 3=100 6=65536
      #|SETTINGS ACK
    ),
  )
  c.receive(back)
  inspect(
    drain(c),
    content=(
      #|settings
      #|settings acked
    ),
  )
  pump(c, s)
  inspect(drain(s), content="settings acked")
  assert_eq(s.settings(), @http2.settings)
  assert_eq(c.peer_settings(), @http2.settings)
}

///|
test "a request and its response" {
  let (c, s) = pair()
  assert_eq(c.next_stream(), 1)
  c.headers(1, get("/a"), end=true)
  pump(c, s)
  inspect(
    drain(s),
    content=(
      #|request 1 :method=GET :scheme=https :path=/a :authority=x
      #|end 1
    ),
  )
  s.headers(1, [h(":status", "200"), h("content-length", "2")])
  s.data(1, b"hi", end=true)
  inspect(
    frames(s.take()),
    content=(
      #|HEADERS 1 END_HEADERS
      #|DATA 1 2 END_STREAM
    ),
  )
}

///|
test "a whole exchange, body, trailers and all, over two connections" {
  let (c, s) = pair()
  c.headers(1, [
    h(":method", "POST"),
    h(":scheme", "https"),
    h(":path", "/up"),
    h(":authority", "x"),
  ])
  c.data(1, b"abc")
  c.headers(1, [h("x-sum", "6")], end=true)
  pump(c, s)
  inspect(
    drain(s),
    content=(
      #|request 1 :method=POST :scheme=https :path=/up :authority=x
      #|data 1 abc
      #|trailers 1 x-sum=6
      #|end 1
    ),
  )
  s.headers(1, status("100"))
  s.headers(1, status("200"))
  s.data(1, b"ok")
  s.headers(1, [h("grpc-status", "0")], end=true)
  pump(s, c)
  inspect(
    drain(c),
    content=(
      #|informational 1 :status=100
      #|response 1 :status=200
      #|data 1 ok
      #|trailers 1 grpc-status=0
      #|end 1
    ),
  )
  assert_eq(c.window(1), 0)
  assert_eq(s.window(1), 0)
}

///|
test "a declared content-length must match what arrives" {
  let (c, s) = pair()
  c.headers(1, [
    h(":method", "POST"),
    h(":scheme", "https"),
    h(":path", "/"),
    h(":authority", "x"),
    h("content-length", "5"),
  ])
  c.data(1, b"abc", end=true)
  pump(c, s)
  inspect(
    drain(s),
    content=(
      #|request 1 :method=POST :scheme=https :path=/ :authority=x content-length=5
      #|data 1 abc
      #|reset 1 code=1
    ),
  )
  inspect(frames(s.take()), content="RST_STREAM 1 1")
}

///|
test "data waits on the window, and acknowledgement reopens it" {
  let (c, s) = pair(server=@http2.Settings::new(initial_window_size=10))
  c.headers(1, get("/"))
  assert_eq(c.window(1), 10)
  inspect(
    refused(() => c.data(1, b"01234567890")),
    content="Order(more data than the flow-control window)",
  )
  c.data(1, b"0123456789")
  assert_eq(c.window(1), 0)
  pump(c, s)
  inspect(
    drain(s),
    content=(
      #|request 1 :method=GET :scheme=https :path=/ :authority=x
      #|data 1 0123456789
    ),
  )
  s.acknowledge(1, 10)
  // Half the stream window has come back; the connection's is far from half.
  let update = s.take()
  inspect(frames(update), content="WINDOW_UPDATE 1 10")
  c.receive(update)
  inspect(drain(c), content="window 1 +10")
  assert_eq(c.window(1), 10)
  assert_eq(c.window(0), 65525)
}

///|
test "long data and long field blocks are cut to the peer's frame size" {
  let (c, _) = pair()
  // `~` has a thirteen-bit Huffman code, so the block is sent as it is.
  c.headers(1, [..get("/"), h("x-pad", "~".repeat(20000))])
  c.data(1, Bytes::make(40000, b'z'), end=true)
  inspect(
    frames(c.take()),
    content=(
      #|HEADERS 1
      #|CONTINUATION 1 END_HEADERS
      #|DATA 1 16384
      #|DATA 1 16384
      #|DATA 1 7232 END_STREAM
    ),
  )
}

///|
test "a field block in CONTINUATION frames is read as one" {
  let (c, s) = pair()
  c.headers(1, [..get("/"), h("x-pad", "~".repeat(20000))], end=true)
  let octets = c.take()
  assert_true(frames(octets).contains("CONTINUATION 1 END_HEADERS"))
  s.receive(octets)
  let seen = drain(s)
  assert_true(seen.has_prefix("request 1 :method=GET"))
  assert_true(seen.has_suffix("\nend 1"))
}

///|
test "ping is answered, reset is reported" {
  let (c, s) = pair()
  c.ping(b"12345678")
  pump(c, s)
  inspect(drain(s), content="ping")
  pump(s, c)
  inspect(drain(c), content="ping acked")
  c.headers(1, get("/"))
  c.reset(1, code=@http2.error_cancel)
  pump(c, s)
  inspect(
    drain(s),
    content=(
      #|request 1 :method=GET :scheme=https :path=/ :authority=x
      #|reset 1 code=8 remote
    ),
  )
}

///|
test "a server pushes, and the client reads the promise and the response" {
  let (c, s) = pair()
  c.headers(1, get("/page"), end=true)
  pump(c, s)
  let _ = drain(s)
  let promised = s.push(1, get("/style.css"))
  assert_eq(promised, 2)
  s.headers(1, status("200"))
  s.headers(2, status("200"))
  s.data(2, b"css", end=true)
  s.end(1)
  pump(s, c)
  inspect(
    drain(c),
    content=(
      #|pushed 1 -> 2 :method=GET :scheme=https :path=/style.css :authority=x
      #|response 1 :status=200
      #|response 2 :status=200
      #|data 2 css
      #|end 2
      #|end 1
    ),
  )
}

///|
test "a client that turned push off is not pushed to" {
  let (c, s) = pair(client=@http2.Settings::new(enable_push=false))
  c.headers(1, get("/"), end=true)
  pump(c, s)
  let _ = drain(s)
  inspect(
    refused(() => ignore(s.push(1, get("/x")))),
    content="Order(the client has turned push off)",
  )
}

///|
test "after GOAWAY the server takes no new streams and the client opens none" {
  let (c, s) = pair()
  c.headers(1, get("/"), end=true)
  pump(c, s)
  let _ = drain(s)
  s.goaway()
  pump(s, c)
  inspect(drain(c), content="goaway code=0 last=1")
  inspect(
    refused(() => c.headers(3, get("/"))),
    content="Order(a new stream after the server's GOAWAY)",
  )
  // One already in flight past the last stream is ignored.
  s.receive(headers_frame(3, get("/late"), end=true))
  inspect(drain(s), content="")
}

///|
test "settings change mid-connection, and take effect when acknowledged" {
  let (c, s) = pair()
  s.update(@http2.Settings::new(initial_window_size=1000))
  pump(s, c)
  inspect(drain(c), content="settings")
  assert_eq(c.peer_settings().initial_window_size, 1000)
  assert_eq(s.settings().initial_window_size, 65535)
  pump(c, s)
  inspect(drain(s), content="settings acked")
  assert_eq(s.settings().initial_window_size, 1000)
}

///|
test "a smaller header table is honoured with a size update on the next block" {
  let (c, s) = pair(client=@http2.Settings::new(header_table_size=0))
  c.headers(1, get("/"), end=true)
  pump(c, s)
  let _ = drain(s)
  s.headers(1, [h(":status", "200"), h("x-tag", "a")], end=true)
  pump(s, c)
  inspect(
    drain(c),
    content=(
      #|response 1 :status=200 x-tag=a
      #|end 1
    ),
  )
}

///|
test "a field list past the limit resets the stream and keeps the table in step" {
  let (c, s) = pair(server=@http2.Settings::new(max_header_list_size=Some(450)))
  let big = h("x-big", "v".repeat(200))
  c.headers(1, [..get("/"), big, big], end=true)
  pump(c, s)
  inspect(drain(s), content="")
  inspect(frames(s.take()), content="RST_STREAM 1 11")
  // The next request names the big field from the table, and still reads.
  c.headers(3, [..get("/again"), big], end=true)
  pump(c, s)
  inspect(
    drain(s),
    content="request 3 :method=GET :scheme=https :path=/again :authority=x x-big=" +
      "v".repeat(200) +
      "\nend 3",
  )
}

///|
test "streams past the concurrency limit are refused, and may be retried" {
  let s = server()
  s.update(@http2.Settings::new(max_concurrent_streams=Some(1)))
  let _ = s.take()
  s.receive(headers_frame(1, get("/one")))
  let _ = drain(s)
  s.receive(headers_frame(3, get("/two")))
  inspect(drain(s), content="")
  inspect(frames(s.take()), content="RST_STREAM 3 7")
}

///|
test "malformed requests are stream errors" {
  let bad = [
    [h(":method", "GET"), h(":path", "/"), h(":authority", "x")],
    [..get("/"), h("Upper", "x")],
    [..get("/"), h("connection", "close")],
    [..get("/"), h("te", "gzip")],
    [h("x", "1"), ..get("/")],
    [..get("/"), h("x", " padded")],
    [h(":method", "CONNECT"), h(":path", "/"), h(":authority", "x")],
    [..get(""), h(":method", "GET")],
  ]
  for fields in bad {
    let s = server()
    s.receive(headers_frame(1, fields, end=true))
    inspect(drain(s), content="")
    inspect(frames(s.take()), content="RST_STREAM 1 1")
  }
  // CONNECT names only an authority, and extended CONNECT needs the setting.
  let s = server()
  s.receive(
    headers_frame(1, [h(":method", "CONNECT"), h(":authority", "x:443")]),
  )
  inspect(drain(s), content="request 1 :method=CONNECT :authority=x:443")
}

///|
test "connection errors raise, with the GOAWAY queued" {
  let wrong = @http2.Conn::new(Server)
  let _ = wrong.take()
  wrong.receive(b"GET / HTTP/1.1\r\n\r\n")
  inspect(
    refused(() => ignore(wrong.next())),
    content="Connection(code=1, not an HTTP/2 connection preface)",
  )
  inspect(
    frames(wrong.take()),
    content="GOAWAY 0 1 not an HTTP/2 connection preface",
  )
  inspect(
    refused(() => ignore(wrong.next())),
    content="Order(the connection already failed)",
  )
  let first = @http2.Conn::new(Server)
  let opening = Buffer()
  opening.write_bytes(@http2.preface)
  opening.write_bytes(
    @http2.Frame::Ping(payload=b"12345678", ack=false).encode(),
  )
  first.receive(opening.to_bytes())
  inspect(
    refused(() => ignore(first.next())),
    content="Connection(code=1, a first frame that is not SETTINGS)",
  )
  let cases = [
    (
      @http2.Frame::Data(stream_id=1, data=b"x", end_stream=false, padding=0).encode(),
      "Connection(code=1, DATA on an idle stream)",
    ),
    (
      @http2.Frame::WindowUpdate(stream_id=0, increment=0x7FFFFFFF).encode(),
      "Connection(code=3, the connection window past 2^31 - 1)",
    ),
    (
      @http2.Frame::Continuation(stream_id=1, fragment=b"", end_headers=true).encode(),
      "Connection(code=1, a CONTINUATION outside a field block)",
    ),
    (
      @http2.Frame::Settings(params=[(4, -1)], ack=false).encode(),
      "Connection(code=3, SETTINGS_INITIAL_WINDOW_SIZE past 2^31 - 1)",
    ),
    (
      @http2.Frame::RstStream(stream_id=5, error_code=0).encode(),
      "Connection(code=1, RST_STREAM on an idle stream)",
    ),
    (
      @http2.Frame::Unknown(
        ftype=0,
        flags=0,
        stream_id=1,
        payload=Bytes::make(16385, b'x'),
      ).encode(),
      "Connection(code=6, a frame longer than SETTINGS_MAX_FRAME_SIZE)",
    ),
  ]
  for case in cases {
    let s = server()
    s.receive(case.0)
    inspect(refused(() => ignore(s.next())), content=case.1)
  }
  // A field block admits nothing but its CONTINUATION.
  let s = server()
  s.receive(
    @http2.Frame::Headers(
      stream_id=1,
      fragment=b"",
      end_stream=false,
      end_headers=false,
      priority=None,
      padding=0,
    ).encode(),
  )
  s.receive(@http2.Frame::Ping(payload=b"12345678", ack=false).encode())
  inspect(
    refused(() => ignore(s.next())),
    content="Connection(code=1, a frame inside a field block)",
  )
}

///|
test "frames on a closed stream: ignored after this side's reset, refused otherwise" {
  let s = server()
  s.receive(headers_frame(1, get("/")))
  let _ = drain(s)
  s.reset(1)
  let _ = s.take()
  s.receive(
    @http2.Frame::Data(stream_id=1, data=b"late", end_stream=false, padding=0).encode(),
  )
  inspect(drain(s), content="")
  // The connection window still gets the octets back, in time.
  inspect(frames(s.take()), content="")
  let t = server()
  t.receive(headers_frame(1, get("/"), end=true))
  let _ = drain(t)
  t.headers(1, status("204"), end=true)
  let _ = t.take()
  t.receive(
    @http2.Frame::Data(stream_id=1, data=b"late", end_stream=false, padding=0).encode(),
  )
  inspect(drain(t), content="")
  inspect(frames(t.take()), content="RST_STREAM 1 5")
}

///|
test "padding goes back to the window at once" {
  let s = server()
  s.update(@http2.Settings::new(initial_window_size=100))
  let _ = s.take()
  s.receive(@http2.Frame::Settings(params=[], ack=true).encode())
  let _ = drain(s)
  s.receive(headers_frame(1, get("/")))
  s.receive(
    @http2.Frame::Data(stream_id=1, data=b"ab", end_stream=false, padding=60).encode(),
  )
  inspect(
    drain(s),
    content=(
      #|request 1 :method=GET :scheme=https :path=/ :authority=x
      #|data 1 ab
    ),
  )
  inspect(frames(s.take()), content="WINDOW_UPDATE 1 61")
}

///|
test "calls out of order are this side's fault" {
  let (c, s) = pair()
  inspect(
    refused(() => c.data(1, b"x")),
    content="Order(data on a stream with no head sent, or one this side ended)",
  )
  inspect(
    refused(() => s.headers(1, status("200"))),
    content="Order(a server answers on a stream the client opened)",
  )
  inspect(
    refused(() => c.headers(2, get("/"))),
    content="Order(a new stream's id is odd and above every one used)",
  )
  inspect(
    refused(() => c.headers(1, [h(":method", "GET")])),
    content="Order(a request with no :scheme or :path)",
  )
  c.headers(1, get("/"))
  inspect(
    refused(() => c.headers(1, [h("x", "1")])),
    content="Order(trailers end the stream)",
  )
  pump(c, s)
  let _ = drain(s)
  inspect(
    refused(() => s.headers(1, status("101"))),
    content="Order(HTTP/2 has no 101)",
  )
  inspect(
    refused(() => s.headers(1, status("100"), end=true)),
    content="Order(an informational response cannot end the stream)",
  )
  inspect(
    refused(() => c.ping(b"short")),
    content="Order(a PING carries eight octets)",
  )
}

///|
test "the peer closing the transport is a close" {
  let (c, _) = pair()
  c.receive(b"")
  inspect(drain(c), content="closed")
  inspect(
    refused(() => c.receive(b"x")),
    content="Order(octets received after the peer closed)",
  )
}
