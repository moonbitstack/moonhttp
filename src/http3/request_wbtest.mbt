// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The rules a request stream is held to (RFC 9114 §4.1, §4.1.1, §4.1.3, §4.2, §4.3, §7.1,
// §7.2), one test a rule: the order the frames may come in, what a field section may say, and
// what happens when a peer says something else.

///|
/// The code `feed` refused with, or `None` when it took everything.
fn refused_code(taken : Result[Array[Part], Refused]) -> Code? {
  match taken {
    Ok(_) => None
    Err(e) => Some(e.code())
  }
}

///|
/// A request stream carrying `fields` and `body`.
fn stream_of(fields : Array[@header.Header], body : Bytes) -> Bytes {
  message(fields, body)
}

///|
/// A request stream carrying `fields` and no body.
fn head_only(fields : Array[@header.Header]) -> Bytes {
  stream_of(fields, b"")
}

///|
/// What a well-formed GET looks like.
fn get_fields() -> Array[@header.Header] {
  [
    @header.Header::of(":method", "GET"),
    @header.Header::of(":scheme", "https"),
    @header.Header::of(":authority", "example.com"),
    @header.Header::of(":path", "/"),
  ]
}

///|
test "http3 request stream: a well-formed request yields its head, then its body" {
  let reader = Incoming::new()
  let parts = reader.feed(stream_of(get_fields(), b"hello"))
  assert_eq(parts.length(), 2)
  assert_eq(parts[0], Head(get_fields()))
  assert_eq(parts[1], Data(b"hello"))
}

///|
test "http3 request stream: a body split across reads comes back in the pieces it arrived" {
  let reader = Incoming::new(chunk=4)
  let wire = stream_of(get_fields(), b"hello world")
  // The head alone, then a DATA frame header and the first three octets of the body behind it.
  let head_len = message(get_fields(), b"").length()
  let first = reader.feed(wire[0:head_len + 5].to_owned())
  assert_eq(first, [Head(get_fields()), Data(b"hel")])
  let rest = reader.feed(wire[head_len + 5:].to_owned())
  assert_eq(rest, [Data(b"lo w"), Data(b"orld")])
}

///|
test "http3 request stream: DATA before HEADERS is H3_FRAME_UNEXPECTED" {
  let reader = Incoming::new()
  let taken = Ok(reader.feed((Data(b"x") : Frame).encode())) catch {
    e => Err(e)
  }
  assert_eq(refused_code(taken), Some(FrameUnexpected))
}

///|
test "http3 request stream: a frame a control stream owns is H3_FRAME_UNEXPECTED" {
  for
    frame in [
      (Settings([(max_field_section, 16384UL)]) : Frame),
      GoAway(0UL),
      CancelPush(1UL),
      MaxPushId(1UL),
      PushPromise(1UL, b""),
    ] {
    let reader = Incoming::new()
    let wire = join(head_only(get_fields()), frame.encode())
    let taken = Ok(reader.feed(wire)) catch { e => Err(e) }
    assert_eq(refused_code(taken), Some(FrameUnexpected))
  }
}

///|
test "http3 request stream: a duplicated pseudo-header is H3_MESSAGE_ERROR" {
  let reader = Incoming::new()
  let fields = get_fields()
  fields.push(@header.Header::of(":method", "GET"))
  let taken = Ok(reader.feed(head_only(fields))) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(MessageError))
}

///|
test "http3 request stream: a pseudo-header this protocol does not define is H3_MESSAGE_ERROR" {
  let reader = Incoming::new()
  let fields = get_fields()
  fields.push(@header.Header::of(":foo", "bar"))
  let taken = Ok(reader.feed(head_only(fields))) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(MessageError))
}

///|
test "http3 request stream: a pseudo-header after the regular fields is H3_MESSAGE_ERROR" {
  let reader = Incoming::new()
  let fields : Array[@header.Header] = [
    @header.Header::of(":method", "GET"),
    @header.Header::of(":scheme", "https"),
    @header.Header::of(":authority", "example.com"),
    @header.Header::of("x-custom", "v"),
    @header.Header::of(":path", "/"),
  ]
  let taken = Ok(reader.feed(head_only(fields))) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(MessageError))
}

///|
test "http3 request stream: a request without :method, :scheme or :path is H3_MESSAGE_ERROR" {
  let cases : Array[Array[@header.Header]] = [
    [@header.Header::of("x-custom", "v")],
    [@header.Header::of(":method", "GET"), @header.Header::of(":path", "/")],
    [
      @header.Header::of(":method", "GET"),
      @header.Header::of(":scheme", "https"),
    ],
  ]
  for fields in cases {
    let reader = Incoming::new()
    let taken = Ok(reader.feed(head_only(fields))) catch { e => Err(e) }
    assert_eq(refused_code(taken), Some(MessageError))
  }
}

///|
test "http3 request stream: an http or https request without an authority is H3_MESSAGE_ERROR" {
  let fields : Array[@header.Header] = [
    @header.Header::of(":method", "GET"),
    @header.Header::of(":scheme", "https"),
    @header.Header::of(":path", "/"),
  ]
  let reader = Incoming::new()
  let taken = Ok(reader.feed(head_only(fields))) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(MessageError))
  // A Host field names the authority just as well (RFC 9114 §4.3.1).
  let hosted = fields.copy()
  hosted.push(@header.Header::of("host", "example.com"))
  let reader = Incoming::new()
  assert_eq(
    refused_code(Ok(reader.feed(head_only(hosted))) catch { e => Err(e) }),
    None,
  )
}

///|
test "http3 request stream: the connection-specific fields are H3_MESSAGE_ERROR" {
  let banned = [
    ("connection", "close"),
    ("keep-alive", "timeout=5"),
    ("proxy-connection", "keep-alive"),
    ("transfer-encoding", "chunked"),
    ("upgrade", "websocket"),
    ("te", "gzip"),
  ]
  for pair in banned {
    let fields = get_fields()
    fields.push(@header.Header::of(pair.0, pair.1))
    let reader = Incoming::new()
    let taken = Ok(reader.feed(head_only(fields))) catch { e => Err(e) }
    assert_eq(refused_code(taken), Some(MessageError))
  }
  // TE with trailers says which end decodes the body, not how it is framed, and is allowed.
  let allowed_fields = get_fields()
  allowed_fields.push(@header.Header::of("te", "trailers"))
  let reader = Incoming::new()
  assert_eq(
    refused_code(
      Ok(reader.feed(head_only(allowed_fields))) catch {
        e => Err(e)
      },
    ),
    None,
  )
}

///|
test "http3 request stream: an upper-case field name is H3_MESSAGE_ERROR" {
  let fields = get_fields()
  fields.push(@header.Header::of("X-Custom", "v"))
  let reader = Incoming::new()
  let taken = Ok(reader.feed(head_only(fields))) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(MessageError))
}

///|
test "http3 request stream: trailers are read, and may carry no pseudo-header" {
  let wire = head_only(get_fields())
  let tail = (
    Headers(@qpack.encode([@header.Header::of("x-checksum", "abc")])) : Frame)
  let reader = Incoming::new()
  let parts = reader.feed(join(wire, tail.encode()))
  assert_eq(parts.length(), 2)
  assert_eq(parts[1], Trailers([@header.Header::of("x-checksum", "abc")]))
  // DATA after them is a frame in the wrong place.
  let taken = Ok(reader.feed((Data(b"late") : Frame).encode())) catch {
    e => Err(e)
  }
  assert_eq(refused_code(taken), Some(FrameUnexpected))
  // And a pseudo-header in the trailers is malformed.
  let reader = Incoming::new()
  let bad = (
    Headers(@qpack.encode([@header.Header::of(":status", "200")])) : Frame)
  let taken = Ok(reader.feed(join(wire, bad.encode()))) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(MessageError))
}

///|
test "http3 request stream: a third HEADERS frame is H3_FRAME_UNEXPECTED" {
  let wire = head_only(get_fields())
  let tail = (Headers(@qpack.encode([@header.Header::of("x-a", "1")])) : Frame)
  let reader = Incoming::new()
  assert_eq(reader.feed(join(wire, tail.encode())).length(), 2)
  let taken = Ok(reader.feed(tail.encode())) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(FrameUnexpected))
}

///|
test "http3 request stream: a frame over the field section limit is H3_EXCESSIVE_LOAD" {
  let reader = Incoming::new(limit=64UL)
  let big = (Headers(Bytes::make(65, b'a')) : Frame).encode()
  let taken = Ok(reader.feed(join(head_only(get_fields()), big))) catch {
    e => Err(e)
  }
  assert_eq(refused_code(taken), Some(ExcessiveLoad))
}

///|
test "http3 request stream: a bad static index or an absent dynamic entry is QPACK_DECOMPRESSION_FAILED" {
  let prefix = b"\x00\x00"
  // An indexed field line naming static entry 99, which the table does not have.
  let bad_static = (Headers(join(prefix, b"\xff\x24")) : Frame).encode()
  let reader = Incoming::new()
  let taken = Ok(reader.feed(bad_static)) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(QpackDecompressionFailed))
  // An indexed field line into a dynamic table nothing has been inserted into.
  let bad_dynamic = (Headers(join(prefix, b"\x80")) : Frame).encode()
  let reader = Incoming::new()
  let taken = Ok(reader.feed(bad_dynamic)) catch { e => Err(e) }
  assert_eq(refused_code(taken), Some(QpackDecompressionFailed))
}

///|
test "http3 request stream: a stream that ends inside a frame is H3_FRAME_ERROR" {
  let wire = (Headers(@qpack.encode(get_fields())) : Frame).encode()
  let reader = Incoming::new()
  reader.feed(wire[0:wire.length() - 1].to_owned()) |> ignore
  let ended = try {
    reader.end()
    None
  } catch {
    e => Some(e.code())
  }
  assert_eq(ended, Some(FrameError))
}

///|
test "http3 request stream: a reserved frame type is read past, not refused" {
  let reader = Incoming::new()
  let grease = (Reserved(0x21UL, b"\xff\xff") : Frame).encode()
  let wire = join(grease, head_only(get_fields()))
  assert_eq(reader.feed(wire), [Head(get_fields())])
}

///|
test "http3 request: read_request reads a head and leaves the body" {
  let req = read_request(stream_of(get_fields(), b"body"))
  match req {
    Some(r) => {
      assert_eq(r.meth, "GET")
      assert_eq(r.authority, "example.com")
      assert_eq(r.body, b"body")
    }
    None => abort("expected a request")
  }
  // A malformed field section is not a request at all.
  assert_eq(
    read_request(head_only([@header.Header::of("x", "y")])) is None,
    true,
  )
}
