// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What each connection error code is worth on the wire, and what the unidirectional streams are
// held to (RFC 9114 §6.2.1, §7.2, §7.2.4.1, §8.1; RFC 9204 §4.1.3, §4.2, §4.4.3): the control
// stream's SETTINGS first and once, the encoder stream's capacity limit, the decoder stream's
// acknowledgements, and the streams that may exist only once.

///|
/// The code `taken` refused with, or `None` when it was accepted.
fn code_of(taken : Result[Unit, Refused]) -> Code? {
  match taken {
    Ok(_) => None
    Err(e) => Some(e.code())
  }
}

///|
/// A control stream's bytes with `settings` as its SETTINGS frame.
fn settings_bytes(pairs : Array[(UInt64, UInt64)]) -> Bytes {
  (Settings(pairs) : Frame).encode()
}

///|
test "http3 errors: every code writes the number its registry gives it" {
  let cases : Array[(Code, UInt64)] = [
    (NoError, 0x100UL),
    (GeneralProtocolError, 0x101UL),
    (InternalError, 0x102UL),
    (StreamCreationError, 0x103UL),
    (ClosedCriticalStream, 0x104UL),
    (FrameUnexpected, 0x105UL),
    (FrameError, 0x106UL),
    (ExcessiveLoad, 0x107UL),
    (IdError, 0x108UL),
    (SettingsError, 0x109UL),
    (MissingSettings, 0x10aUL),
    (RequestRejected, 0x10bUL),
    (RequestCancelled, 0x10cUL),
    (RequestIncomplete, 0x10dUL),
    (MessageError, 0x10eUL),
    (ConnectError, 0x10fUL),
    (VersionFallback, 0x110UL),
    (QpackDecompressionFailed, 0x200UL),
    (QpackEncoderStreamError, 0x201UL),
    (QpackDecoderStreamError, 0x202UL),
  ]
  for case in cases {
    assert_eq(case.0.code(), case.1)
  }
}

///|
test "http3 errors: a refusal without a code of its own is the general protocol error" {
  let plain : Refused = Malformed("something")
  assert_eq(plain.code(), GeneralProtocolError)
  assert_eq(Malformed("x").to_string(), "Malformed(x)")
  assert_eq(
    Fault(code=FrameUnexpected, detail="no").to_string(),
    "H3_FRAME_UNEXPECTED(no)",
  )
}

///|
test "http3 control stream: the first frame must be SETTINGS" {
  let reader = Control::new()
  let taken = Ok(reader.feed((MaxPushId(1UL) : Frame).encode()) |> ignore) catch {
    e => Err(e)
  }
  assert_eq(code_of(taken), Some(MissingSettings))
}

///|
test "http3 control stream: its SETTINGS are read even when split across reads" {
  let reader = Control::new()
  let wire = settings_bytes(Settings::new(0UL, 16384UL, 0UL).pairs())
  assert_eq(reader.feed(wire[0:3].to_owned()), None)
  let settings = reader.feed(wire[3:].to_owned())
  assert_eq(settings, Some(Settings::new(0UL, 16384UL, 0UL)))
  assert_eq(reader.settings(), Some(Settings::new(0UL, 16384UL, 0UL)))
}

///|
test "http3 control stream: DATA, HEADERS and a second SETTINGS are H3_FRAME_UNEXPECTED" {
  for frame in [(Data(b"x") : Frame), Headers(b"\x00\x00"), Settings([])] {
    let reader = Control::new()
    reader.feed(settings_bytes(Settings::new(0UL, 16384UL, 0UL).pairs()))
    |> ignore
    let taken = Ok(reader.feed(frame.encode()) |> ignore) catch { e => Err(e) }
    assert_eq(code_of(taken), Some(FrameUnexpected))
  }
}

///|
test "http3 settings: an HTTP/2 identifier is H3_SETTINGS_ERROR, even behind a reserved one" {
  // MAX_CONCURRENT_STREAMS on its own.
  let reader = Control::new()
  let taken = Ok(reader.feed(settings_bytes([(0x03UL, 100UL)])) |> ignore) catch {
    e => Err(e)
  }
  assert_eq(code_of(taken), Some(SettingsError))
  // The same behind the reserved identifier 0x21, which reading must not stop at.
  let reader = Control::new()
  let taken = Ok(
    reader.feed(settings_bytes([(0x21UL, 0UL), (0x02UL, 0UL)])) |> ignore,
  ) catch {
    e => Err(e)
  }
  assert_eq(code_of(taken), Some(SettingsError))
}

///|
test "http3 settings: the same identifier twice is H3_SETTINGS_ERROR" {
  for pairs in [[(0x07UL, 100UL), (0x07UL, 100UL)], [(64UL, 0UL), (64UL, 0UL)]] {
    let reader = Control::new()
    let taken = Ok(reader.feed(settings_bytes(pairs)) |> ignore) catch {
      e => Err(e)
    }
    assert_eq(code_of(taken), Some(SettingsError))
  }
}

///|
test "http3 settings: a payload ending between an identifier and its value is H3_FRAME_ERROR" {
  let reader = Control::new()
  let taken = Ok(reader.feed(b"\x04\x01\x01") |> ignore) catch { e => Err(e) }
  assert_eq(code_of(taken), Some(FrameError))
}

///|
test "http3 control stream: a frame longer than the limit is refused before it is held" {
  let reader = Control::new(limit=16384UL)
  // GOAWAY declaring 2^30 octets, of which none are sent.
  let taken = Ok(reader.feed(b"\x07\xc0\x00\x00\x00\x40\x00\x00\x00") |> ignore) catch {
    e => Err(e)
  }
  assert_eq(code_of(taken), Some(ExcessiveLoad))
}

///|
test "http3 control stream: ending it is H3_CLOSED_CRITICAL_STREAM" {
  let reader = Control::new()
  let ended = try {
    reader.end()
    None
  } catch {
    e => Some(e.code())
  }
  assert_eq(ended, Some(ClosedCriticalStream))
}

///|
test "http3 encoder stream: a capacity over what was advertised is QPACK_ENCODER_STREAM_ERROR" {
  let reader = Encoder::new(limit=0)
  let taken = Ok(
    reader.feed(@qpack.Change::encode(@qpack.SetCapacity(4096))) |> ignore,
  ) catch {
    e => Err(e)
  }
  assert_eq(code_of(taken), Some(QpackEncoderStreamError))
  // The huge value a peer can send in one instruction, which no Int32 holds.
  let reader = Encoder::new(limit=0)
  let taken = Ok(reader.feed(b"\x3f\xe1\xc7\xaf\xa0\x25") |> ignore) catch {
    e => Err(e)
  }
  assert_eq(code_of(taken), Some(QpackEncoderStreamError))
  // A capacity within the limit is taken, and fills the table it names.
  let reader = Encoder::new(limit=4096)
  reader.feed(@qpack.Change::encode(@qpack.SetCapacity(4096))) |> ignore
  reader.feed(
    @qpack.Change::encode(@qpack.Insert(is_static=true, index=1, value=b"x")),
  )
  |> ignore
  assert_eq(reader.table().insert_count, 1)
  assert_eq(reader.table().capacity, 4096)
}

///|
test "http3 encoder stream: a name index that names nothing is QPACK_ENCODER_STREAM_ERROR" {
  let reader = Encoder::new(limit=4096)
  let taken = Ok(
    reader.feed(@qpack.Change::encode(@qpack.Duplicate(index=0))) |> ignore,
  ) catch {
    e => Err(e)
  }
  assert_eq(code_of(taken), Some(QpackEncoderStreamError))
}

///|
test "http3 encoder stream: ending it is H3_CLOSED_CRITICAL_STREAM" {
  let reader = Encoder::new()
  let ended = try {
    reader.end()
    None
  } catch {
    e => Some(e.code())
  }
  assert_eq(ended, Some(ClosedCriticalStream))
}

///|
test "http3 decoder stream: an Increment of 0 is QPACK_DECODER_STREAM_ERROR" {
  let reader = Decoder::new()
  let taken = Ok(reader.feed(b"\x00") |> ignore) catch { e => Err(e) }
  assert_eq(code_of(taken), Some(QpackDecoderStreamError))
}

///|
test "http3 decoder stream: acknowledgements are read, and the stream may not end" {
  let reader = Decoder::new()
  reader.feed(@qpack.Ack::encode(@qpack.Section(stream_id=0))) |> ignore
  reader.feed(@qpack.Ack::encode(@qpack.Cancel(stream_id=4))) |> ignore
  reader.feed(@qpack.Ack::encode(@qpack.Increment(increment=2))) |> ignore
  let ended = try {
    reader.end()
    None
  } catch {
    e => Some(e.code())
  }
  assert_eq(ended, Some(ClosedCriticalStream))
}

///|
test "http3 conn: each of the three critical streams may be opened once" {
  let conn = Conn::new(Server, Settings::new(0UL, 16384UL, 0UL))
  conn.open_stream(ControlKind)
  conn.open_stream(EncoderKind)
  conn.open_stream(DecoderKind)
  for kind in [ControlKind, EncoderKind, DecoderKind] {
    let again = try {
      conn.open_stream(kind)
      None
    } catch {
      e => Some(e.code())
    }
    assert_eq(again, Some(StreamCreationError))
  }
}

///|
test "http3 conn: a push stream at a server is H3_STREAM_CREATION_ERROR, at a client it is not" {
  let server = Conn::new(Server, Settings::new(0UL, 16384UL, 0UL))
  let refused = try {
    server.open_stream(PushKind(0UL))
    None
  } catch {
    e => Some(e.code())
  }
  assert_eq(refused, Some(StreamCreationError))
  let client = Conn::new(Client, Settings::new(0UL, 16384UL, 0UL))
  client.open_stream(PushKind(0UL))
  // A reserved kind is a peer exercising §9, and neither opens nor closes anything.
  client.open_stream(ReservedKind(0x21UL))
}

///|
test "http3 conn: closing a critical stream is H3_CLOSED_CRITICAL_STREAM, a push stream is not" {
  let conn = Conn::new(Server, Settings::new(0UL, 16384UL, 0UL))
  for kind in [ControlKind, EncoderKind, DecoderKind] {
    let closed = try {
      conn.close_stream(kind)
      None
    } catch {
      e => Some(e.code())
    }
    assert_eq(closed, Some(ClosedCriticalStream))
  }
  conn.close_stream(PushKind(3UL))
  assert_eq(ControlKind.is_critical(), true)
  assert_eq(ReservedKind(0x21UL).is_critical(), false)
}

///|
test "http3 conn: a control stream that does not open with SETTINGS is H3_MISSING_SETTINGS" {
  let conn = Conn::new(Server, Settings::new(0UL, 16384UL, 0UL))
  let wire = Stream::encode(ControlKind)
  let bad = join(wire, (MaxPushId(0UL) : Frame).encode())
  let refused = try {
    conn.accept_uni_stream(bad) |> ignore
    None
  } catch {
    e => Some(e.code())
  }
  assert_eq(refused, Some(MissingSettings))
}
