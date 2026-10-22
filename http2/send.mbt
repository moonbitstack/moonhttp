// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Send a head on `stream`: a client's request on a stream it opens with this,
/// a server's informational or final response, or either side's trailers.
///
/// Which one it is follows from the stream: a new id from a client is a request,
/// the first head a server sends is its response (a 1xx leaves room for another),
/// and a head after the final one is the trailers, which must end the stream. The
/// fields are checked against RFC 9113 §8.2 and §8.3 as a peer would check them,
/// and a block longer than the peer's frame size is carried on in CONTINUATION
/// frames. Raises [`Refused::Order`] for a head the protocol does not allow here.
pub fn Conn::headers(
  self : Conn,
  stream : Int32,
  fields : Array[@header.Header],
  end~ : Bool = false,
) -> Unit raise Refused {
  self.alive()
  guard self.streams.get(stream) is Some(s) else {
    return self.request(stream, fields, end)
  }
  match s.phase {
    ReservedLocal => {
      // The response a push promised.
      self.respond(s, fields, end)
      s.phase = HalfRemote
    }
    Open | HalfRemote if !s.sent && self.role is Server =>
      self.respond(s, fields, end)
    Open | HalfRemote => {
      if !end {
        raise Order("trailers end the stream")
      }
      if fault(fields, Trailers) is Some(why) {
        raise Order(why)
      }
      self.emit(stream, fields, end)
    }
    _ => raise Order("a head on a stream this side has ended")
  }
  if end {
    self.finish(s)
  }
}

///|
/// A client opening `stream` with its request.
fn Conn::request(
  self : Conn,
  stream : Int32,
  fields : Array[@header.Header],
  end : Bool,
) -> Unit raise Refused {
  if self.role is Server {
    raise Order("a server answers on a stream the client opened")
  }
  if stream % 2 == 0 || stream < self.next_id {
    raise Order("a new stream's id is odd and above every one used")
  }
  if self.gone is Some(_) {
    raise Order("a new stream after the server's GOAWAY")
  }
  if self.theirs.max_concurrent_streams is Some(n) && self.active(false) >= n {
    raise Order("past the server's SETTINGS_MAX_CONCURRENT_STREAMS")
  }
  let extended = self.theirs.enable_connect_protocol
  if fault(fields, Request, extended~) is Some(why) {
    raise Order(why)
  }
  let s = self.stream(stream, Open)
  s.sent = true
  s.head = find(fields, ":method") is Some(m) && m == b"HEAD"
  self.next_id = stream + 2
  self.emit(stream, fields, end)
  if end {
    self.finish(s)
  }
}

///|
/// A server's response head, informational or final.
fn Conn::respond(
  self : Conn,
  s : Stream,
  fields : Array[@header.Header],
  end : Bool,
) -> Unit raise Refused {
  if fault(fields, Response) is Some(why) {
    raise Order(why)
  }
  let code = status(fields)
  if code < 200 {
    if code == 101 {
      raise Order("HTTP/2 has no 101")
    }
    if end {
      raise Order("an informational response cannot end the stream")
    }
  } else {
    s.sent = true
  }
  self.emit(s.id, fields, end)
}

///|
/// Send `data` on `stream`, in frames no longer than the peer allows.
///
/// It must fit in [`Conn::window`]; a caller with more waits for `WindowUpdated`.
/// Empty data with `end` sends the END_STREAM alone.
pub fn Conn::data(
  self : Conn,
  stream : Int32,
  data : BytesView,
  end~ : Bool = false,
) -> Unit raise Refused {
  self.alive()
  guard self.streams.get(stream) is Some(s) &&
    s.phase is (Open | HalfRemote) &&
    s.sent else {
    raise Order("data on a stream with no head sent, or one this side ended")
  }
  let n = data.length()
  if n > self.window(stream) {
    raise Order("more data than the flow-control window")
  }
  let max = self.theirs.max_frame_size
  let mut off = 0
  while off < n {
    let take = if n - off < max { n - off } else { max }
    self.write(
      Frame::Data(
        stream_id=stream,
        data=data[off:off + take].to_owned(),
        end_stream=end && off + take == n,
        padding=0,
      ),
    )
    off = off + take
  }
  if n == 0 && end {
    self.write(
      Frame::Data(stream_id=stream, data=b"", end_stream=true, padding=0),
    )
  }
  self.send = self.send - n
  s.send = s.send - n
  if end {
    self.finish(s)
  }
}

///|
/// End `stream` from this side with an empty DATA frame.
pub fn Conn::end(self : Conn, stream : Int32) -> Unit raise Refused {
  self.data(stream, b"", end=true)
}

///|
/// Reset `stream` (§6.4). NO_ERROR is h2's default too: a reset is as often a
/// caller that no longer wants the stream as a fault.
pub fn Conn::reset(
  self : Conn,
  stream : Int32,
  code~ : Int32 = error_no_error,
) -> Unit raise Refused {
  self.alive()
  if !self.streams.contains(stream) {
    raise Order("a reset of a stream that is not open")
  }
  self.write(Frame::RstStream(stream_id=stream, error_code=code))
  self.close(stream, true)
}

///|
/// Promise the response to the request in `fields` on the client's `stream`, and
/// the id of the new stream the response goes on (§8.4).
///
/// The response is then sent with [`Conn::headers`] and [`Conn::data`] on the
/// returned id.
pub fn Conn::push(
  self : Conn,
  stream : Int32,
  fields : Array[@header.Header],
) -> Int32 raise Refused {
  self.alive()
  if self.role is Client {
    raise Order("only a server pushes")
  }
  if !self.theirs.enable_push {
    raise Order("the client has turned push off")
  }
  guard self.streams.get(stream) is Some(s) &&
    self.peers(stream) &&
    s.phase is (Open | HalfRemote) else {
    raise Order("a push rides on an open stream the client started")
  }
  if fault(fields, Promise) is Some(why) {
    raise Order(why)
  }
  let promised = self.next_id
  self.next_id = promised + 2
  let _ = self.stream(promised, ReservedLocal)
  // The promised id takes four octets of the first frame.
  self.fragments(
    stream,
    self.block_of(fields),
    self.theirs.max_frame_size - 4,
    (fragment, last) => {
      Frame::PushPromise(
        stream_id=stream,
        promised_id=promised,
        fragment~,
        end_headers=last,
        padding=0,
      )
    },
  )
  promised
}

///|
/// Send a PING with eight octets of `payload`; the answer comes as `PingAcked`.
pub fn Conn::ping(self : Conn, payload : Bytes) -> Unit raise Refused {
  self.alive()
  if payload.length() != 8 {
    raise Order("a PING carries eight octets")
  }
  self.write(Frame::Ping(payload~, ack=false))
}

///|
/// Tell the peer this side will process no stream past the last one it opened
/// (§6.8). Streams already open carry on; new ones from the peer are ignored.
pub fn Conn::goaway(
  self : Conn,
  code~ : Int32 = error_no_error,
  debug~ : Bytes = b"",
) -> Unit raise Refused {
  self.alive()
  let last = self.last()
  self.write(Frame::GoAway(last_stream_id=last, error_code=code, debug~))
  self.told = Some(last)
}

///|
/// Move this side to `settings`. They take effect when the peer acknowledges them,
/// reported as `SettingsAcked`.
pub fn Conn::update(self : Conn, settings : Settings) -> Unit raise Refused {
  self.alive()
  if settings.fault() is Some(why) {
    raise Order(why)
  }
  let base = self.strict()
  self.write(Frame::Settings(params=settings.pairs(base, self.role), ack=false))
  self.pending.push(settings)
}

///|
/// Hand back `size` octets of `stream`'s data, now processed, so the peer may send
/// more (§6.9). WINDOW_UPDATE goes out when half a window has come back, as h2
/// does; a caller that never acknowledges stalls the peer.
pub fn Conn::acknowledge(
  self : Conn,
  stream : Int32,
  size : Int32,
) -> Unit raise Refused {
  if size < 0 {
    raise Order("a negative acknowledgement")
  }
  self.credit(size)
  if self.streams.get(stream) is Some(s) {
    self.credit_stream(s, size)
  }
}

///|
/// Widen the receive window of `stream`, or of the connection for stream 0, by
/// `by` octets at once, beyond what acknowledgement would.
pub fn Conn::widen(
  self : Conn,
  stream : Int32,
  by : Int32,
) -> Unit raise Refused {
  self.alive()
  let w = if stream == 0 {
    self.recv
  } else {
    match self.streams.get(stream) {
      Some(s) => s.recv
      None => raise Order("widening a stream that is not open")
    }
  }
  if by <= 0 || w.now > 0x7FFFFFFF - by {
    raise Order("a window update outside 1..2^31 - 1")
  }
  w.open(by)
  self.write(Frame::WindowUpdate(stream_id=stream, increment=by))
}

// -- frames -------------------------------------------------------------------

///|
fn Conn::alive(self : Conn) -> Unit raise Refused {
  if self.dead {
    raise Order("the connection already failed")
  }
}

///|
/// This side has sent END_STREAM on `s`.
fn Conn::finish(self : Conn, s : Stream) -> Unit {
  match s.phase {
    Open => s.phase = HalfLocal
    HalfRemote => self.close(s.id, false)
    _ => ()
  }
}

///|
/// The compressed block for `fields`, opening with the table size update the peer
/// is owed.
fn Conn::block_of(self : Conn, fields : Array[@header.Header]) -> Bytes {
  let buf = Buffer()
  if self.resize is Some(n) {
    buf.write_bytes(@hpack.size_update(n))
    self.resize = None
  }
  buf.write_bytes(self.enc.encode(fields[:]))
  buf.to_bytes()
}

///|
/// A HEADERS frame and the CONTINUATION frames after it.
fn Conn::emit(
  self : Conn,
  stream : Int32,
  fields : Array[@header.Header],
  end : Bool,
) -> Unit {
  self.fragments(stream, self.block_of(fields), self.theirs.max_frame_size, (
    fragment,
    last,
  ) => {
    Frame::Headers(
      stream_id=stream,
      fragment~,
      end_stream=end,
      end_headers=last,
      priority=None,
      padding=0,
    )
  })
}

///|
/// `block` cut to fit: the first piece, at most `room` octets, in the frame `first`
/// builds, and the rest in CONTINUATION frames of the peer's frame size.
fn Conn::fragments(
  self : Conn,
  stream : Int32,
  block : Bytes,
  room : Int32,
  first : (Bytes, Bool) -> Frame,
) -> Unit {
  let n = block.length()
  let cut = if n < room { n } else { room }
  self.write(first(block[0:cut].to_owned(), cut == n))
  let max = self.theirs.max_frame_size
  let mut off = cut
  while off < n {
    let take = if n - off < max { n - off } else { max }
    self.write(
      Frame::Continuation(
        stream_id=stream,
        fragment=block[off:off + take].to_owned(),
        end_headers=off + take == n,
      ),
    )
    off = off + take
  }
}
