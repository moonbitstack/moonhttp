// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Read and handle one frame, or the client preface; `false` when the held octets
/// do not hold a whole one yet.
fn Conn::frame(self : Conn) -> Bool raise Refused {
  let data = self.held[self.at:]
  if self.role is Server && !self.preface {
    let n = if data.length() < preface.length() {
      data.length()
    } else {
      preface.length()
    }
    for i = 0; i < n; i = i + 1 {
      if data[i] != preface[i] {
        raise self.fail(
          error_protocol_error, "not an HTTP/2 connection preface",
        )
      }
    }
    if n < preface.length() {
      return false
    }
    self.at = self.at + n
    self.preface = true
    return true
  }
  let head = FrameHeader::decode(self.held, offset=self.at) catch {
    _ => return false
  }
  if head.length > self.mine.max_frame_size {
    raise self.fail(
      error_frame_size_error, "a frame longer than SETTINGS_MAX_FRAME_SIZE",
    )
  }
  if data.length() < 9 + head.length {
    return false
  }
  let (frame, used) = decode(self.held, offset=self.at) catch {
    FrameSizeError(m) => raise self.fail(error_frame_size_error, m)
    e => raise self.fail(error_protocol_error, e.to_string())
  }
  self.at = self.at + used
  self.handle(head, frame)
  true
}

///|
fn Conn::handle(
  self : Conn,
  head : FrameHeader,
  frame : Frame,
) -> Unit raise Refused {
  // A field block in progress admits nothing but its own CONTINUATION (§6.10).
  if self.block is Some(b) {
    guard frame is Continuation(stream_id~, fragment~, end_headers~) &&
      stream_id == b.stream else {
      raise self.fail(error_protocol_error, "a frame inside a field block")
    }
    b.buf.write_bytes(fragment)
    self.bound(b.buf)
    if end_headers {
      self.block = None
      self.complete(b)
    }
    return
  }
  if !self.greeted {
    guard frame is Settings(ack=false, ..) else {
      raise self.fail(
        error_protocol_error, "a first frame that is not SETTINGS",
      )
    }
    self.greeted = true
  }
  let zero = head.stream_id == 0
  match frame {
    Settings(..) | Ping(..) | GoAway(..) if !zero =>
      raise self.fail(error_protocol_error, "a connection frame on a stream")
    Data(..)
    | Headers(..)
    | Priority(..)
    | RstStream(..)
    | PushPromise(..)
    | Continuation(..) if zero =>
      raise self.fail(error_protocol_error, "a stream frame on stream 0")
    Data(stream_id~, data~, end_stream~, ..) =>
      self.data_in(stream_id, data, end_stream, head.length)
    Headers(stream_id~, fragment~, end_stream~, end_headers~, priority~, ..) => {
      let b = {
        stream: stream_id,
        promised: None,
        end: end_stream,
        buf: Buffer(),
        looped: priority is Some(p) && p.stream_dependency == stream_id,
      }
      self.open(b, fragment, end_headers)
    }
    PushPromise(stream_id~, promised_id~, fragment~, end_headers~, ..) => {
      if self.role is Server {
        raise self.fail(error_protocol_error, "a PUSH_PROMISE from a client")
      }
      if !self.strict().enable_push {
        raise self.fail(error_protocol_error, "a PUSH_PROMISE with push off")
      }
      let b = {
        stream: stream_id,
        promised: Some(promised_id),
        end: false,
        buf: Buffer(),
        looped: false,
      }
      self.open(b, fragment, end_headers)
    }
    Priority(stream_id~, priority~) =>
      // Priority signals are advisory and RFC 9113 deprecates them; only a stream
      // made to depend on itself is an error (§5.3.1).
      if priority.stream_dependency == stream_id {
        self.refuse(stream_id, error_protocol_error)
      }
    RstStream(stream_id~, error_code~) =>
      if self.streams.contains(stream_id) {
        self.events.push(Reset(stream=stream_id, code=error_code, remote=true))
        self.close(stream_id, false)
      } else if self.idle(stream_id) {
        raise self.fail(error_protocol_error, "RST_STREAM on an idle stream")
      }
    Settings(params~, ack~) =>
      if ack {
        self.acked()
      } else {
        self.settle(params)
      }
    Ping(payload~, ack~) =>
      if ack {
        self.events.push(PingAcked(payload))
      } else {
        self.write(Frame::Ping(payload~, ack=true))
        self.events.push(Ping(payload))
      }
    GoAway(last_stream_id~, error_code~, debug~) => {
      self.gone = Some(last_stream_id)
      self.events.push(GoAway(code=error_code, last=last_stream_id, debug~))
    }
    WindowUpdate(stream_id~, increment~) => self.widened(stream_id, increment)
    Continuation(..) =>
      raise self.fail(
        error_protocol_error, "a CONTINUATION outside a field block",
      )
    Unknown(..) => ()
  }
}

///|
/// Start a field block, and finish it at once when it fits in one frame.
fn Conn::open(
  self : Conn,
  b : Block,
  fragment : Bytes,
  end_headers : Bool,
) -> Unit raise Refused {
  b.buf.write_bytes(fragment)
  self.bound(b.buf)
  if end_headers {
    self.complete(b)
  } else {
    self.block = Some(b)
  }
}

///|
/// A field block can never be larger than the list it decodes to, give or take a
/// few octets per field, so one past SETTINGS_MAX_HEADER_LIST_SIZE is a peer
/// sending CONTINUATION frames without end.
fn Conn::bound(self : Conn, buf : Buffer) -> Unit raise Refused {
  if self.strict().max_header_list_size is Some(n) && buf.length() > n {
    raise self.fail(
      error_enhance_your_calm, "a field block past SETTINGS_MAX_HEADER_LIST_SIZE",
    )
  }
}

///|
/// A whole field block: decoded at once, whatever becomes of it, because the two
/// ends' HPACK tables must stay in step.
fn Conn::complete(self : Conn, b : Block) -> Unit raise Refused {
  let fields = Some(
    self.dec.decode(
      b.buf.to_bytes()[:],
      limit?=self.strict().max_header_list_size,
    ),
  ) catch {
    @hpack.Exceeded(..) => None
    e => raise self.fail(error_compression_error, e.to_string())
  }
  match b.promised {
    Some(promised) => self.promise_in(b.stream, promised, fields)
    None => self.headers_in(b, fields)
  }
}

///|
fn Conn::headers_in(
  self : Conn,
  b : Block,
  fields : Array[@header.Header]?,
) -> Unit raise Refused {
  let id = b.stream
  guard self.streams.get(id) is Some(s) else {
    return self.headers_new(b, fields)
  }
  if s.phase is (HalfRemote | ReservedLocal) {
    return self.refuse(id, error_stream_closed)
  }
  guard fields is Some(fields) else {
    return self.refuse(id, error_enhance_your_calm)
  }
  if b.looped {
    return self.refuse(id, error_protocol_error)
  }
  if s.phase is ReservedRemote {
    s.phase = HalfLocal
  }
  if s.got {
    // A second head after the final one is the trailers, which end the stream.
    if !b.end || fault(fields, Trailers) is Some(_) {
      return self.refuse(id, error_protocol_error)
    }
    self.events.push(Trailers(stream=id, fields~))
    return self.ended(s)
  }
  // Only a client waits for a head on a stream it already has: the response.
  if fault(fields, Response) is Some(_) {
    return self.refuse(id, error_protocol_error)
  }
  let code = status(fields)
  if code < 200 {
    // HTTP/2 has no 101 (§8.6), and a 1xx never ends a stream.
    if code == 101 || b.end {
      return self.refuse(id, error_protocol_error)
    }
    self.events.push(Informational(stream=id, fields~))
    return
  }
  s.got = true
  s.length = if s.head || code == 204 || code == 304 {
    None
  } else {
    length(fields)
  }
  self.events.push(Response(stream=id, fields~))
  if b.end {
    self.ended(s)
  }
}

///|
/// HEADERS on a stream this connection does not have open.
fn Conn::headers_new(
  self : Conn,
  b : Block,
  fields : Array[@header.Header]?,
) -> Unit raise Refused {
  let id = b.stream
  if !self.peers(id) || self.role is Client {
    if self.idle(id) {
      raise self.fail(error_protocol_error, "HEADERS on a stream never opened")
    }
    return self.lapsed(id)
  }
  if !self.idle(id) {
    return self.lapsed(id)
  }
  self.last_peer = id
  // After a GOAWAY, streams past the last one it named are not processed (§6.8).
  if self.told is Some(last) && id > last {
    return
  }
  guard fields is Some(fields) else {
    return self.refuse(id, error_enhance_your_calm)
  }
  if self.strict().max_concurrent_streams is Some(n) && self.active(true) >= n {
    return self.refuse(id, error_refused_stream)
  }
  let extended = self.strict().enable_connect_protocol
  if b.looped || fault(fields, Request, extended~) is Some(_) {
    return self.refuse(id, error_protocol_error)
  }
  let s = self.stream(id, Open)
  s.got = true
  s.length = length(fields)
  self.events.push(Request(stream=id, fields~))
  if b.end {
    self.ended(s)
  }
}

///|
/// A frame that only HEADERS or DATA bring, on a stream that has closed.
///
/// One this side reset may still have frames in flight, which §5.4.2 says to
/// ignore; any other gets RST_STREAM with STREAM_CLOSED (§5.1).
fn Conn::lapsed(self : Conn, id : Int32) -> Unit {
  if self.closed.get(id) is Some(true) {
    return
  }
  self.write(Frame::RstStream(stream_id=id, error_code=error_stream_closed))
}

///|
fn Conn::promise_in(
  self : Conn,
  id : Int32,
  promised : Int32,
  fields : Array[@header.Header]?,
) -> Unit raise Refused {
  if promised % 2 != 0 || promised <= self.last_peer {
    raise self.fail(error_protocol_error, "a promised stream id out of order")
  }
  self.last_peer = promised
  match self.streams.get(id) {
    Some(s) if s.phase is (Open | HalfLocal) && !self.peers(id) => ()
    // The associated stream was reset here and the promise crossed the reset.
    _ if self.closed.get(id) is Some(true) => {
      self.write(Frame::RstStream(stream_id=promised, error_code=error_cancel))
      return self.close(promised, true)
    }
    _ =>
      raise self.fail(
        error_protocol_error, "a PUSH_PROMISE on a stream that cannot carry one",
      )
  }
  guard fields is Some(fields) && fault(fields, Promise) is None else {
    self.write(
      Frame::RstStream(stream_id=promised, error_code=error_protocol_error),
    )
    return self.close(promised, true)
  }
  let s = self.stream(promised, ReservedRemote)
  s.head = find(fields, ":method") is Some(m) && m == b"HEAD"
  self.events.push(Pushed(stream=id, promised~, fields~))
}

///|
fn Conn::data_in(
  self : Conn,
  id : Int32,
  data : Bytes,
  end : Bool,
  size : Int32,
) -> Unit raise Refused {
  if !self.recv.consume(size) {
    raise self.fail(error_flow_control_error, "DATA past the connection window")
  }
  guard self.streams.get(id) is Some(s) else {
    // Nobody will read it, so the connection gets it back now.
    self.credit(size)
    if self.idle(id) {
      raise self.fail(error_protocol_error, "DATA on an idle stream")
    }
    return self.lapsed(id)
  }
  match s.phase {
    Open | HalfLocal => ()
    HalfRemote => {
      self.credit(size)
      return self.refuse(id, error_stream_closed)
    }
    ReservedLocal | ReservedRemote =>
      raise self.fail(error_protocol_error, "DATA on a reserved stream")
  }
  if !s.recv.consume(size) {
    self.credit(size)
    return self.refuse(id, error_flow_control_error)
  }
  if !s.got {
    self.credit(size)
    return self.refuse(id, error_protocol_error)
  }
  s.received = s.received + data.length()
  if s.length is Some(n) && s.received > n {
    self.credit(size)
    return self.refuse(id, error_protocol_error)
  }
  // Padding carries nothing for the caller to pace, so it goes back at once.
  let pad = size - data.length()
  if pad > 0 {
    self.credit(pad)
    self.credit_stream(s, pad)
  }
  if data.length() > 0 {
    self.events.push(Data(stream=id, data~))
  }
  if end {
    self.ended(s)
  }
}

///|
/// The peer ended the stream: its content-length is checked, and the stream moves
/// on.
fn Conn::ended(self : Conn, s : Stream) -> Unit {
  if s.length is Some(n) && n != s.received {
    return self.refuse(s.id, error_protocol_error)
  }
  self.events.push(End(stream=s.id))
  match s.phase {
    Open => s.phase = HalfRemote
    HalfLocal => self.close(s.id, false)
    _ => ()
  }
}

///|
/// The peer's SETTINGS: applied, acknowledged, and reported.
fn Conn::settle(
  self : Conn,
  params : Array[(Int32, Int32)],
) -> Unit raise Refused {
  let before = self.theirs
  let after = match before.merge(params, self.role) {
    Ok(s) => s
    Err((code, why)) => raise self.fail(code, why)
  }
  let delta = after.initial_window_size - before.initial_window_size
  for _, s in self.streams {
    if delta > 0 && s.send > 0x7FFFFFFF - delta {
      raise self.fail(
        error_flow_control_error, "a stream window past 2^31 - 1 after SETTINGS",
      )
    }
    s.send = s.send + delta
  }
  if after.header_table_size != before.header_table_size {
    self.enc.table.resize(after.header_table_size)
    self.resize = Some(after.header_table_size)
  }
  self.theirs = after
  self.write(Frame::Settings(params=[], ack=true))
  self.events.push(Settings(after))
}

///|
/// The peer acknowledged this side's oldest pending SETTINGS, which take effect
/// now.
fn Conn::acked(self : Conn) -> Unit {
  guard self.pending.length() > 0 else { return }
  let before = self.mine
  let after = self.pending.remove(0)
  self.mine = after
  self.dec.limit = after.header_table_size
  let delta = after.initial_window_size - before.initial_window_size
  if delta != 0 {
    for _, s in self.streams {
      s.recv.now = s.recv.now + delta
      s.recv.max = after.initial_window_size
    }
  }
  self.events.push(SettingsAcked(after))
}

///|
fn Conn::widened(self : Conn, id : Int32, inc : Int32) -> Unit raise Refused {
  if id == 0 {
    if inc == 0 {
      raise self.fail(error_protocol_error, "a WINDOW_UPDATE of zero")
    }
    if self.send > 0x7FFFFFFF - inc {
      raise self.fail(
        error_flow_control_error, "the connection window past 2^31 - 1",
      )
    }
    self.send = self.send + inc
    return self.events.push(WindowUpdated(stream=0, delta=inc))
  }
  match self.streams.get(id) {
    Some(s) =>
      if inc == 0 {
        self.refuse(id, error_protocol_error)
      } else if s.send > 0x7FFFFFFF - inc {
        self.refuse(id, error_flow_control_error)
      } else {
        s.send = s.send + inc
        self.events.push(WindowUpdated(stream=id, delta=inc))
      }
    None =>
      if self.idle(id) {
        raise self.fail(error_protocol_error, "WINDOW_UPDATE on an idle stream")
      }
  }
}
