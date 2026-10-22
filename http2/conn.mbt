// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which end of a connection a [`Conn`] is.
pub(all) enum Role {
  Server
  Client
} derive(Eq, Debug)

///|
pub extend Role with Eq::{not_equal, equal}

///|
pub extend Role with Debug::{to_repr}

///|
/// What a connection reads from its peer.
///
/// As in `http1`, a message is a head, any number of `Data`, then `End`; trailers
/// come as `Trailers` before the `End`. `Reset` with `remote=false` is a stream this
/// side refused, with the RST_STREAM already queued. `Settings` and `Ping` have
/// already been acknowledged when they are read.
pub(all) enum Event {
  Request(stream~ : Int32, fields~ : Array[@header.Header])
  Response(stream~ : Int32, fields~ : Array[@header.Header])
  // A 1xx response, of which a stream may have several before its final one.
  Informational(stream~ : Int32, fields~ : Array[@header.Header])
  Trailers(stream~ : Int32, fields~ : Array[@header.Header])
  Data(stream~ : Int32, data~ : Bytes)
  End(stream~ : Int32)
  Reset(stream~ : Int32, code~ : Int32, remote~ : Bool)
  // The server promised `promised`, a response to the request in `fields`, on
  // the client's stream `stream`.
  Pushed(stream~ : Int32, promised~ : Int32, fields~ : Array[@header.Header])
  // Stream 0 is the connection.
  WindowUpdated(stream~ : Int32, delta~ : Int32)
  // The peer's settings, now in force.
  Settings(Settings)
  // This side's settings, now that the peer has acknowledged them.
  SettingsAcked(Settings)
  Ping(Bytes)
  PingAcked(Bytes)
  GoAway(code~ : Int32, last~ : Int32, debug~ : Bytes)
  NeedData
  // The peer closed the transport.
  Closed
} derive(Eq, Debug)

///|
pub extend Event with Eq::{not_equal, equal}

///|
pub extend Event with Debug::{to_repr}

///|
/// Where a stream that is not idle or closed stands (RFC 9113 §5.1).
priv enum Phase {
  ReservedLocal
  ReservedRemote
  Open
  // This side has sent END_STREAM.
  HalfLocal
  // The peer has.
  HalfRemote
}

///|
priv struct Stream {
  id : Int32
  mut phase : Phase
  // How much this side may still send.
  mut send : Int32
  recv : Window
  // This side's final head has gone out, so a further HEADERS is trailers.
  mut sent : Bool
  // The peer's has arrived.
  mut got : Bool
  // The peer's declared content-length, checked against what arrives (§8.1.1).
  mut length : Int32?
  mut received : Int32
  // The request was HEAD, so the response has no body whatever it declares.
  mut head : Bool
}

///|
/// A field block waiting for its CONTINUATION frames (§6.10).
priv struct Block {
  stream : Int32
  // The stream a PUSH_PROMISE promises, `None` for HEADERS.
  promised : Int32?
  end : Bool
  buf : Buffer
  // The HEADERS frame made the stream depend on itself (§5.3.1).
  looped : Bool
}

///|
/// How many closed streams a connection remembers, to tell a frame that crossed
/// this side's RST_STREAM in flight, which §5.4.2 says to ignore, from one sent on
/// a stream long finished.
let remembered : Int32 = 256

///|
/// An HTTP/2 connection without a socket (RFC 9113): octets in, events out; calls
/// in, octets out.
///
/// The caller owns the I/O. It hands what it reads to [`Conn::receive`], takes
/// events from [`Conn::next`] until `NeedData`, and writes whatever [`Conn::take`]
/// returns, which may be frames the connection queued on its own: the opening
/// SETTINGS, acknowledgements, window updates, resets. The design is python-hyper
/// h2's (https://python-hyper.org/projects/h2/): stream states, flow control,
/// settings, header compression and field validation are kept here once, so a
/// server, a client and a test over recorded octets all run the same code.
struct Conn {
  role : Role
  // Settings in force: acknowledged by the peer.
  mut mine : Settings
  // Settings sent and not yet acknowledged, oldest first.
  pending : Array[Settings]
  mut theirs : Settings
  enc : @hpack.Encoder
  dec : @hpack.Decoder
  // A table size the encoder owes the peer at the start of its next block (RFC
  // 7541 §4.2).
  mut resize : Int32?
  streams : Map[Int32, Stream]
  // Recently closed streams: `true` when this side reset them.
  closed : Map[Int32, Bool]
  order : Array[Int32]
  mut held : Bytes
  mut at : Int32
  mut eof : Bool
  out : Buffer
  events : Array[Event]
  // A server has read the client's preface.
  mut preface : Bool
  // The peer's first SETTINGS has arrived.
  mut greeted : Bool
  recv : Window
  mut send : Int32
  // The next stream id this side may open or promise.
  mut next_id : Int32
  // The highest stream id the peer has opened or promised.
  mut last_peer : Int32
  mut block : Block?
  // The last stream id this side's GOAWAY said it would process.
  mut told : Int32?
  // The last stream id the peer's GOAWAY said it would process.
  mut gone : Int32?
  mut dead : Bool
}

///|
/// A connection at its start, with its opening frames queued: the client's
/// preface and SETTINGS, or the server's SETTINGS (§3.4).
///
/// `settings` take effect when the peer acknowledges them; until then both ends go
/// by [`initial`]. Settings outside what §6.5.2 allows abort, since no peer could
/// accept them.
pub fn Conn::new(role : Role, settings~ : Settings = settings) -> Conn {
  if settings.fault() is Some(why) {
    abort("http2.Conn::new: \{why}")
  }
  let conn = {
    role,
    mine: initial,
    pending: [settings],
    theirs: initial,
    enc: @hpack.Encoder::new(),
    dec: @hpack.Decoder::new(),
    resize: None,
    streams: Map([]),
    closed: Map([]),
    order: [],
    held: b"",
    at: 0,
    eof: false,
    out: Buffer(),
    events: [],
    preface: false,
    greeted: false,
    recv: Window::new(initial.initial_window_size),
    send: initial.initial_window_size,
    next_id: if role is Client {
      1
    } else {
      2
    },
    last_peer: 0,
    block: None,
    told: None,
    gone: None,
    dead: false,
  }
  if role is Client {
    conn.out.write_bytes(preface)
  }
  conn.write(Frame::Settings(params=settings.pairs(initial, role), ack=false))
  conn
}

///|
/// Octets read from the peer. Empty means the peer closed the transport.
pub fn Conn::receive(self : Conn, data : BytesView) -> Unit raise Refused {
  if data.length() == 0 {
    self.eof = true
    return
  }
  if self.eof {
    raise Order("octets received after the peer closed")
  }
  let buf = Buffer(size_hint=self.held.length() - self.at + data.length())
  buf.write_bytesview(self.held[self.at:])
  buf.write_bytesview(data)
  self.held = buf.to_bytes()
  self.at = 0
}

///|
/// The next event from the peer.
///
/// A connection error raises `Connection` with the GOAWAY already queued in
/// [`Conn::take`], after which the connection is finished. A stream error does not
/// raise: the RST_STREAM is queued and the stream ends with `Reset`.
pub fn Conn::next(self : Conn) -> Event raise Refused {
  if self.events.length() > 0 {
    return self.events.remove(0)
  }
  if self.dead {
    raise Order("the connection already failed")
  }
  while self.frame() {
    if self.events.length() > 0 {
      return self.events.remove(0)
    }
  }
  if self.eof {
    Closed
  } else {
    NeedData
  }
}

///|
/// The octets queued for the peer since the last call.
pub fn Conn::take(self : Conn) -> Bytes {
  let out = self.out.to_bytes()
  self.out.reset()
  out
}

///|
/// This side's settings in force.
pub fn Conn::settings(self : Conn) -> Settings {
  self.mine
}

///|
/// The peer's settings in force.
pub fn Conn::peer_settings(self : Conn) -> Settings {
  self.theirs
}

///|
/// The id the next stream this side opens, or the next push it promises, will
/// have.
pub fn Conn::next_stream(self : Conn) -> Int32 {
  self.next_id
}

///|
/// How much this side may send on `stream` now, the smaller of its own window and
/// the connection's; stream 0 is the connection alone.
pub fn Conn::window(self : Conn, stream : Int32) -> Int32 {
  let n = if stream == 0 {
    self.send
  } else {
    match self.streams.get(stream) {
      Some(s) => if s.send < self.send { s.send } else { self.send }
      None => 0
    }
  }
  if n < 0 {
    0
  } else {
    n
  }
}

// -- bookkeeping --------------------------------------------------------------

///|
fn Conn::write(self : Conn, frame : Frame) -> Unit {
  self.out.write_bytes(frame.encode())
}

///|
/// Whether `id` is one the peer opens: odd from a client, even from a server.
fn Conn::peers(self : Conn, id : Int32) -> Bool {
  (id % 2 == 1) == (self.role is Server)
}

///|
/// Whether neither end has used `id` yet.
fn Conn::idle(self : Conn, id : Int32) -> Bool {
  if self.peers(id) {
    id > self.last_peer
  } else {
    id >= self.next_id
  }
}

///|
/// How many streams one side has open, counting toward the other's
/// SETTINGS_MAX_CONCURRENT_STREAMS (§5.1.2); reserved streams do not count.
fn Conn::active(self : Conn, peer : Bool) -> Int32 {
  let mut n = 0
  for id, s in self.streams {
    if self.peers(id) == peer && !(s.phase is (ReservedLocal | ReservedRemote)) {
      n = n + 1
    }
  }
  n
}

///|
/// The settings this side is moving to: the last one sent, acknowledged or not.
///
/// Limits that protect this side (header list size, concurrent streams) are held
/// to these at once rather than after the acknowledgement, which leaves a peer free
/// to retry a refused stream.
fn Conn::strict(self : Conn) -> Settings {
  match self.pending.last() {
    Some(s) => s
    None => self.mine
  }
}

///|
/// A stream that has just started, with windows from both ends' settings in force.
fn Conn::stream(self : Conn, id : Int32, phase : Phase) -> Stream {
  let s = {
    id,
    phase,
    send: self.theirs.initial_window_size,
    recv: Window::new(self.mine.initial_window_size),
    sent: false,
    got: false,
    length: None,
    received: 0,
    head: false,
  }
  self.streams[id] = s
  s
}

///|
fn Conn::close(self : Conn, id : Int32, reset : Bool) -> Unit {
  self.streams.remove(id)
  self.closed[id] = reset
  self.order.push(id)
  if self.order.length() > remembered {
    self.closed.remove(self.order.remove(0))
  }
}

///|
/// A stream error (§5.4.2): RST_STREAM queued, and `Reset` for a stream the caller
/// has heard of.
fn Conn::refuse(self : Conn, id : Int32, code : Int32) -> Unit {
  self.write(Frame::RstStream(stream_id=id, error_code=code))
  if self.streams.contains(id) {
    self.events.push(Reset(stream=id, code~, remote=false))
  }
  self.close(id, true)
}

///|
/// A connection error (§5.4.1): GOAWAY queued with `msg` as its debug data, and
/// the error to raise.
fn Conn::fail(self : Conn, code : Int32, msg : String) -> Refused {
  self.write(
    Frame::GoAway(
      last_stream_id=self.last(),
      error_code=code,
      debug=octets(msg),
    ),
  )
  self.dead = true
  Connection(code~, msg)
}

///|
/// The last peer stream a GOAWAY may name: never more than an earlier one named
/// (§6.8).
fn Conn::last(self : Conn) -> Int32 {
  match self.told {
    Some(t) if t < self.last_peer => t
    _ => self.last_peer
  }
}

///|
/// Hand `n` octets back to the connection window, with the WINDOW_UPDATE that is
/// due.
fn Conn::credit(self : Conn, n : Int32) -> Unit {
  let inc = self.recv.process(n)
  if inc > 0 {
    self.write(Frame::WindowUpdate(stream_id=0, increment=inc))
  }
}

///|
/// The same for a stream, while the peer may still send on it.
fn Conn::credit_stream(self : Conn, s : Stream, n : Int32) -> Unit {
  if s.phase is (Open | HalfLocal) {
    let inc = s.recv.process(n)
    if inc > 0 {
      self.write(Frame::WindowUpdate(stream_id=s.id, increment=inc))
    }
  }
}

///|
/// Text as octets, one per code unit.
fn octets(s : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < s.length(); i = i + 1 {
    buf.write_byte((s[i].to_int() & 0xff).to_byte())
  }
  buf.to_bytes()
}
