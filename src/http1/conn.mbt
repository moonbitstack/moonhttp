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
/// Where one side of a connection is in its half of an exchange.
///
/// These are h11's states (https://h11.readthedocs.io/en/latest/api.html), one per
/// side, read with [`Conn::ours`] and [`Conn::theirs`]. A server that has read a
/// request is `SendResponse` until it answers. A side whose exchange said
/// `Connection: close` ends in `MustClose` rather than `Done`. A client that asked
/// to upgrade waits in `MightSwitch` until the server says yes, which is
/// `Switched` for both, or no, which puts it back to `Done`.
pub(all) enum State {
  Idle
  SendResponse
  SendBody
  Done
  MustClose
  Closed
  MightSwitch
  Switched
  Error
} derive(Eq, Debug)

///|
pub extend State with Eq::{not_equal, equal}

///|
pub extend State with Debug::{to_repr}

///|
/// What a connection reads from its peer, or is given to write.
///
/// A message is always a head, any number of `Data`, then `End`, even when the
/// body is empty, so a consumer handles one sequence. `NeedData` and `Paused` are
/// only ever read: the first asks for more octets, the second says the next
/// message waits for [`Conn::start_next`] or, after a switch, belongs to another
/// protocol.
pub(all) enum Event {
  Request(Request)
  Response(Response)
  // A 1xx: `100 Continue`, or the `101` that switches protocols.
  Informational(Response)
  Data(Bytes)
  // The end of a message, with its trailer fields.
  End(Array[@header.Header])
  NeedData
  Paused
  // Read, the peer closed its side; sent, this side is closing its own.
  Closed
} derive(Eq, Debug)

///|
pub extend Event with Eq::{not_equal, equal}

///|
pub extend Event with Debug::{to_repr}

///|
/// How the peer's body in progress is delimited, and how far into it the reader
/// is.
priv enum Reading {
  Length(Int32)
  // At a chunk-size line.
  Size
  // Inside a chunk, with this many octets of it to come.
  Within(Int32)
  // At the line break after a chunk's octets.
  Break
  ToClose
}

///|
/// How this side's body in progress is delimited.
priv enum Writing {
  Length(Int32)
  Chunks
  ToClose
  // A response to HEAD: written as a GET's would be, with the body dropped.
  Silent
}

///|
/// An HTTP/1.1 connection without a socket (RFC 9112): octets in, events out;
/// events in, octets out.
///
/// The caller owns the I/O. It hands what it reads to [`Conn::receive`], takes
/// events from [`Conn::next`] until `NeedData`, and writes whatever
/// [`Conn::send`] returns. The order of messages, keep-alive, pipelining, framing
/// and protocol switches are checked here, once, by h11's state machine, so a
/// server, a client, a TLS stream and a test over recorded octets all run the
/// same code.
struct Conn {
  role : Role
  limits : Limits
  mut client : State
  mut server : State
  mut held : Bytes
  mut at : Int32
  mut eof : Bool
  mut reading : Reading
  mut writing : Writing
  // The verb of the exchange in progress: it decides a response's framing.
  mut verb : String
  // The version of the peer's last message, empty before the first.
  mut peer : String
  mut keep : Bool
  mut upgrade : Bool
  mut connect : Bool
}

///|
/// A connection at its start, both sides `Idle`.
///
/// `limits` bounds what the peer may send before a message is complete: its
/// head, a chunk-size line, a trailer section. Bodies are handed over as they
/// arrive and are not bounded here.
pub fn Conn::new(role : Role, limits~ : Limits = limits) -> Conn {
  {
    role,
    limits,
    client: Idle,
    server: Idle,
    held: b"",
    at: 0,
    eof: false,
    reading: Length(0),
    writing: Length(0),
    verb: "",
    peer: "",
    keep: true,
    upgrade: false,
    connect: false,
  }
}

///|
/// This side's state.
pub fn Conn::ours(self : Conn) -> State {
  self.state(self.role)
}

///|
/// The peer's state.
pub fn Conn::theirs(self : Conn) -> State {
  self.state(self.other())
}

///|
/// Octets read from the peer. Empty means the peer closed its side.
///
/// Raises [`Refused::Order`] for octets after that, which no transport delivers.
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
/// Bodies come as `Data` in the pieces they arrived in, whether sized, chunked or
/// running to the close. `NeedData` asks for [`Conn::receive`]; while it is
/// returned, the octets held past `limits.head` raise [`Refused::Exceeded`]. A
/// head that does not parse raises what [`request`] or [`response`] would, an
/// event out of order raises `Malformed`, and either way the peer's state becomes
/// `Error` and the connection will not be reused. A server may still answer it:
/// [`Refused::status`] gives the status.
pub fn Conn::next(self : Conn) -> Event raise Refused {
  let them = self.other()
  match self.state(them) {
    Error => raise Order("reading from a peer whose stream already failed")
    MightSwitch | Switched => return Paused
    Done if self.at < self.held.length() => return Paused
    _ => ()
  }
  errdefer self.fail(them)
  let event = self.read()
  if event is NeedData {
    let held = self.held.length() - self.at
    if held > self.limits.head {
      raise Exceeded(limit=self.limits.head, got=held)
    }
    return NeedData
  }
  // An event out of order is the peer's fault when it is read.
  self.process(them, event) catch {
    Order(m) => raise Malformed(m)
    e => raise e
  }
  match event {
    Request(r) => self.reading = reading(r.body)
    Response(r) => self.reading = reading(r.body)
    _ => ()
  }
  event
}

///|
/// The octets that write `event` to the peer.
///
/// A response's framing is decided here rather than trusted. A `Content-Length`
/// field is used as given. Without one the body is chunked to an HTTP/1.1 peer
/// and runs to the close otherwise, with the fields rewritten to say so. A
/// response to HEAD keeps the fields a GET would get and drops the body. A
/// `Connection: close` is added whenever the connection will not be reused, and
/// `Connection: keep-alive` for an HTTP/1.0 peer when it will. A request is
/// written as given, framed by its own fields.
///
/// Raises [`Refused::Order`] for an event this side may not send now: data before
/// a head, more body than its `Content-Length`, a body that ends short of it. This
/// side's state then becomes `Error`.
pub fn Conn::send(self : Conn, event : Event) -> Bytes raise Refused {
  if self.ours() is Error {
    raise Order("sending after this side already failed")
  }
  errdefer self.fail(self.role)
  self.write(event)
}

///|
/// Begin the next exchange on a kept-alive connection.
///
/// Both sides must be `Done`; a side in `MustClose` means the connection is to be
/// closed instead. A pipelined request already received is read by the next
/// [`Conn::next`].
pub fn Conn::start_next(self : Conn) -> Unit raise Refused {
  guard self.client is Done && self.server is Done else {
    raise Order("a new exchange before both sides are done")
  }
  self.client = Idle
  self.server = Idle
  self.verb = ""
  self.reading = Length(0)
  self.writing = Length(0)
}

///|
/// The octets received but not read as HTTP.
///
/// After a switch these belong to the new protocol: a WebSocket frame that came
/// in the same segment as the upgrade request, for instance.
pub fn Conn::trailing(self : Conn) -> Bytes {
  self.held[self.at:].to_owned()
}

// -- the state machine --------------------------------------------------------

///|
fn Conn::other(self : Conn) -> Role {
  match self.role {
    Server => Client
    Client => Server
  }
}

///|
fn Conn::state(self : Conn, of : Role) -> State {
  match of {
    Client => self.client
    Server => self.server
  }
}

///|
fn Conn::set(self : Conn, of : Role, to : State) -> Unit {
  match of {
    Client => self.client = to
    Server => self.server = to
  }
}

///|
/// The side that raised, or was found at fault, is `Error`, and the connection is
/// not reused.
fn Conn::fail(self : Conn, of : Role) -> Unit {
  self.set(of, Error)
  self.keep = false
  self.settle()
}

///|
/// One event through the state machine: the transition it makes on the side that
/// sent it, the bookkeeping it carries, then the transitions that follow from the
/// two states together (h11's `ConnectionState`).
fn Conn::process(
  self : Conn,
  actor : Role,
  event : Event,
) -> Unit raise Refused {
  let switch = match (actor, event) {
    (Server, Informational(r)) if r.status == 101 => {
      guard self.upgrade else {
        raise Order("a 101 to a request that did not ask to upgrade")
      }
      true
    }
    (Server, Response(r)) => self.connect && r.status < 300
    _ => false
  }
  let from = self.state(actor)
  let to : State? = match (actor, from, event) {
    (_, Idle | Done | MustClose | Closed, Closed) => Some(Closed)
    (Client, Idle, Request(_)) => Some(SendBody)
    (_, SendBody, Data(_)) => Some(SendBody)
    (_, SendBody, End(_)) => Some(Done)
    (Server, Idle, Response(_)) => Some(SendBody)
    (Server, SendResponse, Informational(_)) =>
      Some(if switch { Switched } else { SendResponse })
    (Server, SendResponse, Response(_)) =>
      Some(if switch { Switched } else { SendBody })
    _ => None
  }
  guard to is Some(to) else { raise Order(what(event) + " out of order") }
  self.set(actor, to)
  match event {
    Request(r) => {
      guard self.server is Idle else {
        raise Order("a request before the last response")
      }
      self.server = SendResponse
      self.verb = r.verb
      self.connect = r.verb == "CONNECT"
      self.upgrade = r.field("upgrade") is Some(_)
      if !r.keep_alive {
        self.keep = false
      }
    }
    Response(r) => {
      if !switch {
        self.upgrade = false
        self.connect = false
      }
      // A body that runs to the close leaves nothing to reuse.
      if !r.keep_alive || r.body is Closed {
        self.keep = false
      }
    }
    _ => ()
  }
  if actor != self.role {
    match event {
      Request(r) => self.peer = r.version
      Response(r) | Informational(r) => self.peer = r.version
      _ => ()
    }
  }
  self.settle()
}

///|
/// The transitions that follow from where both sides stand, rather than from an
/// event.
fn Conn::settle(self : Conn) -> Unit {
  let proposed = self.upgrade || self.connect
  if proposed && self.client is Done {
    self.client = MightSwitch
  }
  if !proposed && self.client is MightSwitch {
    self.client = Done
  }
  if !self.keep {
    if self.client is Done {
      self.client = MustClose
    }
    if self.server is Done {
      self.server = MustClose
    }
  }
  match (self.client, self.server) {
    (MightSwitch, Switched) => self.client = Switched
    (Closed, Done | Idle) | (Error, Done) => self.server = MustClose
    (Done | Idle, Closed) | (Done, Error) => self.client = MustClose
    _ => ()
  }
}

///|
fn what(event : Event) -> String {
  match event {
    Request(_) => "a request"
    Response(_) => "a response"
    Informational(_) => "an informational response"
    Data(_) => "body data"
    End(_) => "the end of a message"
    Closed => "a close"
    NeedData | Paused => "a read-only event"
  }
}

// -- reading ------------------------------------------------------------------

///|
fn reading(body : Body) -> Reading {
  match body {
    Empty => Length(0)
    Sized(n) => Length(n)
    Chunked => Size
    Closed => ToClose
  }
}

///|
/// The next event in the held octets, before the state machine sees it.
fn Conn::read(self : Conn) -> Event raise Refused {
  let data = self.held[self.at:]
  match self.theirs() {
    Idle | SendResponse => self.head(data)
    SendBody => self.body(data)
    _ => {
      if data.length() > 0 {
        raise Malformed("octets after the last message")
      }
      if self.eof {
        Closed
      } else {
        NeedData
      }
    }
  }
}

///|
fn Conn::head(self : Conn, data : BytesView) -> Event raise Refused {
  match self.role {
    Server => {
      let (r, used) = request(data, limits=self.limits) catch {
        Partial => return self.wait(data.length() == 0)
        e => raise e
      }
      // RFC 9112 §3.2: a server must answer 400 to an HTTP/1.1 request with no
      // Host, and to any request with more than one.
      let hosts = r.fields.iter().filter(f => f.name == ascii("host")).count()
      if hosts > 1 {
        raise Malformed("more than one Host field")
      }
      if hosts == 0 && r.version == "HTTP/1.1" {
        raise Malformed("an HTTP/1.1 request with no Host field")
      }
      self.at = self.at + used
      Request(r)
    }
    Client => {
      let (r, used) = response(data, verb=self.verb, limits=self.limits) catch {
        Partial => return self.wait(data.length() == 0)
        e => raise e
      }
      self.at = self.at + used
      if r.status < 200 {
        Informational(r)
      } else {
        Response(r)
      }
    }
  }
}

///|
fn Conn::body(self : Conn, data : BytesView) -> Event raise Refused {
  match self.reading {
    Length(0) => End([])
    Length(n) =>
      match self.take(data, n) {
        Some(part) => {
          self.reading = Length(n - part.length())
          Data(part)
        }
        None => self.wait(false)
      }
    Size => {
      let (size, used) = chunk_size(data) catch {
        Partial => return self.wait(false)
        e => raise e
      }
      if size == 0 {
        let (trailers, more) = trailer(data[used:]) catch {
          Partial => return self.wait(false)
          e => raise e
        }
        self.at = self.at + used + more
        return End(trailers)
      }
      self.at = self.at + used
      self.reading = Within(size)
      self.body(data[used:])
    }
    Within(n) =>
      match self.take(data, n) {
        Some(part) => {
          let left = n - part.length()
          self.reading = if left == 0 { Break } else { Within(left) }
          Data(part)
        }
        None => self.wait(false)
      }
    Break => {
      match data {
        [b'\n', ..] => self.at = self.at + 1
        [b'\r', b'\n', ..] => self.at = self.at + 2
        [] | [b'\r'] => return self.wait(false)
        _ => raise Malformed("a chunk not terminated by a break")
      }
      self.reading = Size
      self.body(self.held[self.at:])
    }
    ToClose =>
      if data.length() > 0 {
        self.at = self.held.length()
        Data(data.to_owned())
      } else if self.eof {
        End([])
      } else {
        NeedData
      }
  }
}

///|
/// Up to `n` held octets, or `None` when none are held.
fn Conn::take(self : Conn, data : BytesView, n : Int32) -> Bytes? {
  if data.length() == 0 {
    return None
  }
  let k = if data.length() < n { data.length() } else { n }
  self.at = self.at + k
  Some(data[0:k].to_owned())
}

///|
/// What an incomplete event comes to: more octets to wait for, a peer that left
/// between messages, or a peer that left partway through one.
fn Conn::wait(self : Conn, between : Bool) -> Event raise Refused {
  if !self.eof {
    return NeedData
  }
  if between && self.theirs() is Idle {
    return Closed
  }
  raise Malformed("the peer closed partway through a message")
}

// -- writing ------------------------------------------------------------------

///|
fn Conn::write(self : Conn, event : Event) -> Bytes raise Refused {
  match event {
    Request(r) => {
      guard self.role is Client else {
        raise Order("a server does not send requests")
      }
      let body = framing(r.fields, true) catch {
        e => raise Order("a request whose framing does not read: \{e}")
      }
      self.process(Client, event)
      self.writing = match body {
        Chunked => Chunks
        Sized(n) => Length(n)
        _ => Length(0)
      }
      r.encode()
    }
    Informational(r) => {
      guard self.role is Server else {
        raise Order("a client does not send responses")
      }
      guard r.status >= 100 && r.status < 200 else {
        raise Order("an informational status is 1xx")
      }
      self.process(Server, event)
      r.encode()
    }
    Response(r) => {
      guard self.role is Server else {
        raise Order("a client does not send responses")
      }
      guard r.status >= 200 && r.status < 1000 else {
        raise Order("a final status is three digits from 200")
      }
      let (r, writing) = self.frame(r)
      self.process(Server, Response(r))
      self.writing = writing
      r.encode()
    }
    Data(d) => {
      self.process(self.role, event)
      match self.writing {
        Length(n) => {
          if d.length() > n {
            raise Order("more body than the message declared")
          }
          self.writing = Length(n - d.length())
          d
        }
        Chunks => if d.length() == 0 { b"" } else { chunk(d[:]) }
        ToClose => d
        Silent => b""
      }
    }
    End(trailers) => {
      self.process(self.role, event)
      match self.writing {
        Chunks => last_chunk(trailers~)
        Silent => b""
        Length(n) => {
          if n > 0 {
            raise Order("a body that ended short of its Content-Length")
          }
          if trailers.length() > 0 {
            raise Order("trailer fields need a chunked body")
          }
          b""
        }
        ToClose => {
          if trailers.length() > 0 {
            raise Order("trailer fields need a chunked body")
          }
          b""
        }
      }
    }
    Closed => {
      self.process(self.role, event)
      b""
    }
    NeedData | Paused => raise Order("not an event one sends")
  }
}

///|
/// A response with its framing fields made true, and how its body is written
/// (h11's `_clean_up_response_headers_for_sending`).
fn Conn::frame(self : Conn, r : Response) -> (Response, Writing) raise Refused {
  let head = self.verb == "HEAD"
  let mut fields = r.fields.copy()
  // A response nobody asked for, an error answering a request that did not parse,
  // ends the connection.
  let mut close = !self.keep ||
    !r.keep_alive ||
    self.server is Idle ||
    token(fields, "connection", "close")
  let writing : Writing = if r.status == 204 ||
    r.status == 304 ||
    (self.verb == "CONNECT" && r.status < 300) {
    Length(0)
  } else {
    let declared = framing(fields, false) catch {
      e => raise Order("a response whose framing does not read: \{e}")
    }
    match declared {
      Sized(n) => if head { Silent } else { Length(n) }
      Empty if find(fields, "content-length") is Some(_) =>
        if head {
          Silent
        } else {
          Length(0)
        }
      _ => {
        fields = without(fields, "content-length")
        fields = without(fields, "transfer-encoding")
        if self.peer == "HTTP/1.1" {
          fields.push(@header.Header::of("transfer-encoding", "chunked"))
          if head {
            Silent
          } else {
            Chunks
          }
        } else if head {
          Silent
        } else {
          close = true
          ToClose
        }
      }
    }
  }
  if close {
    fields = closing(fields)
  } else if self.peer == "HTTP/1.0" && find(fields, "connection") is None {
    fields.push(@header.Header::of("connection", "keep-alive"))
  }
  ({ ..r, fields, keep_alive: !close, }, writing)
}

///|
fn without(
  fields : Array[@header.Header],
  name : String,
) -> Array[@header.Header] {
  let n = ascii(name)
  fields.filter(f => f.name != n)
}

///|
/// The fields with `Connection` saying `close`: other connection options are
/// kept, `keep-alive` is dropped.
fn closing(fields : Array[@header.Header]) -> Array[@header.Header] {
  let options : Array[String] = []
  for f in fields {
    if f.name == ascii("connection") {
      for o in text(f.value[:]).split(",") {
        let o = o.trim().to_owned().to_lower()
        if o != "" && o != "keep-alive" && !options.contains(o) {
          options.push(o)
        }
      }
    }
  }
  if !options.contains("close") {
    options.push("close")
  }
  let out = without(fields, "connection")
  out.push(@header.Header::of("connection", options.join(", ")))
  out
}
