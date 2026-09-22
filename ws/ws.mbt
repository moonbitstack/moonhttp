// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A protocol violation, carrying the status the connection must then be failed with
/// (RFC 6455 §7.4.1, §7.1.7).
///
/// This is not end of stream: a peer that simply stops sending has not violated anything,
/// and the connection closes without a status.
pub(all) suberror Refused {
  /// The peer broke the framing: a set RSV bit with no extension negotiated, a reserved
  /// opcode, a client frame that is not masked, a control frame that is fragmented or
  /// longer than 125 bytes, a continuation with no message in progress, or a new data
  /// frame before the last one finished.
  Protocol(String)
  /// A text message or close reason whose bytes are not UTF-8 (§8.1), or a close code
  /// §7.4.1 does not allow on the wire.
  Payload(String)
  /// The peer announced or sent more than this endpoint accepts.
  Exceeded(limit~ : Int, got~ : Int64)
} derive(Eq, Debug)

///|
/// The §7.4.1 status a violation is closed with: `1002` for framing, `1007` for payload,
/// `1009` for size.
pub fn Refused::status(self : Refused) -> Int {
  match self {
    Protocol(_) => 1002
    Payload(_) => 1007
    Exceeded(..) => 1009
  }
}

///|
/// A refusal prints as the fault it is, with the code the wire will carry.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Protocol(m) => logger.write_string("Protocol(1002, " + m + ")")
    Payload(m) => logger.write_string("Payload(1007, " + m + ")")
    Exceeded(limit~, got~) =>
      logger.write_string("Exceeded(1009, limit=\{limit}, got=\{got})")
  }
}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

///|
/// How many bytes of payload this endpoint accepts, in one frame and in a message
/// reassembled from many.
///
/// Sixteen mebibytes is uvicorn's `--ws-max-size`. The ceiling has to bound the
/// reassembled message and not only each fragment, because a message split into enough
/// small frames would otherwise pass every per-frame check and still exhaust memory.
pub let limit : Int = 16 * 1024 * 1024

///|
/// A frame opcode (RFC 6455 §5.2): the three data opcodes and the three control ones.
pub(all) enum Opcode {
  Continuation
  Text
  Binary
  Close
  Ping
  Pong
} derive(Eq, Debug)

///|
/// The four-bit value on the wire.
pub fn Opcode::code(self : Opcode) -> Int {
  match self {
    Continuation => 0x0
    Text => 0x1
    Binary => 0x2
    Close => 0x8
    Ping => 0x9
    Pong => 0xa
  }
}

///|
/// The opcode a wire value names, or `None` when §5.2 reserves it.
pub fn Opcode::of(code : Int) -> Opcode? {
  match code {
    0x0 => Some(Continuation)
    0x1 => Some(Text)
    0x2 => Some(Binary)
    0x8 => Some(Close)
    0x9 => Some(Ping)
    0xa => Some(Pong)
    _ => None
  }
}

///|
/// Whether this is a control opcode, which §5.5 holds to tighter rules than a data
/// frame: at most 125 bytes of payload, and never fragmented.
pub fn Opcode::is_control(self : Opcode) -> Bool {
  match self {
    Close | Ping | Pong => true
    Continuation | Text | Binary => false
  }
}

///|
/// A frame (RFC 6455 §5.2): its FIN bit, its opcode, and its payload already unmasked.
pub(all) struct Frame {
  fin : Bool
  opcode : Opcode
  payload : Bytes
} derive(Eq, Debug)

///|
/// A frame on the wire (RFC 6455 §5.2).
///
/// A four-byte `mask` sets the MASK bit and masks the payload. A client must mask every
/// frame and a server must mask none (§5.1), and the key has to be unpredictable, so it
/// comes from the caller: this package has no randomness and should not pretend to.
///
/// The length takes the shortest of the three forms — seven bits up to 125, sixteen bits
/// under `126`, sixty-four under `127`.
pub fn Frame::encode(self : Frame, mask? : Bytes = b"") -> Bytes {
  let buf = Buffer()
  let first = (if self.fin { 0x80 } else { 0 }) | self.opcode.code()
  buf.write_byte(first.to_byte())
  let masked = mask.length() == 4
  let n = self.payload.length()
  let flag = if masked { 0x80 } else { 0 }
  if n <= 125 {
    buf.write_byte((flag | n).to_byte())
  } else if n <= 0xffff {
    buf.write_byte((flag | 126).to_byte())
    buf.write_byte((n >> 8).to_byte())
    buf.write_byte(n.to_byte())
  } else {
    buf.write_byte((flag | 127).to_byte())
    let len = n.to_int64()
    for i = 7; i >= 0; i = i - 1 {
      buf.write_byte((len >> (i * 8)).to_byte())
    }
  }
  if masked {
    buf.write_bytes(mask)
    for i = 0; i < n; i = i + 1 {
      buf.write_byte(
        (self.payload[i].to_int() ^ mask[i % 4].to_int()).to_byte(),
      )
    }
  } else {
    buf.write_bytes(self.payload)
  }
  buf.to_bytes()
}

///|
/// Check a frame's first two bytes and its announced length, answering with the opcode.
///
/// `client` says the frames being read came from a client, whose frames must be masked
/// (§5.1); a server's must not be, and reading those takes `client=false`.
///
/// Run this before reading the payload. It is the length check that keeps a sixty-four
/// bit length from being truncated into a short allocation, and keeps an honest but
/// enormous one from being allocated at all — the sign bit included, which §5.2 reserves.
pub fn check(
  b0 : Int,
  b1 : Int,
  len : Int64,
  client~ : Bool,
  limit? : Int = limit,
) -> Opcode raise Refused {
  if (b0 & 0x70) != 0 {
    raise Protocol("an RSV bit is set with no extension negotiated")
  }
  guard Opcode::of(b0 & 0x0f) is Some(opcode) else {
    raise Protocol("a reserved opcode")
  }
  if client && (b1 & 0x80) == 0 {
    raise Protocol("a client frame that is not masked")
  }
  if opcode.is_control() {
    if len > 125L {
      raise Protocol("a control frame carrying more than 125 bytes")
    }
    if (b0 & 0x80) == 0 {
      raise Protocol("a fragmented control frame")
    }
  }
  if len < 0L || len > limit.to_int64() {
    raise Exceeded(limit~, got=len)
  }
  opcode
}

///|
/// One frame at the start of `b`, with its payload unmasked, and how many bytes it took.
///
/// `None` means `b` does not hold a whole frame yet, so a caller feeds it more and asks
/// again. A frame that breaks the rules is refused rather than answered `None`, so a
/// violation is never mistaken for a short buffer.
pub fn decode(
  b : BytesView,
  client? : Bool = true,
  limit? : Int = limit,
) -> (Frame, Int)? raise Refused {
  if b.length() < 2 {
    return None
  }
  let b0 = b[0].to_int()
  let b1 = b[1].to_int()
  let mut at = 2
  let mut len = (b1 & 0x7f).to_int64()
  if len == 126L {
    if b.length() < at + 2 {
      return None
    }
    len = ((b[at].to_int() << 8) | b[at + 1].to_int()).to_int64()
    at = at + 2
  } else if len == 127L {
    if b.length() < at + 8 {
      return None
    }
    let mut wide = 0L
    for i = 0; i < 8; i = i + 1 {
      wide = (wide << 8) | b[at + i].to_int().to_int64()
    }
    len = wide
    at = at + 8
  }
  let opcode = check(b0, b1, len, client~, limit~)
  // `check` bounded it, so narrowing cannot truncate.
  let n = len.to_int()
  let masked = (b1 & 0x80) != 0
  let mut key = 0
  if masked {
    if b.length() < at + 4 {
      return None
    }
    key = at
    at = at + 4
  }
  if b.length() < at + n {
    return None
  }
  let payload = Buffer()
  for i = 0; i < n; i = i + 1 {
    if masked {
      payload.write_byte(
        (b[at + i].to_int() ^ b[key + i % 4].to_int()).to_byte(),
      )
    } else {
      payload.write_byte(b[at + i])
    }
  }
  Some(
    ({ fin: (b0 & 0x80) != 0, opcode, payload: payload.to_bytes(), }, at + n),
  )
}

///|
/// A complete application message: text with its payload decoded, binary with its bytes,
/// or a close with its status and reason.
///
/// Control frames do not surface here — a `Reader` answers a ping itself — so an
/// application sees what it sent and received and nothing of the protocol's upkeep.
///
/// Text carries a `String` rather than bytes because §8.1 makes invalid UTF-8 a `1007`
/// failure: bytes that would not decode never get this far, so nothing hands an
/// application a message the peer did not send.
pub(all) enum Message {
  Text(String)
  Binary(Bytes)
  Close(status~ : Int, reason~ : Bytes)
} derive(Eq, Debug)

///|
/// A close frame's payload (RFC 6455 §5.5.1): the status big-endian, then the reason.
pub fn close(status : Int, reason? : String = "") -> Bytes {
  let buf = Buffer()
  buf.write_byte((status >> 8).to_byte())
  buf.write_byte(status.to_byte())
  buf.write_bytes(@utf8.encode(reason))
  buf.to_bytes()
}

///|
/// The status a close payload carries, or `1005` when it carries none (§7.1.5).
///
/// `1005` is a local sentinel and must never be sent: a close that came with no status is
/// echoed with no status, not with this number.
pub fn status(payload : BytesView) -> Int {
  if payload.length() >= 2 {
    (payload[0].to_int() << 8) | payload[1].to_int()
  } else {
    1005
  }
}

///|
/// The reason a close payload carries — everything after the two status bytes.
pub fn reason(payload : BytesView) -> Bytes {
  if payload.length() > 2 {
    payload[2:].to_owned()
  } else {
    b""
  }
}

///|
/// Whether a status may appear on the wire (RFC 6455 §7.4.1 and the IANA registry).
///
/// `1004` is reserved, and `1005`, `1006` and `1015` are sentinels an endpoint sets
/// locally — a peer that sends one has broken the protocol. `1012` through `1014` were
/// registered after RFC 6455 and are allowed here, because refusing a registered status
/// would break a real deployment for the sake of a closed reading of §7.4.1.
pub fn allowed(status : Int) -> Bool {
  (status >= 1000 && status <= 1003) ||
  (status >= 1007 && status <= 1014) ||
  (status >= 3000 && status <= 4999)
}

///|
/// What a frame made of the connection: a message when it finished one, and a frame to
/// send back when the protocol owes one.
///
/// A ping owes a pong, and a close owes a close (§5.5.1). The reply comes back as a frame
/// rather than as bytes because a client has to mask what it sends and only the caller
/// has the randomness to do it with.
pub(all) struct Step {
  message : Message?
  reply : Frame?
} derive(Eq, Debug)

///|
/// The state of one direction: what has been assembled so far, and of what kind.
pub struct Reader {
  payload : Buffer
  mut kind : Opcode?
  limit : Int
}

///|
/// A reader with nothing assembled.
pub fn Reader::new(limit? : Int = limit) -> Reader {
  { payload: Buffer(), kind: None, limit, }
}

///|
/// How many bytes of the message in progress have been assembled.
pub fn Reader::pending(self : Reader) -> Int {
  self.payload.length()
}

///|
/// Take one frame (RFC 6455 §5.4 for fragments, §5.5 for the control frames interleaved
/// with them).
///
/// A ping is answered with a pong carrying the same payload, a pong is dropped, and a
/// close is echoed and then reported. A data frame extends or finishes the message.
pub fn Reader::feed(self : Reader, frame : Frame) -> Step raise Refused {
  match frame.opcode {
    Ping =>
      {
        message: None,
        reply: Some({ fin: true, opcode: Pong, payload: frame.payload, }),
      }
    Pong => { message: None, reply: None, }
    Close => {
      let got = status(frame.payload[:])
      if frame.payload.length() >= 2 && !allowed(got) {
        raise Payload(
          "a close status §7.4.1 does not allow on the wire: \{got}",
        )
      }
      let why = reason(frame.payload[:])
      if why.length() > 0 {
        let _ = @utf8.decode(why[:]) catch {
          _ => raise Payload("a close reason that is not valid UTF-8")
        }
      }
      // A close that carried no status is echoed with none: 1005 is local and must not
      // reach the wire.
      let echo = if frame.payload.length() >= 2 { close(got) } else { b"" }
      {
        message: Some(Close(status=got, reason=why)),
        reply: Some({ fin: true, opcode: Close, payload: echo, }),
      }
    }
    Text | Binary => {
      if self.kind is Some(_) {
        raise Protocol("a new data frame before the last message finished")
      }
      self.kind = Some(frame.opcode)
      self.add(frame.payload)
      if frame.fin {
        self.finish()
      } else {
        { message: None, reply: None, }
      }
    }
    Continuation => {
      if self.kind is None {
        raise Protocol("a continuation frame with no message in progress")
      }
      self.add(frame.payload)
      if frame.fin {
        self.finish()
      } else {
        { message: None, reply: None, }
      }
    }
  }
}

///|
/// Extend the message being assembled, refusing once the total passes the ceiling. A
/// per-frame check alone would not bound a message split into enough small fragments.
fn Reader::add(self : Reader, part : Bytes) -> Unit raise Refused {
  let total = self.payload.length() + part.length()
  if total > self.limit {
    raise Exceeded(limit=self.limit, got=total.to_int64())
  }
  self.payload.write_bytes(part)
}

///|
/// Finish the message and start the next one empty.
fn Reader::finish(self : Reader) -> Step raise Refused {
  let data = self.payload.to_bytes()
  let kind = self.kind
  self.payload.reset()
  self.kind = None
  let message = if kind is Some(Binary) {
    Message::Binary(data)
  } else {
    // §8.1: a text message that is not UTF-8 fails the connection with 1007. Decoding it
    // lossily would hand the application a message the peer never sent.
    Message::Text(
      @utf8.decode(data[:]) catch {
        _ => raise Payload("a text message that is not valid UTF-8")
      },
    )
  }
  { message: Some(message), reply: None, }
}

///|
pub extend Opcode with Debug::{to_repr}

///|
pub extend Opcode with Eq::{not_equal, equal}

///|
pub extend Frame with Debug::{to_repr}

///|
pub extend Frame with Eq::{not_equal, equal}

///|
pub extend Message with Debug::{to_repr}

///|
pub extend Message with Eq::{not_equal, equal}

///|
pub extend Step with Debug::{to_repr}

///|
pub extend Step with Eq::{not_equal, equal}
