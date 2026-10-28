// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The compressing half of RFC 1951, shaped for a message stream rather than a
/// file.
///
/// A file has one end, so a compressor can put the last block's `BFINAL` bit up,
/// flush, and be done. A WebSocket does not: RFC 7692 §7.2.1 runs one DEFLATE
/// stream across every message on the connection, ends each message with an
/// empty stored block and strips its four-octet tail, and expects the next
/// message to carry on inside the same stream. So each call here writes blocks
/// with `BFINAL` clear and ends with that empty block, and the octets a caller
/// gets are the ones that go on the wire — tail already removed.
///
/// The window is the compressor's memory, and `takeover` is whether it survives
/// a message boundary. Shared, it buys a second message the first one's
/// repetitions; reset, each message stands alone and the receiver may drop what
/// it held.
///
/// One fixed-Huffman block per message, the shape RFC 7692 §7.2.3.1 shows. A
/// dynamic block carries its own code lengths, and on the short messages a
/// WebSocket carries those cost more than they save.
pub struct Deflater {
  bits : Int32
  takeover : Bool
  mut history : Array[Byte]
}

///|
/// A compressor with a window of `1 << bits` bytes.
///
/// Fifteen bits — the 32 KiB DEFLATE allows — is the default every
/// implementation uses, and a smaller one only exists because an extension may
/// negotiate it down (RFC 7692 §7.1.2). `takeover` off starts each message with
/// an empty window, which is what `*_no_context_takeover` asks for.
pub fn Deflater::new(bits~ : Int32 = 15, takeover~ : Bool = true) -> Deflater {
  guard bits >= 8 && bits <= 15 else {
    abort("deflate: a \{bits}-bit window is outside what DEFLATE allows")
  }
  { bits, takeover, history: [], }
}

///|
/// How far back a match may reach, in bytes.
pub fn Deflater::window(self : Deflater) -> Int32 {
  1 << self.bits
}

///|
/// Whether the window survives a message boundary.
pub fn Deflater::takeover(self : Deflater) -> Bool {
  self.takeover
}

///|
/// Throw away the window, as `*_no_context_takeover` asks between messages.
pub fn Deflater::reset(self : Deflater) -> Unit {
  self.history = []
}

///|
/// Compress one message into the octets RFC 7692 §7.2.1 puts on the wire.
///
/// The returned bytes are a *segment* of a longer stream: they begin with a
/// block whose `BFINAL` is clear and end with the empty stored block's header,
/// with the four octets `00 00 ff ff` already taken off the tail. A receiver
/// puts those four back and decompresses (RFC 7692 §7.2.2), which is what
/// `Inflater` does.
///
/// `finish` ends the stream instead of leaving it open: the last block is written
/// with `BFINAL` set and the tail stays on, so the octets are a whole DEFLATE
/// stream that a file decompressor reads. A WebSocket never asks for it — a
/// connection that compressed its last message simply stops — but a caller using
/// this as a plain compressor ends a stream this way.
///
/// `level` is not a knob here: the match search is one setting, the one a
/// compressed message is worth. A caller who wants a ratio instead of a latency
/// budget wants a different library.
pub fn Deflater::compress(
  self : Deflater,
  data : BytesView,
  finish~ : Bool = false,
) -> Bytes {
  let w = Writer::new()
  let window = self.window()
  if !self.takeover {
    self.history = []
  }
  let hist = self.history
  let hlen = hist.length()
  let n = data.length()
  let total = hlen + n
  w.bits(0, 1) // BFINAL: a message is not the end of the stream
  w.bits(1, 2) // BTYPE 01: the fixed Huffman codes
  if total > 0 {
    let head = FixedArray::make(1 << 15, -1)
    let prev = FixedArray::make(total, -1)
    // Seed the chains with the window, or a message cannot point back into the
    // one before it and `takeover` would mean nothing.
    for p in 0..<hlen {
      insert(head, prev, hist, data, hlen, p, total)
    }
    let mut i = hlen
    while i < total {
      let mut best_len = 0
      let mut best_dist = 0
      if i + min_match <= total {
        let cap = if total - i < max_match { total - i } else { max_match }
        let mut j = head[hash_at(hist, data, hlen, i)]
        let mut left = chain
        while j >= 0 && left > 0 {
          let dist = i - j
          if dist > window {
            break
          }
          let mut len = 0
          while len < cap &&
                byte_at(hist, data, hlen, j + len) ==
                byte_at(hist, data, hlen, i + len) {
            len += 1
          }
          if len > best_len {
            best_len = len
            best_dist = dist
            if len >= cap {
              break
            }
          }
          j = prev[j]
          left -= 1
        }
      }
      let taken = if best_len >= min_match {
        w.emit_match(best_len, best_dist)
        best_len
      } else {
        w.emit(byte_at(hist, data, hlen, i))
        1
      }
      // Every position inside a match goes into the chain too, or the next match
      // cannot start in the middle of this one.
      for _ in 0..<taken {
        insert(head, prev, hist, data, hlen, i, total)
        i += 1
      }
    }
  }
  w.emit(256) // end of block
  // §7.2.1 steps 2 and 3: an empty stored block, and its tail taken off — or,
  // when this message closes the stream, the same block with `BFINAL` set and the
  // tail left where a file decompressor expects it.
  if finish {
    w.bits(1, 1)
  } else {
    w.bits(0, 1)
  }
  w.bits(0, 2)
  w.align()
  w.out.push(b'\x00')
  w.out.push(b'\x00')
  w.out.push(b'\xff')
  w.out.push(b'\xff')
  let mut kept = w.out.length()
  if !finish {
    kept = w.out.length() - 4
  }
  let wire : Array[Byte] = []
  for k in 0..<kept {
    wire.push(w.out[k])
  }
  if self.takeover {
    for k in 0..<n {
      self.history.push(data[k])
    }
    // Two windows is enough to serve a one-window search, and keeps an endless
    // stream from growing every message.
    if self.history.length() > 2 * window {
      let from = self.history.length() - window
      let trimmed : Array[Byte] = []
      for k in from..<self.history.length() {
        trimmed.push(self.history[k])
      }
      self.history = trimmed
    }
  }
  Bytes::from_array(wire)
}

///|
/// How deep the match finder looks at each position. Zlib's own level 6 walks
/// 128 links, and the deeper chains buy little on the lengths a message carries.
let chain : Int32 = 128

///|
/// One octet of the message with the window still in front of it, so a match may
/// reach either side of the boundary.
fn byte_at(
  hist : Array[Byte],
  data : BytesView,
  hlen : Int32,
  i : Int32,
) -> Int32 {
  if i < hlen {
    hist[i].to_int()
  } else {
    data[i - hlen].to_int()
  }
}

///|
/// Three octets folded into a chain bucket.
fn hash_at(
  hist : Array[Byte],
  data : BytesView,
  hlen : Int32,
  i : Int32,
) -> Int32 {
  (
    (byte_at(hist, data, hlen, i) << 10) ^
    (byte_at(hist, data, hlen, i + 1) << 5) ^
    byte_at(hist, data, hlen, i + 2)
  ) &
  0x7FFF
}

///|
/// Put a position at the head of its bucket, chaining it to whatever was there.
fn insert(
  head : FixedArray[Int32],
  prev : FixedArray[Int32],
  hist : Array[Byte],
  data : BytesView,
  hlen : Int32,
  i : Int32,
  total : Int32,
) -> Unit {
  if i + min_match <= total {
    let k = hash_at(hist, data, hlen, i)
    prev[i] = head[k]
    head[k] = i
  }
}
