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
  /// The tail of the stream so far, which a later message may point back into.
  /// Kept as the last window of octets, so a search reads one array and the
  /// window never grows past what a distance can reach.
  mut history : Bytes
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
  { bits, takeover, history: b"", }
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
  self.history = b""
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
    self.history = b""
  }
  let n = data.length()
  let hlen = self.history.length()
  let total = hlen + n
  // The window and the message in one array of integers: a match may reach across
  // the boundary between them, one array turns every read in the search into one
  // indexing, and holding each octet already widened keeps a byte-to-int conversion
  // out of the inner loop. The unchecked accessors keep a bounds test out of it too.
  let all : Array[Int32] = []
  all.reserve_capacity(total + 1)
  for b in self.history {
    all.push(b.to_int())
  }
  for k in 0..<n {
    all.push(data[k].to_int())
  }
  // A fixed block costs at most nine bits a literal, so the output cannot exceed
  // this; reserving it keeps the writer from growing through a hundred copies.
  w.out.reserve_capacity(total + total / 8 + 16)
  if n >= 4096 && total > 0 && !compressible(all, hlen, total) {
    // Octets that do not repeat are cheaper stored: DEFLATE's own escape hatch
    // (§3.2.4) copies them in 65535-octet blocks without a code per octet, which is
    // what a WebSocket carrying random bytes needs.
    let mut at = hlen
    while at < total {
      let chunk = if total - at < 65535 { total - at } else { 65535 }
      w.bits(0, 1) // BFINAL: a message is not the end of the stream
      w.bits(0, 2) // BTYPE 00: stored
      w.align()
      let nlen = chunk ^ 0xFFFF
      w.out.push((chunk & 0xFF).to_byte())
      w.out.push(((chunk >> 8) & 0xFF).to_byte())
      w.out.push((nlen & 0xFF).to_byte())
      w.out.push(((nlen >> 8) & 0xFF).to_byte())
      for k in 0..<chunk {
        w.out.push(all.unsafe_get(at + k).to_byte())
      }
      at += chunk
    }
  } else {
    w.bits(0, 1) // BFINAL: a message is not the end of the stream
    w.bits(1, 2) // BTYPE 01: the fixed Huffman codes
    if total > 0 {
      let head = Array::make(1 << 15, -1)
      let prev = Array::make(total, -1)
      // Seed the chains with the window, or a message cannot point back into the
      // one before it and `takeover` would mean nothing. The hash is written out
      // here rather than called: this loop runs once per octet, and a call per octet
      // is most of what a message costs.
      for p in 0..<hlen {
        if p + min_match <= total {
          let k = (
              (all.unsafe_get(p) << 10) ^
              (all.unsafe_get(p + 1) << 5) ^
              all.unsafe_get(p + 2)
            ) &
            0x7FFF
          prev.unsafe_set(p, head.unsafe_get(k))
          head.unsafe_set(k, p)
        }
      }
      let mut i = hlen
      while i < total {
        let mut best_len = 0
        let mut best_dist = 0
        let mut bucket = -1
        if i + min_match <= total {
          bucket = (
              (all.unsafe_get(i) << 10) ^
              (all.unsafe_get(i + 1) << 5) ^
              all.unsafe_get(i + 2)
            ) &
            0x7FFF
          let cap = if total - i < max_match { total - i } else { max_match }
          let mut j = head.unsafe_get(bucket)
          let mut left = chain
          while j >= 0 && left > 0 {
            let dist = i - j
            if dist > window {
              break
            }
            let mut len = 0
            while len < cap &&
                  all.unsafe_get(j + len) == all.unsafe_get(i + len) {
              len += 1
            }
            if len > best_len {
              best_len = len
              best_dist = dist
              if len >= cap {
                break
              }
            }
            j = prev.unsafe_get(j)
            left -= 1
          }
        }
        let taken = if best_len >= min_match {
          w.emit_match(best_len, best_dist)
          best_len
        } else {
          w.emit(all.unsafe_get(i))
          1
        }
        // The position already hashed for the search goes into the chain without
        // hashing again; the positions inside a match hash themselves.
        let stop = i + taken
        let mut at = i
        if bucket >= 0 {
          prev.unsafe_set(at, head.unsafe_get(bucket))
          head.unsafe_set(bucket, at)
          at += 1
        }
        while at < stop {
          if at + min_match <= total {
            let k = (
                (all.unsafe_get(at) << 10) ^
                (all.unsafe_get(at + 1) << 5) ^
                all.unsafe_get(at + 2)
              ) &
              0x7FFF
            prev.unsafe_set(at, head.unsafe_get(k))
            head.unsafe_set(k, at)
          }
          at += 1
        }
        i = stop
      }
    }
    w.emit(256) // end of block
  }
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
  wire.reserve_capacity(kept)
  for k in 0..<kept {
    wire.push(w.out.unsafe_get(k))
  }
  if self.takeover {
    // A later message may point back into the last window of this one, and nothing
    // older than a window can be reached, so that is all that is kept.
    let from = if all.length() > window { all.length() - window } else { 0 }
    let tail : Array[Byte] = []
    tail.reserve_capacity(all.length() - from)
    for k in from..<all.length() {
      tail.push(all.unsafe_get(k).to_byte())
    }
    self.history = Bytes::from_array(tail)
  }
  Bytes::from_array(wire)
}

///|
/// How deep the match finder looks at each position. Zlib's own level 6 walks
/// 128 links, and the deeper chains buy little on the lengths a message carries.
let chain : Int32 = 128

///|
/// Whether a message is worth Huffman-coding: a cheap probe over up to 8192 sample
/// positions, counting exact three-octet repeats. Text repeats a word every few
/// octets and clears the bar at once; random octets almost never do, and a message
/// that does not repeat is cheaper stored.
fn compressible(all : Array[Int32], hlen : Int32, total : Int32) -> Bool {
  let n = total - hlen
  let table = Array::make(8192, -1)
  let stride = if n > 8192 { n / 8192 } else { 1 }
  let mut hits = 0
  let mut sampled = 0
  let mut i = hlen
  while i + 2 < total && sampled < 8192 {
    let k = (
        (all.unsafe_get(i) << 6) ^
        (all.unsafe_get(i + 1) << 3) ^
        all.unsafe_get(i + 2)
      ) &
      0x1FFF
    let prev = table.unsafe_get(k)
    if prev >= 0 &&
      all.unsafe_get(prev) == all.unsafe_get(i) &&
      all.unsafe_get(prev + 1) == all.unsafe_get(i + 1) &&
      all.unsafe_get(prev + 2) == all.unsafe_get(i + 2) {
      hits += 1
    }
    table.unsafe_set(k, i)
    i += stride
    sampled += 1
  }
  // More than one exact repeat in sixty-four sampled positions means the message
  // has structure to exploit; less means it reads as noise.
  hits * 64 >= sampled
}
