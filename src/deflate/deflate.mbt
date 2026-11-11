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
/// The block type is chosen per message: a dynamic block carries its own code
/// lengths and usually wins on anything past a few hundred symbols, and the fixed
/// block — the shape RFC 7692 §7.2.3.1 prints — is what a short message, or one
/// that is mostly a single long match, actually costs less with.
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
    // The parse first, as tokens, because a block's code lengths come from how often
    // each symbol appears and that is only known once the whole message has been
    // walked. A token is a literal when `lens` holds zero, with its value in `vals`;
    // otherwise it is a match length, with its distance there.
    let lens : Array[Int32] = []
    let vals : Array[Int32] = []
    let lit_freq = Array::make(286, 0)
    let dist_freq = Array::make(30, 0)
    // What the fixed code would spend, counted during the parse so the choice below
    // costs no second walk.
    let mut fixed_bits = 0
    lens.reserve_capacity(n)
    vals.reserve_capacity(n)
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
            let len = match_len(all, j, i, cap)
            if len > best_len {
              best_len = len
              best_dist = dist
              if len >= cap || len >= nice {
                break
              }
            }
            j = prev.unsafe_get(j)
            left -= 1
          }
        }
        let taken = if best_len >= min_match {
          let ls = len_sym.unsafe_get(best_len)
          let ds = dist_symbol(best_dist)
          lit_freq.unsafe_set(ls, lit_freq.unsafe_get(ls) + 1)
          dist_freq.unsafe_set(ds, dist_freq.unsafe_get(ds) + 1)
          fixed_bits += (fixed_rev.unsafe_get(ls) & 0xF) + 5
          lens.push(best_len)
          vals.push(best_dist)
          best_len
        } else {
          let value = all.unsafe_get(i)
          lit_freq.unsafe_set(value, lit_freq.unsafe_get(value) + 1)
          fixed_bits += fixed_rev.unsafe_get(value) & 0xF
          lens.push(0)
          vals.push(value)
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
    lit_freq.unsafe_set(256, lit_freq.unsafe_get(256) + 1)
    fixed_bits += 7
    // A block shorter than a few hundred symbols cannot pay for a header of its own,
    // so the comparison is not even made; past that, whichever is cheaper wins, and
    // the fixed code is what a short message and a single long match both come back
    // to. This is also what keeps the exact octets RFC 7692 §7.2.3.1 prints for
    // "Hello": five octets never reach the comparison.
    let mut plan : Plan? = None
    if lens.length() >= 256 {
      let candidate = build_plan(lit_freq, dist_freq)
      if candidate.data_bits(lit_freq, dist_freq) < fixed_bits {
        plan = Some(candidate)
      }
    }
    match plan {
      Some(p) => {
        w.bits(0, 1) // BFINAL: a message is not the end of the stream
        w.bits(2, 2) // BTYPE 10: the dynamic Huffman codes
        w.plan(p)
        for t in 0..<lens.length() {
          let l = lens.unsafe_get(t)
          let value = vals.unsafe_get(t)
          if l == 0 {
            w.code(p.lit_code.unsafe_get(value))
          } else {
            let (ls, lext, lval) = length_code(l)
            w.code(p.lit_code.unsafe_get(ls))
            if lext > 0 {
              w.bits(lval, lext)
            }
            let (ds, dext, dval) = distance_code(value)
            w.code(p.dist_code.unsafe_get(ds))
            if dext > 0 {
              w.bits(dval, dext)
            }
          }
        }
        w.code(p.lit_code.unsafe_get(256)) // end of block
      }
      None => {
        w.bits(0, 1) // BFINAL: a message is not the end of the stream
        w.bits(1, 2) // BTYPE 01: the fixed Huffman codes
        for t in 0..<lens.length() {
          let l = lens.unsafe_get(t)
          if l == 0 {
            w.emit(vals.unsafe_get(t))
          } else {
            w.emit_match(l, vals.unsafe_get(t))
          }
        }
        w.emit(256) // end of block
      }
    }
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
/// How deep the match finder looks at each position. A message repeats itself in
/// short runs, and the first few links hold the recent ones, so a shallow chain
/// keeps most of the ratio and spends a fraction of the search. The depth was
/// four; two keeps the ratio on English-like text that the benchmarks carry and
/// spends roughly half the work per position, and three or one lose either speed
/// or ratio (one leaves too few candidates and the literals that follow cost more
/// than the search saved). The encoder is the hot path of Autobahn's 12.2.10, so
/// this is the one knob that moves it.
let chain : Int32 = 2

///|
/// The length at which a match is good enough to stop looking: the deeper links
/// cannot beat it by enough to pay for the walk.
let nice : Int32 = 32

///|
/// How many octets match starting at `j` and `i`, up to `cap`, comparing four at a
/// time. The four-octet step is why the encoder no longer crawls a byte at a time
/// through every candidate: the inner loop runs a quarter as often and the result
/// is the same length a byte-by-byte walk would find.
fn match_len(all : Array[Int32], j : Int32, i : Int32, cap : Int32) -> Int32 {
  let mut len = 0
  while len + 4 <= cap {
    let a = (all.unsafe_get(j + len).to_int64() << 24) |
      (all.unsafe_get(j + len + 1).to_int64() << 16) |
      (all.unsafe_get(j + len + 2).to_int64() << 8) |
      all.unsafe_get(j + len + 3).to_int64()
    let b = (all.unsafe_get(i + len).to_int64() << 24) |
      (all.unsafe_get(i + len + 1).to_int64() << 16) |
      (all.unsafe_get(i + len + 2).to_int64() << 8) |
      all.unsafe_get(i + len + 3).to_int64()
    if a != b {
      break
    }
    len += 4
  }
  while len < cap && all.unsafe_get(j + len) == all.unsafe_get(i + len) {
    len += 1
  }
  len
}

///|
/// What carrying `n` octets stored would cost: eight bits each and a five-octet
/// header per 65535, plus the padding that puts the first block on a byte boundary
/// (§3.2.4).
fn stored_bits(n : Int32) -> Int32 {
  let blocks = (n + 65534) / 65535
  8 * n + 40 * blocks + 7
}

///|
/// What a dynamic block would spend if every octet were a literal: the cost of a
/// code for this message's alphabet, before any match has been looked for. Below
/// the stored cost, coding the message pays for itself whatever the matches add.
fn literal_bits(all : Array[Int32], hlen : Int32, total : Int32) -> Int32 {
  let lit_freq = Array::make(286, 0)
  for i in hlen..<total {
    let value = all.unsafe_get(i)
    lit_freq.unsafe_set(value, lit_freq.unsafe_get(value) + 1)
  }
  lit_freq.unsafe_set(256, lit_freq.unsafe_get(256) + 1)
  let dist_freq = Array::make(30, 0)
  build_plan(lit_freq, dist_freq).data_bits(lit_freq, dist_freq)
}

///|
/// Whether a message is worth coding rather than copying into stored blocks.
///
/// Two signals, either of them enough, because they miss different messages. The
/// first is the alphabet: octets drawn from ninety-five symbols carry about six
/// and a half bits each and pay for a code of their own even where nothing in the
/// message repeats, and a token or a base64 blob is exactly that. The second is
/// repetition: octets spread across the whole alphabet still come out far cheaper
/// coded when long runs of them recur, and that is what the three-octet probe
/// below finds. A message that fails both is noise, and copying it costs less than
/// any code.
fn compressible(all : Array[Int32], hlen : Int32, total : Int32) -> Bool {
  if literal_bits(all, hlen, total) < stored_bits(total - hlen) {
    return true
  }
  repeats(all, hlen, total)
}

///|
/// A cheap probe over up to 8192 sample positions, counting exact three-octet
/// repeats. Text repeats a word every few octets and clears the bar at once;
/// random octets almost never do.
fn repeats(all : Array[Int32], hlen : Int32, total : Int32) -> Bool {
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
