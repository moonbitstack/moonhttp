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
  // The window and the message in one buffer: a match may reach across the
  // boundary between them, and one buffer turns every read in the search into one
  // load — a four- or eight-octet load at that, which is what the search and the
  // compare are built on.
  let all : BytesView = if hlen == 0 {
    data
  } else {
    let joined = Buffer::Buffer(size_hint=total)
    joined.write_bytes(self.history[:])
    joined.write_bytes(data)
    joined.to_bytes()[:]
  }
  if n >= 4096 && total > 0 && !compressible(all, hlen, total) {
    // Octets that do not repeat are cheaper stored: DEFLATE's own escape hatch
    // (§3.2.4) copies them in 65535-octet blocks without a code per octet, which is
    // what a WebSocket carrying random bytes needs. Such a block is byte-aligned
    // and copies its octets verbatim, so the size is known before a byte is
    // written and each chunk goes in as one copy: copying the message twice would
    // be the whole cost of compressing it.
    let payload = total - hlen
    let blocks = (payload + 65534) / 65535
    let tail = if finish { 5 } else { 1 }
    let out = Buffer::Buffer(size_hint=payload + 5 * blocks + tail)
    let mut at = hlen
    while at < total {
      let chunk = if total - at < 65535 { total - at } else { 65535 }
      let nlen = chunk ^ 0xFFFF
      out.write_byte(b'\x00') // BFINAL clear, BTYPE 00, padded to a byte
      out.write_byte((chunk & 0xFF).to_byte())
      out.write_byte(((chunk >> 8) & 0xFF).to_byte())
      out.write_byte((nlen & 0xFF).to_byte())
      out.write_byte(((nlen >> 8) & 0xFF).to_byte())
      out.write_bytes(all[at:at + chunk])
      at += chunk
    }
    if finish {
      out.write_byte(b'\x01')
      out.write_byte(b'\x00')
      out.write_byte(b'\x00')
      out.write_byte(b'\xff')
      out.write_byte(b'\xff')
    } else {
      // The empty block's tail is what §7.2.1 takes off; only its header remains.
      out.write_byte(b'\x00')
    }
    if self.takeover {
      let from = if total > window { total - window } else { 0 }
      self.history = all[from:].to_owned()
    }
    return out.to_bytes()
  } else {
    // A fixed block costs at most nine bits a literal, so the output cannot exceed
    // this; reserving it keeps the writer from growing through a hundred copies.
    w.out.reserve_capacity(total + total / 8 + 16)
    // The parse first, as tokens, because a block's code lengths come from how often
    // each symbol appears and that is only known once the whole message has been
    // walked. One token per position: a literal keeps its value, and a match is
    // negative, holding its length in the low nine bits and its distance above them.
    let parse = parse(all, hlen, total, window)
    let mut plan : Plan? = None
    if parse.tokens.length() >= 256 {
      let candidate = build_plan(parse.lit_freq, parse.dist_freq)
      if candidate.data_bits(parse.lit_freq, parse.dist_freq) < parse.fixed_bits {
        plan = Some(candidate)
      }
    }
    match plan {
      Some(p) => {
        w.bits(0, 1) // BFINAL: a message is not the end of the stream
        w.bits(2, 2) // BTYPE 10: the dynamic Huffman codes
        w.plan(p)
        for t in parse.tokens {
          if t >= 0 {
            w.code(p.lit_code.unsafe_get(t))
          } else {
            let token = -t
            let len = token & 0x1FF
            let dist = token >> 9
            let (ls, lext, lval) = length_code(len)
            w.code(p.lit_code.unsafe_get(ls))
            if lext > 0 {
              w.bits(lval, lext)
            }
            let (ds, dext, dval) = distance_code(dist)
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
        for t in parse.tokens {
          if t >= 0 {
            w.emit(t)
          } else {
            let token = -t
            w.emit_match(token & 0x1FF, token >> 9)
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
    let from = if total > window { total - window } else { 0 }
    self.history = all[from:].to_owned()
  }
  Bytes::from_array(wire)
}

///|
/// One message's parse: the tokens in order, how often each symbol was used, and
/// what the fixed code would have spent on them — which is the comparison the
/// block-type choice is made from.
priv struct Parsed {
  tokens : Array[Int32]
  lit_freq : Array[Int32]
  dist_freq : Array[Int32]
  fixed_bits : Int32
}

///|
/// Walk the message once and decide, at each position, whether to write the octet
/// out or to point back at a run of them.
///
/// The search is the whole cost of compressing, so everything expensive is
/// arranged to be done rarely: four octets hash in one load and one multiply, a
/// candidate is rejected on one comparison of its first four octets, and the
/// positions inside a long match are not hashed at all — a message that repeats
/// itself at length is mostly match, and hashing the octets a match already
/// covers buys nothing a later position would not find on its own.
fn parse(
  all : BytesView,
  hlen : Int32,
  total : Int32,
  window : Int32,
) -> Parsed {
  let tokens : Array[Int32] = []
  let lit_freq = Array::make(286, 0)
  let dist_freq = Array::make(30, 0)
  let mut fixed_bits = 0
  tokens.reserve_capacity(total - hlen)
  if total > 0 {
    let head = Array::make(1 << hash_bits, -1)
    let prev = Array::make(window, -1)
    let mask = window - 1
    // Seed the chains with the window, or a message cannot point back into the one
    // before it and `takeover` would mean nothing.
    if hlen > 0 {
      let mut p = 0
      while p < hlen {
        if p + min_hash <= total {
          let h = hash_at(all, p, total)
          prev.unsafe_set(p & mask, head.unsafe_get(h))
          head.unsafe_set(h, p)
        }
        p += 1
      }
    }
    let mut i = hlen
    while i < total {
      let (best, dist) = search(all, head, prev, mask, i, total, window)
      if best >= min_match {
        // The shortest match is where a better one usually follows: the next
        // position may be the start of a longer run, and taking four octets now
        // would spend the same space on less. Only a short match is worth asking
        // about — past that the answer is this one.
        if best < lazy_limit && i + min_hash <= total {
          insert(all, head, prev, mask, i, total)
          let next = lookahead(all, head, i + 1, total, window)
          if next > best {
            let value = all.unsafe_get(i).to_int()
            tokens.push(value)
            lit_freq.unsafe_set(value, lit_freq.unsafe_get(value) + 1)
            fixed_bits += fixed_rev.unsafe_get(value) & 0xF
            i += 1
            continue
          }
          cover(all, head, prev, mask, i, best, total)
        } else {
          insert(all, head, prev, mask, i, total)
          cover(all, head, prev, mask, i, best, total)
        }
        let ls = len_sym.unsafe_get(best)
        let ds = dist_symbol(dist)
        lit_freq.unsafe_set(ls, lit_freq.unsafe_get(ls) + 1)
        dist_freq.unsafe_set(ds, dist_freq.unsafe_get(ds) + 1)
        fixed_bits += (fixed_rev.unsafe_get(ls) & 0xF) + 5
        tokens.push(-((dist << 9) | best))
        i += best
      } else {
        let value = all.unsafe_get(i).to_int()
        lit_freq.unsafe_set(value, lit_freq.unsafe_get(value) + 1)
        fixed_bits += fixed_rev.unsafe_get(value) & 0xF
        tokens.push(value)
        insert(all, head, prev, mask, i, total)
        i += 1
      }
    }
  }
  lit_freq.unsafe_set(256, lit_freq.unsafe_get(256) + 1)
  fixed_bits += 7
  { tokens, lit_freq, dist_freq, fixed_bits, }
}

///|
/// The longest run starting at `i` that an earlier position repeats, and how far
/// back it is. Zero when nothing repeats there.
///
/// A hash bucket is a candidate list, not a match: the shallow end holds the most
/// recent occurrence, which is the cheapest to point at and usually the longest,
/// and the walk stops at the depth the search is worth.
fn search(
  all : BytesView,
  head : Array[Int32],
  prev : Array[Int32],
  mask : Int32,
  i : Int32,
  total : Int32,
  window : Int32,
) -> (Int32, Int32) {
  let mut best = 0
  let mut best_dist = 0
  if i + min_hash > total {
    return (0, 0)
  }
  let cap = if total - i < max_match { total - i } else { max_match }
  let key = key_at(all, i, total)
  let mut j = head.unsafe_get(hash_of(key))
  let mut left = max_chain
  while j >= 0 && left > 0 {
    let dist = i - j
    if dist > window {
      break
    }
    if key_at(all, j, total) == key {
      let len = match_len(all, j, i, cap)
      if len > best {
        best = len
        best_dist = dist
        if len >= cap || len >= nice_length {
          break
        }
      }
    }
    j = prev.unsafe_get(j & mask)
    left -= 1
  }
  (best, best_dist)
}

///|
/// The length of the match at the position after `i`, considered before the one
/// at `i` is taken: the shallow end of the next bucket only, which is one hash and
/// one compare, and is what "is the next octet a better start" costs.
fn lookahead(
  all : BytesView,
  head : Array[Int32],
  i : Int32,
  total : Int32,
  window : Int32,
) -> Int32 {
  if i + min_hash > total {
    return 0
  }
  let j = head.unsafe_get(hash_at(all, i, total))
  if j < 0 || i - j > window {
    return 0
  }
  if key_at(all, j, total) != key_at(all, i, total) {
    return 0
  }
  let cap = if total - i < max_match { total - i } else { max_match }
  match_len(all, j, i, cap)
}

///|
/// Put one position into its bucket.
fn insert(
  all : BytesView,
  head : Array[Int32],
  prev : Array[Int32],
  mask : Int32,
  at : Int32,
  total : Int32,
) -> Unit {
  if at + min_hash <= total {
    let h = hash_at(all, at, total)
    prev.unsafe_set(at & mask, head.unsafe_get(h))
    head.unsafe_set(h, at)
  }
}

///|
/// Record the ground a match covers, so the search after it starts from where the
/// match ended rather than from the octet after its start.
///
/// A short match is hashed through: those positions are what the next few
/// searches want, and there are only a few of them. A long one is not, because
/// hashing its inside is most of what taking the match would cost — but its last
/// position is, and that is the one that matters: the octet after a run repeats
/// the octet before it, so with the tail in its bucket the next search finds a
/// distance of one and spends no extra bits on the distance, which is what turns a
/// megabyte of zeros into two bits a match instead of nine.
fn cover(
  all : BytesView,
  head : Array[Int32],
  prev : Array[Int32],
  mask : Int32,
  i : Int32,
  len : Int32,
  total : Int32,
) -> Unit {
  if len <= insert_inside {
    insert_range(all, head, prev, mask, i + 1, i + len, total)
    return
  }
  insert(all, head, prev, mask, i + len - 1, total)
}

///|
/// Put every position of `[from, to)` into its bucket.
fn insert_range(
  all : BytesView,
  head : Array[Int32],
  prev : Array[Int32],
  mask : Int32,
  from : Int32,
  to : Int32,
  total : Int32,
) -> Unit {
  let mut at = from
  while at < to {
    insert(all, head, prev, mask, at, total)
    at += 1
  }
}

///|
/// How many bits of the hash table there are. Fifteen covers a 32 KiB window with
/// a bucket per two octets of it, which keeps a bucket's chain short enough that
/// the depth limit is rarely what ends a walk.
let hash_bits : Int32 = 15

///|
/// The number of octets a position is hashed on. Three is DEFLATE's shortest
/// match, so no match the format can write is missed by the bucket it lands in.
let min_hash : Int32 = 3

///|
/// How deep the match finder looks at each position. The chains here are sparse —
/// the inside of a match is not hashed — so a walk of eight is what it takes to
/// reach the candidate that pays; deeper costs more than the ratio it buys.
let max_chain : Int32 = 8

///|
/// The length at which a match is good enough to stop looking: the deeper links
/// cannot beat it by enough to pay for the walk.
let nice_length : Int32 = 48

///|
/// The longest match still worth asking the next position about. Four octets of
/// text repeat by coincidence and the octet after them often starts a longer run;
/// past sixteen the next position has been covered by this match and asking costs
/// more than the ratio it buys.
let lazy_limit : Int32 = 16

///|
/// The longest match whose interior is hashed. A short match leaves positions a
/// later search will want; a long one covers ground nothing needs to look at
/// again, and hashing it is most of what a long match would cost.
let insert_inside : Int32 = 8

///|
/// The top `hash_bits` of a three-octet key times an odd constant: one multiply
/// mixes the three octets, and the high bits are the ones that use the whole
/// table.
fn hash_of(key : UInt32) -> Int32 {
  (((key & 0xFFFFFF) * 0x9E3779B1) >> (32 - hash_bits)).reinterpret_as_int()
}

///|
/// The key four octets at `at` hold, or the three the message still has. A key is
/// read as one word when the word is there and built from the octets when it is
/// not: the last three positions of a message are the only ones that take the
/// second path, and reading past the end of the buffer is not something a
/// bounds-checked target allows even when the bytes are not looked at.
fn key_at(all : BytesView, at : Int32, total : Int32) -> UInt32 {
  if at + 4 <= total {
    all.unsafe_read_uint32_le(at)
  } else {
    let low = all.unsafe_get(at).to_int() |
      (all.unsafe_get(at + 1).to_int() << 8) |
      (all.unsafe_get(at + 2).to_int() << 16)
    low.reinterpret_as_uint()
  }
}

///|
fn hash_at(all : BytesView, at : Int32, total : Int32) -> Int32 {
  hash_of(key_at(all, at, total))
}

///|
/// How many octets match starting at `j` and `i`, up to `cap`, eight at a time.
///
/// The window and the message share one buffer, so an eight-octet load reads a
/// whole word of the candidate and one of the position in two instructions; the
/// walk only becomes a byte-by-byte one inside the last word that differs.
fn match_len(all : BytesView, j : Int32, i : Int32, cap : Int32) -> Int32 {
  let mut len = 0
  while len + 8 <= cap {
    if all.unsafe_read_uint64_le(j + len) != all.unsafe_read_uint64_le(i + len) {
      break
    }
    len += 8
  }
  if len + 4 <= cap {
    if all.unsafe_read_uint32_le(j + len) == all.unsafe_read_uint32_le(i + len) {
      len += 4
    }
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
fn literal_bits(all : BytesView, hlen : Int32, total : Int32) -> Int32 {
  let lit_freq = Array::make(286, 0)
  for i in hlen..<total {
    let value = all.unsafe_get(i).to_int()
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
///
/// The probe comes first because it is the cheap one and because a message that
/// repeats is the common case: the histogram below walks every octet, and a text
/// message should not pay for that walk twice.
fn compressible(all : BytesView, hlen : Int32, total : Int32) -> Bool {
  repeats(all, hlen, total) ||
  literal_bits(all, hlen, total) < stored_bits(total - hlen)
}

///|
/// A cheap probe over up to 8192 sample positions, counting exact three-octet
/// repeats. Text repeats a word every few octets and clears the bar at once;
/// random octets almost never do.
fn repeats(all : BytesView, hlen : Int32, total : Int32) -> Bool {
  let n = total - hlen
  let table = Array::make(8192, -1)
  let stride = if n > 8192 { n / 8192 } else { 1 }
  let mut hits = 0
  let mut sampled = 0
  let mut i = hlen
  while i + 4 <= total && sampled < 8192 {
    let k = hash_of(all.unsafe_read_uint32_le(i)) & 0x1FFF
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
