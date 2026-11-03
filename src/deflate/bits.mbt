// The bits, the codes and the tables both directions share.
//
// DEFLATE packs everything least significant bit first except the Huffman codes
// themselves, which go out most significant bit first (RFC 1951 §3.1.1) — so a
// code is reversed on its way into the stream and read a bit at a time out of it.

///|
/// What can go wrong reading a DEFLATE stream.
///
/// Every variant names where it happened and what it saw, because a compressed
/// message from elsewhere is the one input a reader here cannot trust: the point
/// of the format is that a small stream can expand to more than the machine has.
#derive(Eq, Debug)
pub(all) suberror Refused {
  /// The three block-type bits named something §3.2 does not define.
  Block(at~ : Int32, got~ : Int32)
  /// A code that is not in the table, or a length list that does not add up.
  Code(at~ : Int32)
  /// The input stopped inside a block.
  Truncated(at~ : Int32)
  /// A match reaching further back than the window holds, or before its start.
  Distance(at~ : Int32, got~ : Int32)
  /// The output passed the ceiling the caller set.
  Exceeded(limit~ : Int32, got~ : Int32)
}

///|
/// A refusal prints as the fault it is, with where in the stream it happened.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Block(at~, got~) => logger.write_string("Block(at=\{at}, got=\{got})")
    Code(at~) => logger.write_string("Code(at=\{at})")
    Truncated(at~) => logger.write_string("Truncated(at=\{at})")
    Distance(at~, got~) => logger.write_string("Distance(at=\{at}, got=\{got})")
    Exceeded(limit~, got~) =>
      logger.write_string("Exceeded(limit=\{limit}, got=\{got})")
  }
}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

///|
/// The longest match DEFLATE encodes (§3.2.5).
let max_match : Int32 = 258

///|
/// The shortest one: two bytes are cheaper as two literals.
let min_match : Int32 = 3

///|
/// The base length for each length symbol 257–285.
let length_base : FixedArray[Int32] = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83,
  99, 115, 131, 163, 195, 227, 258,
]

///|
/// The extra bits each length symbol carries.
let length_extra : FixedArray[Int32] = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5,
  5, 0,
]

///|
/// The base distance for each distance symbol 0–29.
let dist_base : FixedArray[Int32] = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
  1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
]

///|
/// The extra bits each distance symbol carries.
let dist_extra : FixedArray[Int32] = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
  12, 12, 13, 13,
]

///|
/// The order the code-length code writes its own lengths in (§3.2.7), which puts
/// the ones most likely to be zero last so they can be left out.
let length_order : FixedArray[Int32] = [
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
]

///|
/// The length symbol for a match length, with its extra bits and their value.
fn length_code(len : Int32) -> (Int32, Int32, Int32) {
  let mut i = 28
  while i > 0 && length_base[i] > len {
    i -= 1
  }
  (257 + i, length_extra[i], len - length_base[i])
}

///|
/// The distance symbol for a distance, with its extra bits and their value.
fn distance_code(dist : Int32) -> (Int32, Int32, Int32) {
  let mut i = 29
  while i > 0 && dist_base[i] > dist {
    i -= 1
  }
  (i, dist_extra[i], dist - dist_base[i])
}

///|
/// The fixed literal/length code of §3.2.6, as a code and a width.
fn fixed_code(sym : Int32) -> (Int32, Int32) {
  if sym < 144 {
    (0x30 + sym, 8)
  } else if sym < 256 {
    (0x190 + (sym - 144), 9)
  } else if sym < 280 {
    (sym - 256, 7)
  } else {
    (0xC0 + (sym - 280), 8)
  }
}

///|
/// A canonical Huffman code, held as the count of codes at each width, the
/// symbols in code order, and a direct table for the first few bits.
///
/// The table turns the common case into one array read: an index of the next
/// `bits` bits — least significant first, as the stream carries them — gives the
/// symbol and the width it took. A code longer than `bits` (a dynamic block may
/// have one, up to fifteen) is left as zero and falls back to the bit-at-a-time
/// walk, which stays exact.
priv struct Huffman {
  counts : FixedArray[Int32]
  symbols : FixedArray[Int32]
  table : Array[Int32]
  bits : Int32
}

///|
/// The widest table this decoder builds. Nine bits cover the fixed code whole, and
/// capping a dynamic one here keeps the table under two kilobytes while leaving its
/// longer codes to the exact path.
let table_bits : Int32 = 9

///|
/// Build a code from the width assigned to each symbol. A width of zero means
/// the symbol is not in the code.
fn Huffman::of(lengths : FixedArray[Int32], n : Int32) -> Huffman {
  let counts = FixedArray::make(16, 0)
  for i in 0..<n {
    counts[lengths[i]] += 1
  }
  // Width zero is "not in the code", and has no codes to hand out.
  counts[0] = 0
  let offsets = FixedArray::make(16, 0)
  for width in 1..<16 {
    offsets[width] = offsets[width - 1] + counts[width - 1]
  }
  let symbols = FixedArray::make(if n > 0 { n } else { 1 }, 0)
  for i in 0..<n {
    if lengths[i] != 0 {
      symbols[offsets[lengths[i]]] = i
      offsets[lengths[i]] += 1
    }
  }
  let mut width = 0
  for i in 0..<n {
    if lengths[i] > width {
      width = lengths[i]
    }
  }
  let bits = if width > table_bits { table_bits } else { width }
  let size = if bits > 0 { 1 << bits } else { 1 }
  let table = Array::make(size, 0)
  if bits > 0 {
    // Canonical codes: widths are handed out shortest first, and within a width in
    // symbol order, so `next[w]` is the next code of width `w` to give out (§3.2.2).
    let next = FixedArray::make(16, 0)
    let mut code = 0
    for w in 1..<16 {
      code = (code + counts[w - 1]) << 1
      next[w] = code
    }
    for i in 0..<n {
      let l = lengths[i]
      if l != 0 {
        let c = next[l]
        next[l] = c + 1
        if l <= bits {
          // Reverse the `l` bits into the stream's least-significant-first order,
          // then fill every index that shares those low bits.
          let mut rev = 0
          let mut v = c
          for _ in 0..<l {
            rev = (rev << 1) | (v & 1)
            v = v >> 1
          }
          let step = 1 << l
          let mut idx = rev
          while idx < size {
            table.unsafe_set(idx, (i << 4) | l)
            idx += step
          }
        }
      }
    }
  }
  { counts, symbols, table, bits, }
}

///|
/// Read one symbol: one lookup when the next bits are buffered and name a code the
/// table covers, and the bit-at-a-time walk otherwise.
fn Huffman::read(self : Huffman, br : BitReader) -> Int32 raise Refused {
  if self.bits > 0 {
    // Fill to the table width without consuming, then read the symbol in one go
    // when the code is no wider than what arrived. The fill is written out here
    // because this runs once per symbol, and a call per symbol is the cost.
    while br.held < self.bits && br.pos < br.src.length() {
      br.acc = br.acc | (br.src[br.pos].to_int() << br.held)
      br.pos += 1
      br.held += 8
    }
    let avail = if br.held < self.bits { br.held } else { self.bits }
    if avail > 0 {
      let entry = self.table.unsafe_get(br.acc & ((1 << self.bits) - 1))
      let len = entry & 0xF
      if len != 0 && len <= avail {
        br.acc = br.acc >> len
        br.held = br.held - len
        return entry >> 4
      }
    }
  }
  self.read_slow(br)
}

///|
/// Read one symbol, a bit at a time: the exact path, which also reports a code that
/// is not in the table.
///
/// Codes of a width are consecutive integers and widths are assigned shortest
/// first, so "is this one of the codes at this width" is a subtraction — no table,
/// and no way for a malformed length list to index out of one.
fn Huffman::read_slow(self : Huffman, br : BitReader) -> Int32 raise Refused {
  let mut code = 0
  let mut first = 0
  let mut index = 0
  for width in 1..<16 {
    code = code | br.bits(1)
    let count = self.counts[width]
    if code - first < count {
      return self.symbols[index + (code - first)]
    }
    index += count
    first = (first + count) << 1
    code = code << 1
  }
  raise Code(at=br.pos)
}

///|
/// The fixed literal/length code: 288 symbols, in three widths (§3.2.6).
let fixed_litlen : Huffman = {
  let lengths = FixedArray::make(288, 8)
  for i in 144..<256 {
    lengths[i] = 9
  }
  for i in 256..<280 {
    lengths[i] = 7
  }
  Huffman::of(lengths, 288)
}

///|
/// The fixed distance code: thirty symbols, all five bits wide.
let fixed_dist : Huffman = Huffman::of(FixedArray::make(30, 5), 30)

///|
/// The fixed literal/length code, each code reversed into the stream's bit order
/// once, packed as `(reversed << 4) | width`.
///
/// The encoder emits a fixed block, so a literal is written a hundred thousand times
/// a message; reversing eight bits on every one of them is the difference between a
/// table read and a loop.
let fixed_rev : Array[Int32] = {
  let table = Array::make(288, 0)
  for sym in 0..<288 {
    let (code, len) = fixed_code(sym)
    let mut rev = 0
    let mut v = code
    for _ in 0..<len {
      rev = (rev << 1) | (v & 1)
      v = v >> 1
    }
    table.unsafe_set(sym, (rev << 4) | len)
  }
  table
}

///|
/// The fixed distance code, five bits, already reversed.
let dist_rev : Array[Int32] = {
  let table = Array::make(30, 0)
  for sym in 0..<30 {
    let mut rev = 0
    let mut v = sym
    for _ in 0..<5 {
      rev = (rev << 1) | (v & 1)
      v = v >> 1
    }
    table.unsafe_set(sym, rev)
  }
  table
}

///|
/// The writer both encoders share, holding the bits that have not filled a byte.
priv struct Writer {
  out : Array[Byte]
  mut acc : Int32
  mut held : Int32
}

///|
/// A fresh writer with nothing held.
fn Writer::new() -> Writer {
  { out: [], acc: 0, held: 0, }
}

///|
/// The low `count` bits of `value`, least significant first — the stream's own
/// order, which is what headers and extra bits use.
fn Writer::bits(self : Writer, value : Int32, count : Int32) -> Unit {
  self.acc = self.acc | ((value & ((1 << count) - 1)) << self.held)
  self.held += count
  while self.held >= 8 {
    self.out.push((self.acc & 0xFF).to_byte())
    self.acc = self.acc >> 8
    self.held -= 8
  }
}

///|
/// Pad the last byte with zero bits, so what follows starts on a byte boundary.
fn Writer::align(self : Writer) -> Unit {
  if self.held > 0 {
    self.out.push((self.acc & 0xFF).to_byte())
    self.acc = 0
    self.held = 0
  }
}

///|
/// One literal or length symbol of the fixed code, written from the pre-reversed
/// table so the stream order costs no per-symbol loop (§3.1.1).
fn Writer::emit(self : Writer, sym : Int32) -> Unit {
  let packed = fixed_rev.unsafe_get(sym)
  let len = packed & 0xF
  self.acc = self.acc | (packed >> 4 << self.held)
  self.held += len
  // A fixed code is at most nine bits and nothing is held above seven, so at most
  // two octets come out — an unrolled flush, not a loop.
  if self.held >= 8 {
    self.out.push((self.acc & 0xFF).to_byte())
    self.acc = self.acc >> 8
    self.held -= 8
    if self.held >= 8 {
      self.out.push((self.acc & 0xFF).to_byte())
      self.acc = self.acc >> 8
      self.held -= 8
    }
  }
}

///|
/// A match: the length symbol with its extra bits, then the distance with its
/// own. In a fixed block a distance code is always five bits (§3.2.6).
fn Writer::emit_match(self : Writer, len : Int32, dist : Int32) -> Unit {
  let (lsym, lext, lval) = length_code(len)
  self.emit(lsym)
  if lext > 0 {
    self.bits(lval, lext)
  }
  let (dsym, dext, dval) = distance_code(dist)
  self.bits(dist_rev.unsafe_get(dsym), 5)
  if dext > 0 {
    self.bits(dval, dext)
  }
}

///|
/// The reader both decoders share.
priv struct BitReader {
  src : Bytes
  mut pos : Int32
  mut acc : Int32
  mut held : Int32
}

///|
/// Whether every octet has been read and no bit is left over.
fn BitReader::empty(self : BitReader) -> Bool {
  self.pos >= self.src.length() && self.held == 0
}

///|
/// The next `count` bits, least significant first.
fn BitReader::bits(self : BitReader, count : Int32) -> Int32 raise Refused {
  while self.held < count {
    if self.pos >= self.src.length() {
      raise Truncated(at=self.pos)
    }
    self.acc = self.acc | (self.src[self.pos].to_int() << self.held)
    self.pos += 1
    self.held += 8
  }
  let value = self.acc & ((1 << count) - 1)
  self.acc = self.acc >> count
  self.held -= count
  value
}

///|
/// One whole octet, drawn from the bits already buffered or the stream behind them.
fn BitReader::byte(self : BitReader) -> Int32 raise Refused {
  self.bits(8)
}
