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
} derive(Eq, Debug)

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
/// A canonical Huffman code, held as the count of codes at each width and the
/// symbols in code order — all a bit-at-a-time reader needs, and a great deal
/// less than a table (§3.2.2).
priv struct Huffman {
  counts : FixedArray[Int32]
  symbols : FixedArray[Int32]
}

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
  { counts, symbols, }
}

///|
/// Read one symbol, a bit at a time.
///
/// Codes of a width are consecutive integers and widths are assigned shortest
/// first, so "is this one of the codes at this width" is a subtraction — no
/// table to build, and no way for a malformed length list to index out of one.
fn Huffman::read(self : Huffman, br : BitReader) -> Int32 raise Refused {
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
/// A Huffman code, most significant bit first, against the stream's order — so
/// it is reversed on the way in (§3.1.1).
fn Writer::huff(self : Writer, code : Int32, len : Int32) -> Unit {
  let mut flipped = 0
  for i in 0..<len {
    flipped = (flipped << 1) | ((code >> i) & 1)
  }
  self.bits(flipped, len)
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
/// One literal or length symbol of the fixed code.
fn Writer::emit(self : Writer, sym : Int32) -> Unit {
  let (code, len) = fixed_code(sym)
  self.huff(code, len)
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
  self.huff(dsym, 5)
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
