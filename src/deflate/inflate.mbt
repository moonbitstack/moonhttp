// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The decompressing half of RFC 1951, for a stream that never ends.
///
/// The difference from a file decompressor is what "done" means. A file ends at
/// a block with `BFINAL` set; a permessage-deflate stream has no such block until
/// the connection closes, and each message stops at an empty stored block with
/// the four-octet tail stripped (RFC 7692 §7.2.1). So `decompress` appends the
/// tail back, reads blocks until the octets run out at a block boundary, and
/// reports what a message carried — the stream itself may continue in the next
/// call, with or without the window of the last one.
///
/// Running out of octets *inside* a block is a different thing, and is refused:
/// that is a message somebody truncated, not a message that ended.
pub struct Inflater {
  bits : Int32
  takeover : Bool
  limit : Int32
  mut dict : Array[Byte]
  /// What a fragment ended in the middle of: the octets from the last block
  /// boundary on, and the bits of the byte before them.
  mut pending : Bytes
  mut acc : Int32
  mut held : Int32
}

///|
/// A decompressor with a window of `1 << bits` bytes.
///
/// `takeover` keeps the window between messages, which is what a peer that did
/// not agree to `*_no_context_takeover` may rely on. `limit` bounds one
/// message's output: a compressed stream says nothing about how much it expands
/// to, and a small one can expand to more than the machine has, so a reader of
/// somebody else's messages should always say what it is prepared to hold. A
/// negative limit is no bound at all.
pub fn Inflater::new(
  bits~ : Int32 = 15,
  takeover~ : Bool = true,
  limit~ : Int32 = -1,
) -> Inflater {
  guard bits >= 8 && bits <= 15 else {
    abort("deflate: a \{bits}-bit window is outside what DEFLATE allows")
  }
  { bits, takeover, limit, dict: [], pending: b"", acc: 0, held: 0, }
}

///|
/// Throw away the window, as `*_no_context_takeover` allows between messages.
pub fn Inflater::reset(self : Inflater) -> Unit {
  self.dict = []
  self.pending = b""
  self.acc = 0
  self.held = 0
}

///|
/// Decompress one message — or one fragment of one — and keep the window for the
/// next.
///
/// `payload` is what the wire carried: a segment whose four-octet tail was
/// removed. The tail goes back on at the end of the message (RFC 7692 §7.2.2
/// step 1), and only there: a message split across frames is one DEFLATE stream,
/// and its header says so — "for non-final fragments, the removal of
/// 0x00 0x00 0xff 0xff MUST NOT be done" (§7.2.1).
///
/// So `more` says whether the message continues past this fragment. A fragment that stops in the
/// middle of a block is not an error in that case; what it stopped in the middle
/// of is kept and carried into the next call, which is the same "feed it more and
/// ask again" the message syntaxes use.
pub fn Inflater::decompress(
  self : Inflater,
  payload : BytesView,
  more~ : Bool = false,
) -> Bytes raise Refused {
  let src = Buffer()
  src.write_bytes(self.pending)
  src.write_bytes(payload)
  if !more {
    src.write_bytes(Bytes::from_array([b'\x00', b'\x00', b'\xff', b'\xff']))
  }
  let src = src.to_bytes()
  let br = BitReader::{ src, pos: 0, acc: self.acc, held: self.held, }
  let out : Array[Byte] = []
  // Where the last complete block ended, which is where a resumption starts —
  // octets, bits and how much output the blocks before it produced.
  let mut boundary = (0, 0, 0, 0)
  let mut cut = false
  let mut last = false
  while !last {
    if br.empty() {
      // The octets ran out where a block begins: the stream continues in the next
      // message, which is the ordinary case rather than the end of one.
      break
    }
    boundary = (br.pos, br.acc, br.held, out.length())
    try {
      last = one_block(br, out, self.dict, self.bits, self.limit)
    } catch {
      Truncated(..) => {
        cut = true
        break
      }
      e => raise e
    }
  }
  if cut && !more {
    // A message that stops inside a block is a message somebody cut short.
    raise Truncated(at=br.pos)
  }
  if cut {
    // The block that ran out produced part of a message that will be produced
    // again when the rest of it arrives, so what it wrote goes back.
    let (at, acc, held, length) = boundary
    while out.length() > length {
      let _ = out.pop()
    }
    let kept : Array[Byte] = []
    for k in at..<src.length() {
      kept.push(src[k])
    }
    self.pending = Bytes::from_array(kept)
    self.acc = acc
    self.held = held
  } else {
    self.pending = b""
    self.acc = 0
    self.held = 0
  }
  self.remember(out, more~)
  Bytes::from_array(out)
}

///|
/// One block, answering whether it was the stream's last.
fn one_block(
  br : BitReader,
  out : Array[Byte],
  dict : Array[Byte],
  bits : Int32,
  ceiling : Int32,
) -> Bool raise Refused {
  let last = br.bits(1) == 1
  match br.bits(2) {
    0 => stored(br, out, ceiling)
    1 => block(br, out, dict, bits, fixed_litlen, fixed_dist, ceiling)
    2 => {
      let (litlen, dist) = tables(br)
      block(br, out, dict, bits, litlen, dist, ceiling)
    }
    got => raise Block(at=br.pos, got~)
  }
  last
}

///|
/// Keep as much of what was read as a window can reach, or let it go.
///
/// The window is only the peer's to drop at the *end* of a message: within one,
/// a back-reference may reach anywhere in it, fragments included, whether or not
/// the terms allow the window to survive into the next message.
fn Inflater::remember(self : Inflater, out : Array[Byte], more~ : Bool) -> Unit {
  if !self.takeover && !more {
    self.dict = []
    return
  }
  let window = 1 << self.bits
  if out.length() >= window {
    let from = out.length() - window
    let kept : Array[Byte] = []
    for k in from..<out.length() {
      kept.push(out[k])
    }
    self.dict = kept
    return
  }
  for k in 0..<out.length() {
    self.dict.push(out[k])
  }
  if self.dict.length() > 2 * window {
    let from = self.dict.length() - window
    let kept : Array[Byte] = []
    for k in from..<self.dict.length() {
      kept.push(self.dict[k])
    }
    self.dict = kept
  }
}

///|
/// A stored block: the bit stream aligns to a byte, then a length, its
/// complement, and that many octets verbatim (§3.2.4).
fn stored(
  br : BitReader,
  out : Array[Byte],
  ceiling : Int32,
) -> Unit raise Refused {
  // Whatever is left of the current byte is the padding the format put there.
  br.acc = 0
  br.held = 0
  if br.pos + 4 > br.src.length() {
    raise Truncated(at=br.pos)
  }
  let len = br.src[br.pos].to_int() | (br.src[br.pos + 1].to_int() << 8)
  let nlen = br.src[br.pos + 2].to_int() | (br.src[br.pos + 3].to_int() << 8)
  if len != (nlen ^ 0xFFFF) {
    raise Block(at=br.pos, got=3)
  }
  br.pos += 4
  if br.pos + len > br.src.length() {
    raise Truncated(at=br.pos)
  }
  if ceiling >= 0 && out.length() + len > ceiling {
    raise Exceeded(limit=ceiling, got=out.length() + len)
  }
  for _ in 0..<len {
    out.push(br.src[br.pos])
    br.pos += 1
  }
}

///|
/// The code tables a dynamic block carries with it (§3.2.7).
fn tables(br : BitReader) -> (Huffman, Huffman) raise Refused {
  let nlit = br.bits(5) + 257
  let ndist = br.bits(5) + 1
  let ncode = br.bits(4) + 4
  let meta = FixedArray::make(19, 0)
  for i in 0..<ncode {
    meta[length_order[i]] = br.bits(3)
  }
  let code_lengths = Huffman::of(meta, 19)
  let lengths = FixedArray::make(nlit + ndist, 0)
  let mut i = 0
  while i < nlit + ndist {
    let sym = code_lengths.read(br)
    if sym < 16 {
      lengths[i] = sym
      i += 1
    } else {
      let (repeat, value) = match sym {
        16 => {
          if i == 0 {
            raise Code(at=br.pos)
          }
          (3 + br.bits(2), lengths[i - 1])
        }
        17 => (3 + br.bits(3), 0)
        _ => (11 + br.bits(7), 0)
      }
      if i + repeat > nlit + ndist {
        raise Code(at=br.pos)
      }
      for _ in 0..<repeat {
        lengths[i] = value
        i += 1
      }
    }
  }
  let lit = FixedArray::make(nlit, 0)
  for k in 0..<nlit {
    lit[k] = lengths[k]
  }
  let dist = FixedArray::make(ndist, 0)
  for k in 0..<ndist {
    dist[k] = lengths[nlit + k]
  }
  (Huffman::of(lit, nlit), Huffman::of(dist, ndist))
}

///|
/// The body of a compressed block, under whichever pair of code tables.
///
/// `dict` is the window the previous messages left behind: a match may reach
/// into it, which is what context takeover is for.
fn block(
  br : BitReader,
  out : Array[Byte],
  dict : Array[Byte],
  bits : Int32,
  litlen : Huffman,
  dist : Huffman,
  ceiling : Int32,
) -> Unit raise Refused {
  let mut open = true
  while open {
    if ceiling >= 0 && out.length() > ceiling {
      raise Exceeded(limit=ceiling, got=out.length())
    }
    let sym = litlen.read(br)
    if sym < 256 {
      out.push(sym.to_byte())
    } else if sym == 256 {
      open = false
    } else {
      let index = sym - 257
      if index >= 29 {
        raise Code(at=br.pos)
      }
      let len = length_base[index] + br.bits(length_extra[index])
      let dcode = dist.read(br)
      if dcode >= 30 {
        raise Code(at=br.pos)
      }
      let back = dist_base[dcode] + br.bits(dist_extra[dcode])
      if back > 1 << bits || back > out.length() + dict.length() {
        raise Distance(at=br.pos, got=back)
      }
      if ceiling >= 0 && out.length() + len > ceiling {
        raise Exceeded(limit=ceiling, got=out.length() + len)
      }
      // A byte at a time on purpose: a match may overlap itself, and the octets
      // it copies are the ones this loop is writing.
      for _ in 0..<len {
        let at = out.length()
        let value = if back <= at {
          out[at - back].to_int()
        } else {
          dict[dict.length() - (back - at)].to_int()
        }
        out.push(value.to_byte())
      }
    }
  }
}
