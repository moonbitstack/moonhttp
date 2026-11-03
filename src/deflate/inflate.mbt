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
/// Running out of octets *inside* a block is a different thing at the end of a
/// message, and is refused: that is a message somebody truncated. Inside a
/// message it is the ordinary case, and decoding picks up where it stopped.
pub struct Inflater {
  bits : Int32
  takeover : Bool
  limit : Int32
  priv mut dict : Array[Byte]
  // What a fragment ended in the middle of: the octets of a symbol, a stored
  // block's header or a dynamic block's code tables that were not all there yet,
  // and the bits of the byte before them. Resuming from a symbol rather than a
  // block keeps a message split into small frames linear: a block can run to
  // the whole message, and decoding it again per frame is quadratic.
  priv mut pending : Bytes
  priv mut acc : Int32
  priv mut held : Int32
  priv mut mode : Mode
  priv mut last : Bool
}

///|
/// Where the decoder stands between blocks or inside one.
priv enum Mode {
  Header
  Stored(Int32)
  Codes(Huffman, Huffman)
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
  {
    bits,
    takeover,
    limit,
    dict: [],
    pending: b"",
    acc: 0,
    held: 0,
    mode: Header,
    last: false,
  }
}

///|
/// Throw away the window, as `*_no_context_takeover` allows between messages.
pub fn Inflater::reset(self : Inflater) -> Unit {
  self.dict = []
  self.pending = b""
  self.acc = 0
  self.held = 0
  self.mode = Header
  self.last = false
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
  let br = BitReader::{
    src: src.to_bytes(),
    pos: 0,
    acc: self.acc,
    held: self.held,
  }
  let out : Array[Byte] = []
  // A compressed message is usually about the size of what it expands to, so a
  // reservation the size of the payload avoids growing the buffer a dozen times.
  out.reserve_capacity(payload.length() + 16)
  // Where the last whole step ended — a block header, a stored run, a symbol —
  // which is where the next call resumes if this one runs out of octets. Three
  // scalars rather than a tuple: the loop runs once per symbol, and a tuple here
  // is an allocation per octet of the message.
  let mut mark_pos = 0
  let mut mark_acc = self.acc
  let mut mark_held = self.held
  let mut cut = false
  let mut done = false
  // The handler sits outside the loop: installing one per symbol costs more than
  // the symbol itself for a message of a hundred thousand of them.
  try {
    while !done {
      mark_pos = br.pos
      mark_acc = br.acc
      mark_held = br.held
      match self.mode {
        Header => {
          if br.empty() {
            // The octets ran out where a block begins: the stream continues in
            // the next message, which is the ordinary case rather than the end.
            break
          }
          self.mode = header(br, self)
        }
        Stored(left) => {
          if self.limit >= 0 && out.length() + left > self.limit {
            raise Exceeded(limit=self.limit, got=out.length() + left)
          }
          let mut need = left
          // Whole octets the table lookup buffered come before the stream's own.
          while need > 0 && br.held >= 8 {
            out.push((br.acc & 0xFF).to_byte())
            br.acc = br.acc >> 8
            br.held = br.held - 8
            need -= 1
          }
          let there = br.src.length() - br.pos
          let take = if need < there { need } else { there }
          for _ in 0..<take {
            out.push(br.src[br.pos])
            br.pos += 1
          }
          if take < need {
            self.mode = Stored(need - take)
            raise Truncated(at=br.pos)
          }
          self.mode = Header
          done = self.last
        }
        Codes(litlen, dist) => {
          // The symbol is decoded here rather than in a helper: this branch runs
          // once per octet the message expands to, and a call per octet is the
          // difference between a table read and a call plus a table read.
          if self.limit >= 0 && out.length() > self.limit {
            raise Exceeded(limit=self.limit, got=out.length())
          }
          let sym = litlen.read(br)
          if sym < 256 {
            out.push(sym.to_byte())
          } else if sym == 256 {
            self.mode = Header
            done = self.last
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
            if back > 1 << self.bits || back > out.length() + self.dict.length() {
              raise Distance(at=br.pos, got=back)
            }
            if self.limit >= 0 && out.length() + len > self.limit {
              raise Exceeded(limit=self.limit, got=out.length() + len)
            }
            // A byte at a time on purpose: a match may overlap itself, and the
            // octets it copies are the ones this loop is writing.
            for _ in 0..<len {
              let at = out.length()
              let value = if back <= at {
                out.unsafe_get(at - back).to_int()
              } else {
                self.dict.unsafe_get(self.dict.length() - (back - at)).to_int()
              }
              out.push(value.to_byte())
            }
          }
        }
      }
    }
  } catch {
    Truncated(..) => cut = true
    e => raise e
  }
  if !more && (cut || !(self.mode is Header)) {
    // A message that stops inside a block is a message somebody cut short.
    raise Truncated(at=br.pos)
  }
  if cut {
    // A stored run keeps what it copied; anything else resumes at the step it
    // was in the middle of, so what that step read is read again.
    let at = if self.mode is Stored(_) { br.pos } else { mark_pos }
    let acc = if self.mode is Stored(_) { br.acc } else { mark_acc }
    let held = if self.mode is Stored(_) { br.held } else { mark_held }
    self.pending = br.src[at:].to_owned()
    self.acc = acc
    self.held = held
  } else {
    self.pending = b""
    self.acc = 0
    self.held = 0
  }
  if done {
    self.mode = Header
    self.last = false
  }
  self.remember(out, more~)
  Bytes::from_array(out)
}

///|
/// A block's header: what kind of block it is, and for a stored block its
/// length, for a dynamic one its code tables (§3.2.3).
fn header(br : BitReader, self : Inflater) -> Mode raise Refused {
  let last = br.bits(1) == 1
  let mode = match br.bits(2) {
    0 => {
      // §3.2.4: a stored block starts on the next byte boundary. Drop what is left
      // of the current byte, but keep any whole bytes the table lookup buffered:
      // they are the LEN the block begins with.
      let pad = br.held & 7
      br.acc = br.acc >> pad
      br.held = br.held - pad
      let len = br.byte() | (br.byte() << 8)
      let nlen = br.byte() | (br.byte() << 8)
      if len != (nlen ^ 0xFFFF) {
        raise Block(at=br.pos, got=3)
      }
      Mode::Stored(len)
    }
    1 => Codes(fixed_litlen, fixed_dist)
    2 => {
      let (litlen, dist) = tables(br)
      Codes(litlen, dist)
    }
    got => raise Block(at=br.pos, got~)
  }
  self.last = last
  mode
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
