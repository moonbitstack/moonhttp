// The dynamic block of RFC 1951 §3.2.7: the code lengths travel with the block.
//
// The fixed code is a compromise made for streams compressed in one pass with no
// memory, and it spends eight bits on every octet of the lower half of the
// alphabet. A message that is mostly one alphabet — text, JSON, the letters a
// WebSocket carries — can spend five. The price is the header: two codes, the
// lengths of both, and a third code to carry those lengths. On a message of a few
// kilobytes that is a fraction of what it saves; on one of a few bytes it is more
// than the whole message, which is why the encoder compares the two costs and
// keeps the fixed block when it wins.

///|
/// A block's codes, ready to write: the two symbol codes, the code-length code
/// that carries their lengths, and how many bits the header takes.
priv struct Plan {
  lit_len : Array[Int32]
  lit_code : Array[Int32]
  dist_len : Array[Int32]
  dist_code : Array[Int32]
  /// One past the last literal/length symbol used, and at least 257 — the block
  /// ends with a symbol, so 256 is always in the code.
  nlit : Int32
  /// One past the last distance symbol used, and at least 1.
  ndist : Int32
  cl_len : Array[Int32]
  cl_code : Array[Int32]
  /// The run-length encoded lengths: the symbol, and its extra-bit value.
  rle_sym : Array[Int32]
  rle_val : Array[Int32]
  /// How many of the nineteen code-length widths the header writes.
  hclen : Int32
  header_bits : Int32
}

///|
/// The extra bits a run-length symbol carries: 16 repeats the last length, 17 and
/// 18 repeat a zero (§3.2.7).
fn rle_extra(sym : Int32) -> Int32 {
  if sym == 16 {
    2
  } else if sym == 17 {
    3
  } else if sym == 18 {
    7
  } else {
    0
  }
}

///|
/// A plan for the block these frequencies describe.
fn build_plan(lit_freq : Array[Int32], dist_freq : Array[Int32]) -> Plan {
  let lit_len = huffman_lengths(lit_freq, 15)
  let dist_len = huffman_lengths(dist_freq, 15)
  let mut nlit = 286
  while nlit > 257 && lit_len.unsafe_get(nlit - 1) == 0 {
    nlit -= 1
  }
  let mut ndist = 30
  while ndist > 1 && dist_len.unsafe_get(ndist - 1) == 0 {
    ndist -= 1
  }
  // §3.2.7 carries the two length lists as one, the literal/length widths and then
  // the distance ones, and runs both through the same run-length code.
  let end = nlit + ndist
  let seq = Array::make(end, 0)
  for i in 0..<nlit {
    seq.unsafe_set(i, lit_len.unsafe_get(i))
  }
  for i in 0..<ndist {
    seq.unsafe_set(nlit + i, dist_len.unsafe_get(i))
  }
  let rle_sym : Array[Int32] = []
  let rle_val : Array[Int32] = []
  let mut i = 0
  while i < end {
    let cur = seq.unsafe_get(i)
    let mut run = 1
    while i + run < end && seq.unsafe_get(i + run) == cur {
      run += 1
    }
    if cur == 0 {
      // Zeros are the commonest run in a length list, and the two symbols that
      // exist only for them carry up to 138 at a time.
      while run >= 11 {
        let r = if run > 138 { 138 } else { run }
        rle_sym.push(18)
        rle_val.push(r - 11)
        run -= r
        i += r
      }
      while run >= 3 {
        let r = if run > 10 { 10 } else { run }
        rle_sym.push(17)
        rle_val.push(r - 3)
        run -= r
        i += r
      }
      while run > 0 {
        rle_sym.push(0)
        rle_val.push(0)
        run -= 1
        i += 1
      }
    } else {
      rle_sym.push(cur)
      rle_val.push(0)
      run -= 1
      i += 1
      while run >= 3 {
        let r = if run > 6 { 6 } else { run }
        rle_sym.push(16)
        rle_val.push(r - 3)
        run -= r
        i += r
      }
      while run > 0 {
        rle_sym.push(cur)
        rle_val.push(0)
        run -= 1
        i += 1
      }
    }
  }
  let cl_freq = Array::make(19, 0)
  for k in 0..<rle_sym.length() {
    let s = rle_sym.unsafe_get(k)
    cl_freq.unsafe_set(s, cl_freq.unsafe_get(s) + 1)
  }
  let cl_len = huffman_lengths(cl_freq, 7)
  let cl_code = canonical(cl_len)
  // The header writes the nineteen widths in the order of §3.2.7, which puts the
  // ones most likely to be zero last, and stops at the last nonzero — but never
  // writes fewer than four.
  let mut hclen = 19
  while hclen > 4 && cl_len.unsafe_get(length_order.unsafe_get(hclen - 1)) == 0 {
    hclen -= 1
  }
  let mut header_bits = 5 + 5 + 4 + 3 * hclen
  for k in 0..<rle_sym.length() {
    let s = rle_sym.unsafe_get(k)
    header_bits += cl_len.unsafe_get(s) + rle_extra(s)
  }
  {
    lit_len,
    lit_code: canonical(lit_len),
    dist_len,
    dist_code: canonical(dist_len),
    nlit,
    ndist,
    cl_len,
    cl_code,
    rle_sym,
    rle_val,
    hclen,
    header_bits,
  }
}

///|
/// How many bits the plan's own symbols take: what the frequencies say, which is
/// the sum over the block without walking it again.
fn Plan::data_bits(
  self : Plan,
  lit_freq : Array[Int32],
  dist_freq : Array[Int32],
) -> Int32 {
  let mut bits = self.header_bits
  for s in 0..<286 {
    bits += lit_freq.unsafe_get(s) * self.lit_len.unsafe_get(s)
  }
  for s in 0..<30 {
    bits += dist_freq.unsafe_get(s) * self.dist_len.unsafe_get(s)
  }
  bits
}

///|
/// Write the header: the counts, the code-length code, and the run-length encoded
/// lengths it decodes.
fn Writer::plan(self : Writer, plan : Plan) -> Unit {
  self.bits(plan.nlit - 257, 5)
  self.bits(plan.ndist - 1, 5)
  self.bits(plan.hclen - 4, 4)
  for i in 0..<plan.hclen {
    self.bits(plan.cl_len.unsafe_get(length_order.unsafe_get(i)), 3)
  }
  for k in 0..<plan.rle_sym.length() {
    let s = plan.rle_sym.unsafe_get(k)
    self.code(plan.cl_code.unsafe_get(s))
    let extra = rle_extra(s)
    if extra > 0 {
      self.bits(plan.rle_val.unsafe_get(k), extra)
    }
  }
}

///|
/// Huffman code widths for a frequency table, none wider than `limit`.
///
/// A tree built by merging the two lightest nodes is optimal until one branch is
/// deeper than the format allows — fifteen bits here, seven for the code-length
/// code — and then halving every weight and rebuilding flattens the distribution
/// until it fits. The result is still a prefix code; it is only a little less
/// even than the unbounded one would have been.
fn huffman_lengths(freqs : Array[Int32], limit : Int32) -> Array[Int32] {
  let n = freqs.length()
  let used : Array[Int32] = []
  for i in 0..<n {
    if freqs.unsafe_get(i) > 0 {
      used.push(i)
    }
  }
  if used.length() == 0 {
    return Array::make(n, 0)
  }
  if used.length() == 1 {
    // A code of one symbol still has to be a code: one bit, and no other value is
    // ever written with it (§3.2.7 allows this for the distance code).
    let lone = Array::make(n, 0)
    lone.unsafe_set(used.unsafe_get(0), 1)
    return lone
  }
  let weights = Array::make(n, 0)
  for i in 0..<n {
    weights.unsafe_set(i, freqs.unsafe_get(i))
  }
  while true {
    let widths = tree_widths(weights, used)
    let mut deepest = 0
    for i in 0..<n {
      if widths.unsafe_get(i) > deepest {
        deepest = widths.unsafe_get(i)
      }
    }
    if deepest <= limit {
      return widths
    }
    for i in 0..<n {
      let f = weights.unsafe_get(i)
      if f > 0 {
        weights.unsafe_set(i, (f + 1) / 2)
      }
    }
  }
  abort("deflate: a code that cannot be limited")
}

///|
/// Fall back on the tree, and the width each symbol ends up at.
fn tree_widths(freqs : Array[Int32], used : Array[Int32]) -> Array[Int32] {
  let n = freqs.length()
  let widths = Array::make(n, 0)
  let m = used.length()
  let nodes = 2 * m - 1
  let weight = Array::make(nodes, 0)
  let parent = Array::make(nodes, -1)
  let leaf = Array::make(nodes, -1)
  for i in 0..<m {
    weight.unsafe_set(i, freqs.unsafe_get(used.unsafe_get(i)))
    leaf.unsafe_set(i, used.unsafe_get(i))
  }
  let taken = Array::make(nodes, false)
  let mut next = m
  while next < nodes {
    // The two lightest live nodes. A symbol table is a few hundred entries and this
    // runs once per block, so the plain scan is the right amount of machinery.
    let mut first = -1
    let mut second = -1
    for i in 0..<next {
      if !taken.unsafe_get(i) {
        if first < 0 {
          first = i
        } else if weight.unsafe_get(i) < weight.unsafe_get(first) {
          second = first
          first = i
        } else if second < 0 || weight.unsafe_get(i) < weight.unsafe_get(second) {
          second = i
        }
      }
    }
    taken.unsafe_set(first, true)
    taken.unsafe_set(second, true)
    weight.unsafe_set(
      next,
      weight.unsafe_get(first) + weight.unsafe_get(second),
    )
    parent.unsafe_set(first, next)
    parent.unsafe_set(second, next)
    next += 1
  }
  for i in 0..<m {
    let mut depth = 0
    let mut at = i
    while parent.unsafe_get(at) >= 0 {
      depth += 1
      at = parent.unsafe_get(at)
    }
    widths.unsafe_set(leaf.unsafe_get(i), depth)
  }
  widths
}

///|
/// The canonical codes for these widths, each reversed into the stream's order and
/// packed as `(reversed << 4) | width` (§3.2.2, §3.1.1).
fn canonical(widths : Array[Int32]) -> Array[Int32] {
  let n = widths.length()
  let counts = Array::make(16, 0)
  for i in 0..<n {
    let w = widths.unsafe_get(i)
    if w > 0 {
      counts.unsafe_set(w, counts.unsafe_get(w) + 1)
    }
  }
  let next = Array::make(16, 0)
  let mut code = 0
  for w in 1..<16 {
    code = (code + counts.unsafe_get(w - 1)) << 1
    next.unsafe_set(w, code)
  }
  let out = Array::make(n, 0)
  for i in 0..<n {
    let w = widths.unsafe_get(i)
    if w > 0 {
      let c = next.unsafe_get(w)
      next.unsafe_set(w, c + 1)
      out.unsafe_set(i, (reverse_bits(c, w) << 4) | w)
    }
  }
  out
}

///|
/// A code's bits in the order the stream carries them.
fn reverse_bits(code : Int32, width : Int32) -> Int32 {
  let mut rev = 0
  let mut v = code
  for _ in 0..<width {
    rev = (rev << 1) | (v & 1)
    v = v >> 1
  }
  rev
}
