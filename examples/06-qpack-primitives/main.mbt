///|
/// QPACK primitives (RFC 9204): the 99-entry static table with exact and
/// name-only lookups (Appendix A) and the string literal coding raw and Huffman — the
/// building blocks the field-section encoder is assembled from. The prefixed integer
/// under them all is RFC 7541 §5.1 unchanged, so it comes from `moonvar`.
///
///     moon run examples/27-qpack-primitives --target native
#coverage.skip
fn main {
  run() catch {
    e => println("qpack error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  println("static table entries = \{@qpack.static_table.length()}")
  println("get(17)  = \{field(@qpack.entry(17))} (expect :method GET)")
  println("find(:method, GET)   = \{opt_i(@qpack.find(b":method", b"GET"))}")
  println("find_name(:status)   = \{opt_i(@qpack.find_name(b":status"))}")
  println(
    "max_entries(4096)=\{@qpack.max_entries(4096)} entry_size(:method,GET)=\{@qpack.cost(b":method", b"GET")}",
  )
  let enc = @prefix.encode(1337, prefix=5)
  println("int 1337 (5-bit prefix) = \{hex(enc)}")
  let (v, n) = @prefix.decode(enc[:], prefix=5)
  println("decoded = \{v} in \{n} bytes")
  let raw = @qpack.string(b"hello", 7, 0, false)
  let huff = @qpack.string(b"hello", 7, 0, true)
  println(
    "string \"hello\": raw=\{raw.length()} huffman=\{huff.length()} bytes (huffman shorter=\{huff.length() < raw.length()})",
  )
  match @qpack.read_string(huff[:], 7) {
    Some((d, _)) => println("huffman decoded = \{ascii(d)}")
    None => println("bad string")
  }
}

///|
fn field(o : @header.Header?) -> String {
  match o {
    Some(h) => h.ascii().0 + " " + h.ascii().1
    None => "(none)"
  }
}

///|
fn opt_i(o : Int?) -> String {
  match o {
    Some(n) => n.to_string()
    None => "(none)"
  }
}

///|
fn hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}
