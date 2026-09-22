///|
/// QPACK field-section coding (RFC 9204 §4.5): a header list encodes through the
/// static table (indexed lines, static-name references, and full literals) both
/// raw and Huffman, and decodes back exactly. The Encoded Field Section Prefix
/// (§4.5.1) carrying the Required Insert Count and Base round-trips too.
///
///     moon run examples/28-qpack-field --target native
#coverage.skip
fn main {
  run() catch {
    e => println("qpack field error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let headers = [
    @header.Header::of(":method", "GET"),
    @header.Header::of(":path", "/index.html"),
    @header.Header::of(":scheme", "https"),
    @header.Header::of(":status", "200"),
    @header.Header::of("x-custom-header", "custom-value"),
    @header.Header::of("content-type", "application/json"),
  ]
  let raw = @qpack.encode(headers, huffman=false)
  let huff = @qpack.encode(headers, huffman=true)
  println("field section: raw=\{raw.length()} huffman=\{huff.length()} bytes")
  println("raw round-trip     = \{@qpack.decode(raw) == headers}")
  println("huffman round-trip = \{@qpack.decode(huff) == headers}")
  println("empty section      = \{hex(@qpack.encode([], huffman=false))}")
  // Section prefix: Required Insert Count 4, Base 6 (RFC 9204 §4.5.1).
  let sp = @qpack.prefix(4, 6, 128)
  match @qpack.read_prefix(sp[:], 128, 4) {
    Some((ric, base, consumed)) =>
      println(
        "prefix: encoded=\{hex(sp)} decoded ric=\{ric} base=\{base} consumed=\{consumed}",
      )
    None => println("bad prefix")
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
