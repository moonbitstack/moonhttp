///|
/// The QPACK dynamic table (RFC 9204 §3.2): encoder-stream instructions (set
/// capacity, insert with a static/dynamic name reference, insert literal,
/// duplicate) build the table, absolute and relative indexing read it, an
/// instruction round-trips through the encoder-stream codec, and a dynamic
/// encode splits the encoder-stream inserts from the field section.
///
///     moon run examples/29-qpack-dynamic --target native
#coverage.skip
fn main {
  run() catch {
    e => println("qpack dyn error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let t = @qpack.Table::new(4096)
  let _ = t.apply(SetCapacity(220))
  let _ = t.apply(Insert(is_static=true, index=0, value=b"www.example.com"))
  let _ = t.apply(InsertLiteral(name=b"custom-key", value=b"custom-value"))
  let _ = t.apply(Duplicate(index=0))
  println(
    "table: entries=\{t.entries.length()} insert_count=\{t.insert_count} used=\{t.used}",
  )
  println("get(0)=\{pairb(t.get(0))} get_relative(0)=\{pairb(t.relative(0))}")
  let inst = @qpack.Change::encode(
    InsertLiteral(name=b"k", value=b"v"),
    huffman=false,
  )
  match @qpack.Change::decode(inst[:]) {
    Some((_, n)) =>
      println("encoder inst round-trips, consumed \{n} of \{inst.length()}")
    None => println("bad instruction")
  }
  // Encode headers with dynamic indexing (max_entries = negotiated capacity),
  // then apply the encoder-stream to a peer table and decode the section back.
  let headers = [
    @header.Header::of(":authority", "www.example.com"),
    @header.Header::of("custom-key", "custom-value"),
  ]
  let dt = @qpack.Table::new(4096)
  let (insts, section) = @qpack.encode_with(headers, dt, 128, huffman=false)
  println(
    "dynamic encode: \{insts.length()} encoder-stream bytes, \{section.length()} field-section bytes, inserts=\{dt.insert_count}",
  )
  let peer = @qpack.Table::new(4096)
  let view = insts[:]
  let mut off = 0
  while off < insts.length() {
    match @qpack.Change::decode(view[off:]) {
      Some((got, consumed)) => {
        let _ = peer.apply(got)
        off = off + consumed
      }
      None => break
    }
  }
  println(
    "dynamic round-trip = \{@qpack.decode_with(section, peer, 128) == headers}",
  )
  // The decoder-stream acknowledgement direction (RFC 9204 §4.4).
  let dinst = @qpack.Ack::encode(Section(stream_id=4))
  match @qpack.Ack::decode(dinst[:]) {
    Some((got, _)) =>
      println(
        "decoder inst (Section) round-trip = \{got == Section(stream_id=4)}",
      )
    None => println("bad decoder inst")
  }
}

///|
fn pairb(o : (Bytes, Bytes)?) -> String {
  match o {
    Some((n, v)) => ascii(n) + " " + ascii(v)
    None => "(none)"
  }
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}
