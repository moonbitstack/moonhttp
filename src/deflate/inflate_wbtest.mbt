///|
test "a fragment carries over a symbol or a header, never a block" {
  // One dynamic block can span a whole message. Carrying it over whole and
  // decoding it again per fragment is quadratic in the message; resuming at the
  // last symbol keeps what is carried within one block header.
  let words : Array[Bytes] = [
    b"alpha ", b"bravo ", b"charlie ", b"delta ", b"echo ", b"foxtrot ", b"golf ",
  ]
  let plain = Buffer()
  let mut i = 0
  while plain.length() < 200000 {
    plain.write_bytes(words[(i * 5 + i / 3) % 7][:])
    i += 1
  }
  let wire = @zip.deflate(plain.to_bytes()[:], level=6)
  let inflater = Inflater::new()
  let out = Buffer()
  let mut most = 0
  // A whole stream ends at its final block, so its last octet ends the message.
  for at in 0..<wire.length() {
    let more = at + 1 < wire.length()
    out.write_bytes(inflater.decompress(wire[at:at + 1], more~))
    if inflater.pending.length() > most {
      most = inflater.pending.length()
    }
  }
  assert_eq(out.to_bytes(), plain.to_bytes())
  assert_true(most < 1024)
}
