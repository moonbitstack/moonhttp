///|
/// Serving part of a file (RFC 9110 §14): reading the `Range` a player sends,
/// measuring it against the length, and writing the `Content-Range` that goes
/// back — including the 416 answer, which says how long the file actually is.
///
///     moon run examples/12-range --target native
#coverage.skip
fn main {
  // A ten-thousand-octet representation, and the asks §14.1.2 prints.
  let length = 10000L
  println("Accept-Ranges: \{@range.accept()}")
  for
    asked in [
      "bytes=0-499", "bytes=-500", "bytes=9500-", "bytes=0-999, 4500-5499, -1000",
      "bytes=500-600,601-999", "bytes=20000-", "items=0-9",
    ] {
    let answer = match @range.decode(asked) {
      // §14.2: a unit we do not implement is ignored, and the answer is 200
      // with the whole representation.
      None => "ignored -> 200, the whole thing"
      Some(specs) =>
        match @range.measure(specs[:], length~) {
          // §14.4: a 416 still says how long the representation is, so the
          // client can ask again for something that exists.
          None => "416 -> " + @range.unsatisfied(length).encode()
          Some(parts) => {
            let lines = []
            for part in parts {
              lines.push(
                @range.Content::new(part, complete=length).encode() +
                " (\{part.length()} octets)",
              )
            }
            "206 -> " + lines.join("\n         ")
          }
        }
    }
    println(asked)
    println("  " + answer)
  }

  // More than one range travels as multipart/byteranges (§14.6).
  let head : @range.Part = { at: 0L, last: 3L, }
  let tail : @range.Part = { at: 6L, last: 9L, }
  println("")
  println("Content-Type: \{@range.multipart("cut")}")
  let body = @range.parts(
    [(head, b"0123"), (tail, b"6789")][:],
    boundary="cut",
    kind="text/plain",
    complete=10L,
  )
  let shown = StringBuilder()
  for byte in body {
    if byte == b'\r' {
      shown.write_string("\\r")
    } else if byte == b'\n' {
      shown.write_string("\\n\n")
    } else {
      shown.write_char(byte.to_int().unsafe_to_char())
    }
  }
  println(shown.to_string())

  // §13.1.5: the range is served only if the representation has not changed.
  let tag = "\"v1\""
  println(
    "If-Range \{tag} against \{tag} -> \{@range.unchanged(tag, etag=tag)}",
  )
  println(
    "If-Range \{tag} against \"v2\" -> \{@range.unchanged(tag, etag="\"v2\"")}",
  )
  println(
    "If-Range W/\{tag} against \{tag} -> \{@range.unchanged("W/" + tag, etag=tag)}",
  )
}
