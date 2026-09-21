// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What a download is labelled as.
test "an extension names a media type" {
  let cases = [
    ("report.pdf", "application/pdf"),
    ("photo.JPEG", "image/jpeg"),
    ("photo.jpg", "image/jpeg"),
    ("page.html", "text/html; charset=utf-8"),
    ("notes.md", "text/markdown; charset=utf-8"),
    ("data.json", "application/json"),
    ("config.yaml", "application/yaml"),
    ("archive.zip", "application/zip"),
    ("module.wasm", "application/wasm"),
    ("icon.svg", "image/svg+xml"),
    ("song.mp3", "audio/mpeg"),
    ("clip.mp4", "video/mp4"),
  ]
  for case in cases {
    let (name, want) = case
    assert_eq(@media.type_of(name[:]), want)
  }
}

///|
/// A text type carries its charset, because a browser handed `text/plain` with
/// none applies its own locale's and shows something else.
test "a text type says which charset" {
  assert_true(@media.type_of("a.txt"[:]).contains("charset=utf-8"))
  assert_true(@media.type_of("a.css"[:]).contains("charset=utf-8"))
  assert_true(@media.type_of("a.js"[:]).contains("charset=utf-8"))
  // A binary type does not, because the question does not arise.
  assert_false(@media.type_of("a.png"[:]).contains("charset"))
}

///|
/// Anything unrecognised is bytes, which a browser offers to save rather than
/// trying to render.
test "an unknown extension is bytes" {
  for name in ["a.unheard-of", "no-extension", "", ".", "trailing."] {
    assert_eq(@media.type_of(name[:]), @media.fallback)
  }
  assert_eq(@media.fallback, "application/octet-stream")
  // The last dot wins, so a compound extension resolves on its tail.
  assert_eq(@media.type_of("archive.tar.gz"[:]), "application/gzip")
  assert_eq(@media.type_of("a.b.c.png"[:]), "image/png")
}

///|
/// A plain name is quoted as it is; anything that percent-encoding would change
/// goes out as `filename*`, which is the only form that carries a character
/// outside ASCII and the only one a name cannot break out of.
test "a filename is named in the form that can carry it" {
  assert_eq(
    @media.disposition("report.pdf"[:]),
    "attachment; filename=\"report.pdf\"",
  )
  assert_eq(
    @media.disposition("report.pdf"[:], inline=true),
    "inline; filename=\"report.pdf\"",
  )
  // A space, an accent, a quote, a newline: each forces the encoded form.
  for
    name in ["my report.pdf", "résumé.pdf", "say \"hi\".txt", "one\ntwo.txt"] {
    let got = @media.disposition(name[:])
    assert_true(got.contains("filename*=utf-8''"))
    assert_false(got.contains("filename=\""))
  }
  // A path separator survives, because a name may legitimately carry one and
  // the header is not a path.
  assert_eq(
    @media.disposition("a/b.txt"[:]),
    "attachment; filename=\"a/b.txt\"",
  )
}

///|
/// The encoder and the decoder are a pair, which is why they are in one package.
test "percent encoding round-trips" {
  for
    text in ["hello", "a b", "résumé", "100%", "a/b", "?x=1&y=2", "", "~-._"] {
    let encoded = @mime.percent_encode(text[:])
    assert_eq(
      @mime.percent_decode(@utf8.encode(encoded[:])[:]),
      @utf8.encode(text[:]),
    )
  }
  // The unreserved set is never touched (RFC 3986 §2.3).
  assert_eq(@mime.percent_encode("aZ09-._~"[:]), "aZ09-._~")
  // And `safe` spares what the caller names, and nothing else.
  assert_eq(@mime.percent_encode("a/b"[:]), "a%2Fb")
  assert_eq(@mime.percent_encode("a/b"[:], safe="/"[:]), "a/b")
  assert_eq(@mime.percent_encode("a b/c"[:], safe="/"[:]), "a%20b/c")
}
