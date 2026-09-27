// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One representation, five requests: the fresh one, the repeat, the lost
/// update, the resumed download and the one whose file moved on underneath it.
fn main raise {
  let body = b"the body of a small file, twice the length of its own name"
  let modified = @moondate.http("Sun, 06 Nov 1994 08:49:37 GMT")
  let etag = @conditional.hash(body[:], digest=@sha2.Hasher::new())
  println("ETag           " + etag.encode())
  println("Last-Modified  " + modified.http_text())
  println(
    "the cheap one  " +
    @conditional.stamp(length=body.length().to_int64(), modified~).encode(),
  )
  println("")

  // First time through: nothing is asked, everything is sent.
  verdict("a first GET", @conditional.ask, "GET", etag, modified)

  // The client comes back with what it was given.
  verdict(
    "the same GET, a day later",
    @conditional.Ask::new(none_matching=@conditional.These([etag])),
    "GET",
    etag,
    modified,
  )

  // A write that must not clobber somebody else's: the tag it holds is stale.
  verdict(
    "PUT holding a stale tag",
    @conditional.Ask::new(
      matching=@conditional.These([@conditional.Tag::new("older")]),
    ),
    "PUT",
    etag,
    modified,
  )

  // A create that must not overwrite: `*` asks only whether anything is there.
  verdict(
    "PUT that must not overwrite",
    @conditional.Ask::new(none_matching=@conditional.Any),
    "PUT",
    etag,
    modified,
  )
  println("")

  // A resumed download asks for the rest of the file and states what it has.
  let asking = @conditional.Ask::new(ranging=@conditional.Marked(etag))
  let specs = @range.decode("bytes=32-")
  println("Range          bytes=32-")
  println("If-Range       " + etag.encode())
  partial("still the same file", asking, etag, specs)
  partial(
    "the file changed",
    asking,
    @conditional.hash(b"something else"[:], digest=@sha2.Hasher::new()),
    specs,
  )
}

///|
fn verdict(
  what : String,
  ask : @conditional.Ask,
  verb : String,
  etag : @conditional.Tag,
  modified : @moondate.Moment,
) -> Unit {
  let answer = match ask.evaluate(verb~, etag~, modified~) {
    Go => "200, with the body"
    Fresh => "304, without it"
    Failed => "412"
  }
  println(wide(what) + answer)
}

///|
/// What a server does with a `Range` once `If-Range` has had its say.
fn partial(
  what : String,
  ask : @conditional.Ask,
  etag : @conditional.Tag,
  specs : Array[@range.Spec]?,
) -> Unit {
  if !ask.unchanged(etag~) {
    println(wide(what) + "200, the whole thing again")
    return
  }
  guard specs is Some(specs) else { return }
  guard @range.measure(specs[:], length=58L) is Some(parts) else { return }
  let content = @range.Content::new(parts[0], complete=58L)
  println(wide(what) + "206, Content-Range: " + content.encode())
}

///|
fn wide(text : String) -> String {
  let out = StringBuilder()
  out.write_string(text)
  for i = text.length(); i < 28; i = i + 1 {
    out.write_char(' ')
  }
  out.to_string()
}
