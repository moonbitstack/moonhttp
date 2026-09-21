// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn body(text : String) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<text.length() {
    out.push((text.at(i).to_int() & 0xFF).to_byte())
  }
  Bytes::from_array(out)
}

///|
/// What a browser posts a plain form as.
test "urlencoded bodies" {
  let form = @mime.urlencoded(body("name=Ada&born=1815")[:])
  assert_eq(form.field("name"), Some("Ada"))
  assert_eq(form.field("born"), Some("1815"))
  assert_eq(form.field("absent"), None)
  assert_eq(form.uploads().length(), 0)
  // `+` is a space here and nowhere else in a URL.
  let spaced = @mime.urlencoded(body("q=two+words&r=three%20words")[:])
  assert_eq(spaced.field("q"), Some("two words"))
  assert_eq(spaced.field("r"), Some("three words"))
  // Percent-encoding, including a name that needs it and a value with none.
  let coded = @mime.urlencoded(body("a%26b=%3D%26%3F&flag=&plain")[:])
  assert_eq(coded.field("a&b"), Some("=&?"))
  assert_eq(coded.field("flag"), Some(""))
  assert_eq(coded.field("plain"), Some(""))
  // Non-ASCII arrives percent-encoded as UTF-8.
  let unicode = @mime.urlencoded(body("who=%E9%AA%87%E5%85%94")[:])
  assert_eq(unicode.field("who"), Some("骇兔"))
}

///|
/// A repeated name is a list, and taking only the first would drop half a set
/// of checkboxes without saying so.
test "a repeated name keeps every value" {
  let form = @mime.urlencoded(body("tag=a&tag=b&tag=c&other=x")[:])
  assert_eq(form.values("tag"), ["a", "b", "c"])
  assert_eq(form.field("tag"), Some("a"))
  assert_eq(form.values("other"), ["x"])
  assert_eq(form.values("none"), [])
  assert_eq(form.entries().length(), 4)
}

///|
/// An empty body, and the separators around nothing.
test "urlencoded edges" {
  assert_true(@mime.urlencoded(body("")[:]).is_empty())
  assert_true(@mime.urlencoded(body("&&&")[:]).is_empty())
  assert_eq(@mime.urlencoded(body("=value")[:]).field(""), Some("value"))
  // A stray percent that is not an escape stands for itself.
  assert_eq(@mime.urlencoded(body("a=100%&b=%zz")[:]).field("a"), Some("100%"))
  assert_eq(@mime.urlencoded(body("a=100%&b=%zz")[:]).field("b"), Some("%zz"))
}

///|
/// A multipart body exactly as a browser writes one.
let upload : String = "------WebKitFormBoundaryabc123\r\n" +
  "Content-Disposition: form-data; name=\"title\"\r\n" +
  "\r\n" +
  "a report\r\n" +
  "------WebKitFormBoundaryabc123\r\n" +
  "Content-Disposition: form-data; name=\"tags\"\r\n" +
  "\r\n" +
  "one\r\n" +
  "------WebKitFormBoundaryabc123\r\n" +
  "Content-Disposition: form-data; name=\"tags\"\r\n" +
  "\r\n" +
  "two\r\n" +
  "------WebKitFormBoundaryabc123\r\n" +
  "Content-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\n" +
  "Content-Type: text/plain\r\n" +
  "X-Checksum: abc\r\n" +
  "\r\n" +
  "line one\r\nline two\r\n" +
  "------WebKitFormBoundaryabc123--\r\n"

///|
test "a multipart body from a browser" {
  let form = @mime.multipart(body(upload)[:], "----WebKitFormBoundaryabc123")
  assert_eq(form.field("title"), Some("a report"))
  assert_eq(form.values("tags"), ["one", "two"])
  let file = form.file("file").unwrap()
  assert_eq(file.filename, "notes.txt")
  assert_eq(file.content_type, "text/plain")
  // The content keeps its own line breaks and loses only the trailing CRLF that
  // belongs to the delimiter.
  assert_eq(file.content, b"line one\r\nline two")
  assert_eq(file.size(), 18)
  assert_eq(file.header("x-checksum"), Some("abc"))
  assert_eq(file.header("content-type"), Some("text/plain"))
  assert_eq(file.header("nonesuch"), None)
  assert_eq(form.uploads().length(), 1)
  assert_eq(form.entries().length(), 3)
}

///|
/// The same body through `parse`, which is how a server reaches it: by what the
/// `Content-Type` says.
test "dispatching on the content type" {
  let ct = "multipart/form-data; boundary=----WebKitFormBoundaryabc123"
  assert_eq(
    @mime.parse(body(upload)[:], ct[:]).field("title"),
    Some("a report"),
  )
  assert_eq(
    @mime.parse(body("a=1")[:], "application/x-www-form-urlencoded").field("a"),
    Some("1"),
  )
  // The header is matched case-insensitively and may carry a charset.
  assert_eq(
    @mime.parse(
      body("a=1")[:],
      "Application/X-WWW-Form-Urlencoded; charset=UTF-8",
    ).field("a"),
    Some("1"),
  )
  // Anything else carried no form, which is an answer rather than a failure.
  assert_true(@mime.parse(body("{\"a\":1}")[:], "application/json").is_empty())
  assert_true(@mime.parse(body("x")[:], "").is_empty())
  // A multipart type with no boundary names no parts.
  assert_true(@mime.parse(body(upload)[:], "multipart/form-data").is_empty())
}

///|
/// Header parameters, quoted and bare.
test "header parameters" {
  let h = "form-data; name=\"file\"; filename=\"a b.txt\""
  assert_eq(@mime.param(h[:], "name"), Some("file"))
  assert_eq(@mime.param(h[:], "filename"), Some("a b.txt"))
  assert_eq(@mime.param(h[:], "charset"), None)
  let bare = "multipart/form-data; boundary=abc123 ; charset=utf-8"
  assert_eq(@mime.boundary(bare[:]), Some("abc123"))
  assert_eq(@mime.param(bare[:], "charset"), Some("utf-8"))
  assert_eq(@mime.boundary("text/plain"), None)
}

///|
/// A body is what somebody else sent, so both bounds are checked and the form
/// is refused whole rather than truncated.
test "limits are enforced" {
  let small : @mime.Limits = { parts: 2, part_size: 4, }
  try @mime.urlencoded(body("a=1&b=2&c=3")[:], limits=small) |> ignore catch {
    e => assert_eq(e, @mime.Parts(limit=2))
  } noraise {
    _ => fail("three fields passed a limit of two")
  }
  try @mime.urlencoded(body("a=abcdefgh")[:], limits=small) |> ignore catch {
    e => assert_eq(e, @mime.Part(limit=4, got=10))
  } noraise {
    _ => fail("a ten-byte field passed a limit of four")
  }
  // Only the count is tight here: the size bound trips first otherwise, and
  // this case is about the count.
  let few : @mime.Limits = { parts: 2, part_size: 1000, }
  try
    @mime.multipart(body(upload)[:], "----WebKitFormBoundaryabc123", limits=few)
    |> ignore
  catch {
    e => assert_eq(e, @mime.Parts(limit=2))
  } noraise {
    _ => fail("four parts passed a limit of two")
  }
  // Within the bounds, nothing is refused.
  let roomy : @mime.Limits = { parts: 10, part_size: 100, }
  assert_eq(
    @mime.urlencoded(body("a=1&b=2&c=3")[:], limits=roomy).entries().length(),
    3,
  )
  assert_eq(@mime.limits.parts, 1000)
}

///|
/// A malformed body stops where it stops rather than inventing a structure for
/// the rest.
test "a malformed multipart body" {
  // No closing delimiter, and no blank line ending the headers.
  let broken = "------b\r\nContent-Disposition: form-data; name=\"a\"\r\n"
  assert_true(@mime.multipart(body(broken)[:], "----b").is_empty())
  // A boundary that is not in the body at all.
  assert_true(@mime.multipart(body(upload)[:], "----nothing").is_empty())
  // An empty body.
  assert_true(@mime.multipart(body("")[:], "----b").is_empty())
  // A part with no name still parses, under the empty name.
  let unnamed = "------b\r\nContent-Disposition: form-data\r\n\r\nvalue\r\n------b--\r\n"
  assert_eq(@mime.multipart(body(unnamed)[:], "----b").field(""), Some("value"))
}

///|
/// Percent decoding on its own, since a URL path needs it too and `+` is a
/// space only in a form body.
test "percent decoding" {
  assert_eq(@mime.percent_decode(b"a%20b"[:]), b"a b")
  assert_eq(@mime.percent_decode(b"a+b"[:]), b"a+b")
  assert_eq(@mime.percent_decode(b"%E9%AA%87"[:]), b"\xE9\xAA\x87")
  assert_eq(@mime.percent_decode(b"100%"[:]), b"100%")
  assert_eq(@mime.percent_decode(b"%"[:]), b"%")
  assert_eq(@mime.percent_decode(b"%zz"[:]), b"%zz")
  assert_eq(@mime.percent_decode(b""[:]), b"")
}

///|
/// The two ways of naming a bound are the same bound.
///
/// There is no third way here: a bound belongs to an endpoint rather than to a
/// request, so there are no per-call mirrors of these two fields and nothing
/// can be given twice.
test "the two forms agree" {
  let built = @mime.Limits::new(parts=2, part_size=4)
  assert_eq(@mime.Limits::new(parts=2), { ..@mime.limits, parts: 2, })
  assert_eq(built, { parts: 2, part_size: 4, })
  // Naming none of them is the preset itself.
  assert_eq(@mime.Limits::new(), @mime.limits)
  // And naming one leaves the other where it was.
  assert_eq(@mime.Limits::new(parts=8).part_size, @mime.limits.part_size)
  assert_eq(@mime.Limits::new(part_size=8).parts, @mime.limits.parts)
}

///|
/// The defaults are the ones the mainstream uses: Starlette's `max_files` and
/// `max_fields` are a thousand, and python-multipart holds a part of up to a
/// megabyte in memory.
test "the preset is what other frameworks default to" {
  assert_eq(@mime.limits.parts, 1000)
  assert_eq(@mime.limits.part_size, 1 << 20)
}

///|
/// A body that stops making sense leaves the reader a choice: return the parts
/// read so far, or say so. Silence is the default because a truncated upload is
/// ordinary on a dropped connection; `strict` is for the caller who would rather
/// be told.
test "strict decides what happens to a body that stops making sense" {
  let broken = "------b\r\nContent-Disposition: form-data; name=\"a\"\r\n"
  // The default keeps what it read, which here is nothing.
  assert_true(@mime.multipart(body(broken)[:], "----b").is_empty())
  // Asked to be strict, it says where it gave up.
  try @mime.multipart(body(broken)[:], "----b", strict=true) |> ignore catch {
    e => assert_eq(e, @mime.Malformed(at=9))
  } noraise {
    _ => fail("a truncated multipart body passed in strict mode")
  }
  // A whole body is read the same either way.
  let whole = @mime.multipart(body(upload)[:], "----WebKitFormBoundaryabc123")
  let strictly = @mime.multipart(
    body(upload)[:],
    "----WebKitFormBoundaryabc123",
    strict=true,
  )
  assert_eq(whole.entries().length(), strictly.entries().length())
  assert_eq(whole.uploads().length(), strictly.uploads().length())
}

///|
/// "This request carried no form" is an answer, not a failure — until the caller
/// says it would rather hear about it.
test "strict decides what a body that is not a form means" {
  let json = body("{\"a\":1}")
  assert_true(@mime.parse(json[:], "application/json").is_empty())
  try @mime.parse(json[:], "application/json", strict=true) |> ignore catch {
    e => assert_eq(e, @mime.NotAForm(content_type="application/json"))
  } noraise {
    _ => fail("a JSON body passed as a form in strict mode")
  }
  // A multipart type with no boundary parameter is not a form either: there is
  // nothing to split it on.
  try
    @mime.parse(body(upload)[:], "multipart/form-data", strict=true) |> ignore
  catch {
    e => assert_eq(e, @mime.NotAForm(content_type="multipart/form-data"))
  } noraise {
    _ => fail("multipart with no boundary passed in strict mode")
  }
  assert_true(@mime.parse(body(upload)[:], "multipart/form-data").is_empty())
  // A real form is unaffected by the flag.
  assert_eq(
    @mime.parse(
      body("a=1")[:],
      "application/x-www-form-urlencoded",
      strict=true,
    ).field("a"),
    Some("1"),
  )
}

///|
/// The bound reaches the dispatching entry point too, not only the two it
/// dispatches to.
test "the bound reaches parse" {
  let small = @mime.Limits::new(parts=2)
  try
    @mime.parse(
      body("a=1&b=2&c=3")[:],
      "application/x-www-form-urlencoded",
      limits=small,
    )
    |> ignore
  catch {
    e => assert_eq(e, @mime.Parts(limit=2))
  } noraise {
    _ => fail("three fields passed a limit of two through parse")
  }
}
