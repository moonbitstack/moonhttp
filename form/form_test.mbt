// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
let upload : String = "------WebKitFormBoundaryabc123\r\n" +
  "Content-Disposition: form-data; name=\"title\"\r\n" +
  "\r\n" +
  "a report\r\n" +
  "------WebKitFormBoundaryabc123\r\n" +
  "Content-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\n" +
  "Content-Type: text/plain\r\n" +
  "\r\n" +
  "line one\r\n" +
  "------WebKitFormBoundaryabc123--\r\n"

///|
let multipart : String = "multipart/form-data; boundary=----WebKitFormBoundaryabc123"

///|
fn body(text : String) -> Bytes {
  @utf8.encode(text)
}

///|
test "each encoding by its content type" {
  let posted = @form.parse(body(upload)[:], multipart)
  assert_eq(posted.field("title"), Some("a report"))
  assert_eq(posted.file("file").map(f => f.filename), Some("notes.txt"))
  let plain = @form.parse(
    body("name=Ada+Lovelace&tag=a&tag=b")[:],
    "application/x-www-form-urlencoded",
  )
  assert_eq(plain.field("name"), Some("Ada Lovelace"))
  assert_eq(plain.values("tag"), ["a", "b"])
  assert_eq(plain.uploads().length(), 0)
  // The type is matched case-insensitively and may carry a charset.
  assert_eq(
    @form.parse(
      body("a=1")[:],
      "Application/X-WWW-Form-Urlencoded; charset=UTF-8",
    ).field("a"),
    Some("1"),
  )
}

///|
/// "This request carried no form" is an answer, not a failure, until the caller
/// says it would rather hear about it.
test "strict decides what a body that is not a form means" {
  let json = body("{\"a\":1}")
  assert_true(@form.parse(json[:], "application/json").is_empty())
  assert_true(@form.parse(json[:], "").is_empty())
  try @form.parse(json[:], "application/json", strict=true) |> ignore catch {
    e => assert_eq(e, @moonmime.NotAForm(content_type="application/json"))
  } noraise {
    _ => fail("a JSON body passed as a form in strict mode")
  }
  // A multipart type with no boundary is not a form either: there is nothing to
  // split it on.
  assert_true(@form.parse(body(upload)[:], "multipart/form-data").is_empty())
  try
    @form.parse(body(upload)[:], "multipart/form-data", strict=true) |> ignore
  catch {
    e => assert_eq(e, @moonmime.NotAForm(content_type="multipart/form-data"))
  } noraise {
    _ => fail("multipart with no boundary passed in strict mode")
  }
  // A real form is unaffected by the flag.
  assert_eq(
    @form.parse(
      body("a=1")[:],
      "application/x-www-form-urlencoded",
      strict=true,
    ).field("a"),
    Some("1"),
  )
}

///|
test "one bound for both encodings" {
  let small = @moonmime.Limits::new(parts=2, part_size=4)
  let urlencoded = "application/x-www-form-urlencoded"
  try
    @form.parse(body("a=1&b=2&c=3")[:], urlencoded, limits=small) |> ignore
  catch {
    e => assert_eq(e, @moonmime.Parts(limit=2))
  } noraise {
    _ => fail("three pairs passed a limit of two")
  }
  try
    @form.parse(body("a=abcdefgh")[:], urlencoded, limits=small) |> ignore
  catch {
    e => assert_eq(e, @moonmime.Part(limit=4, got=10))
  } noraise {
    _ => fail("a ten-octet pair passed a limit of four")
  }
  try @form.parse(body(upload)[:], multipart, limits=small) |> ignore catch {
    e => assert_eq(e, @moonmime.Part(limit=4, got=8))
  } noraise {
    _ => fail("an eight-octet part passed a limit of four")
  }
  let roomy = @moonmime.Limits::new(parts=10, part_size=100)
  assert_eq(
    @form.parse(body("a=1&b=2&c=3")[:], urlencoded, limits=roomy)
    .entries()
    .length(),
    3,
  )
}
