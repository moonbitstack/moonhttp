// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Framing an event stream, and reading a form back out of a request body.
///
///     moon run examples/tour
#coverage.skip
fn main raise {
  // Each frame is one chunk. A stream sent as one body is not a stream.
  let events = [
    @sse.Event::new(data="{\"seq\":1}", kind="tick", id="1"),
    @sse.Event::of("two\nlines"),
    @sse.Event::ping(comment="still here"),
  ]
  let stream = StringBuilder()
  for event in events {
    stream.write_string(event.encode())
  }
  println("content-type -> \{@sse.media_type}")
  println("--- the stream ---")
  println(stream.to_string())
  println("--- read back ---")
  for event in @sse.decode(stream.to_string()[:]) {
    println("  \{event.kind.unwrap_or("message")}: \{event.data.escape()}")
  }

  // A form, as a browser posts one.
  let posted = "name=Ada+Lovelace&born=1815&field=%E9%AA%87%E5%85%94"
  let form = @mime.parse(
    @utf8.encode(posted[:])[:],
    "application/x-www-form-urlencoded",
  )
  println("name         -> \{form.field("name").unwrap_or("")}")
  println("field        -> \{form.field("field").unwrap_or("")}")

  // And a file upload.
  let body = "------b\r\n" +
    "Content-Disposition: form-data; name=\"notes\"; filename=\"a.txt\"\r\n" +
    "Content-Type: text/plain\r\n\r\nhello\r\n------b--\r\n"
  let upload = @mime.parse(
    @utf8.encode(body[:])[:],
    "multipart/form-data; boundary=----b",
  )
  match upload.file("notes") {
    Some(file) =>
      println(
        "upload       -> \{file.filename}, \{file.size()} bytes, \{file.content_type}",
      )
    None => println("upload       -> none, which would be the bug")
  }
}
