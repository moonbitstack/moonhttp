///|
/// Mapping HTTP messages onto HTTP/3 request/response streams (RFC 9114 §4.1):
/// a request becomes a HEADERS frame (a QPACK field section of the pseudo- and
/// ordinary headers) plus DATA, and decodes back; a typed request parses out;
/// and `http3_serve` drives a request through a handler that answers 200.
///
///     moon run examples/31-http3-message --target native
#coverage.skip
fn main {
  run() catch {
    e => println("http3 msg error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let wire = @http3.request(
    "POST",
    "https",
    "api.example.com",
    "/submit",
    [@header.Header::of("content-type", "application/json")],
    b"{\"name\":\"mooncat\"}",
  )
  let (headers, body) = @http3.read_message(wire)
  println("request: \{headers.length()} header fields, body = \{ascii(body)}")
  for h in headers {
    println("  \{h.ascii().0}: \{h.ascii().1}")
  }
  match @http3.read_request(wire) {
    Some(req) =>
      println("parsed: \{req.meth} \{req.scheme}://\{req.authority}\{req.path}")
    None => println("parse failed")
  }
  let resp = @http3.response(
    "200",
    [@header.Header::of("server", "mooncat")],
    b"<h1>ok</h1>",
  )
  let (rh, rb) = @http3.read_message(resp)
  println("response: status=\{rh[0].ascii().1} body=\{ascii(rb)}")
  let served = @http3.serve(wire, _req => @http3.Response::{
    status: "200",
    headers: [@header.Header::of("x-app", "mooncat")],
    body: b"handled by mooncat",
  })
  let (ah, ab) = @http3.read_message(served)
  println("served: status=\{ah[0].ascii().1} body=\{ascii(ab)}")
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}
