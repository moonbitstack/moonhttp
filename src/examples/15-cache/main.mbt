// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A stored response and what may be done with it, then a redirect and what it
/// costs — the two decisions a client makes before it sends anything.
///
///     moon run src/examples/15-cache
#coverage.skip
fn main raise {
  let sent = @moondate.http("Sun, 06 Nov 1994 08:49:37 GMT")
  let received = sent
  let request = [("Accept-Encoding", "gzip")]
  let response = [
    ("Cache-Control", "max-age=60"),
    ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
    ("ETag", "\"v1\""),
    ("Vary", "Accept-Encoding"),
    ("Content-Type", "text/plain"),
  ]
  let entry = @cache.Entry::read(
    status=200,
    headers=response,
    request~,
    sent~,
    received~,
  )
  println("lifetime   -> \{entry.lifetime().unwrap_or(-1)}s")
  println(
    "fresh at   -> \{entry.fresh(now=at(sent, 30))}, \{entry.fresh(now=at(sent, 90))}",
  )
  println("age at 90s -> \{entry.current_age(now=at(sent, 90))}s")

  let nothing = @cache.control
  for seconds in [0, 30, 90] {
    let now = at(sent, seconds)
    println(
      "verdict at \{seconds}s -> \{name(entry.verdict(request=nothing, presented=request, now~))}",
    )
  }
  // A client that says it will take something stale gets it.
  println(
    "max-stale  -> \{name(entry.verdict(request=@cache.Control::decode("max-stale=60"), presented=request, now=at(sent, 90)))}",
  )
  // And what a cache sends when it decides to ask instead.
  for (name, value) in entry.conditional() {
    println("conditional -> " + name + ": " + value)
  }

  // A redirect: where, with which method, and which credentials stop here.
  let from = @moonurl.Url::decode("https://example.com/a") catch { _ => return }
  let step = @client.follow(
    status=302,
    location="https://other.example/b",
    from~,
    verb=@method.Method::Post,
    visited=[from][:],
    body=true,
  ) catch {
    e => {
      println("refused    -> " + e.to_string())
      return
    }
  }
  println("redirect   -> \{step.verb.name()} \{step.url.encode()}")
  println("body       -> resent: \{step.body}")
  println("strip      -> " + join(step.strip))

  // An alternative service, as a server advertises one.
  match @client.altsvc("h3=\":443\"; ma=3600"[:]) {
    Some(alternatives) =>
      for alternative in alternatives {
        println("alt-svc    -> " + alternative.encode())
      }
    None => println("alt-svc    -> clear")
  }
}

///|
fn join(items : Array[String]) -> String {
  let out = StringBuilder()
  for i in 0..<items.length() {
    if i > 0 {
      out.write_string(", ")
    }
    out.write_string(items[i])
  }
  out.to_string()
}

///|
/// A moment this many seconds after another.
fn at(base : @moondate.Moment, seconds : Int32) -> @moondate.Moment {
  base.plus(@moondate.Span::new(seconds=seconds.to_int64()))
}

///|
fn name(verdict : @cache.Verdict) -> String {
  match verdict {
    @cache.Serve => "serve"
    @cache.Validate => "validate"
    @cache.Miss => "miss"
  }
}
