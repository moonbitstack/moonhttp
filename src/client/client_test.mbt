// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9110 §15.4 states what a redirect means rather than printing cases, so each
// test here is one of its sentences: the method rewrite of §15.4.2 and §15.4.4, the
// method that is kept by §15.4.8 and §15.4.9, and the credentials §15.4 says stop
// at the origin they were meant for. RFC 7838 §3 prints the field's grammar with
// its examples, which the Alt-Svc tests use verbatim.

///|
fn url(text : String) -> @moonurl.Url {
  @moonurl.Url::decode(text[:]) catch {
    _ => abort("not a URL: " + text)
  }
}

///|
/// The refusal a redirect raises, so a test reads as a list of cases.
fn refused(
  status : Int32,
  location : String,
  from : String,
  verb : @method.Method,
  visited? : Array[@moonurl.Url],
  body? : Bool,
  replay? : Bool,
) -> @client.Refused? {
  let chain = match visited {
    Some(chain) => chain
    None => [url(from)]
  }
  let mut out : @client.Refused? = None
  let _ = try {
    let _ = @client.follow(
      status~,
      location~,
      from=url(from),
      verb~,
      visited=chain[:],
      body?,
      replay?,
    )
  } catch {
    e => out = Some(e)
  }
  out
}

///|
test "a redirect keeps the method or rewrites it, as §15.4 says of each status" {
  let post = @method.Method::Post
  let put = @method.Method::Put
  let get = @method.Method::Get
  let head = @method.Method::Head
  let origin = "https://example.com/a/b"
  // 301 and 302 rewrite a POST to a GET, which every browser does and §15.4.2
  // allows for historical reasons.
  for status in [301, 302] {
    let step = @client.follow(
      status~,
      location="/c",
      from=url(origin),
      verb=post,
      visited=[url(origin)][:],
      body=true,
    ) catch {
      e => fail("a 301 and a 302 were not followed: " + e.to_string())
    }
    assert_eq(step.verb, get)
    assert_false(step.body)
    assert_eq(step.url.path, "/c")
    assert_eq(step.url.host, Some("example.com"))
  }
  // 303 rewrites anything but a HEAD, because it means "the answer is elsewhere".
  let see = @client.follow(
    status=303,
    location="/c",
    from=url(origin),
    verb=put,
    visited=[url(origin)][:],
    body=true,
  ) catch {
    e => fail("a 303 was not followed: " + e.to_string())
  }
  assert_eq(see.verb, get)
  assert_false(see.body)
  let quiet = @client.follow(
    status=303,
    location="/c",
    from=url(origin),
    verb=head,
    visited=[url(origin)][:],
  ) catch {
    e => fail("a 303 to a HEAD was not followed: " + e.to_string())
  }
  assert_eq(quiet.verb, head)
  // 307 and 308 keep both the method and the body, which is what they exist for.
  for status in [307, 308] {
    let step = @client.follow(
      status~,
      location="/c",
      from=url(origin),
      verb=post,
      visited=[url(origin)][:],
      body=true,
    ) catch {
      e => fail("a 307 and a 308 were not followed: " + e.to_string())
    }
    assert_eq(step.verb, post)
    assert_true(step.body)
  }
}

///|
test "a 307 whose body cannot be resent is refused rather than emptied" {
  // §15.4.8: the method and the body both stay. A caller whose body was a stream
  // says so, and gets a refusal instead of a PUT that lost its content.
  assert_true(
    refused(
      307,
      "/c",
      "https://example.com/a",
      @method.Method::Put,
      body=true,
      replay=false,
    )
    is Some(@client.Replay(_)),
  )
  // A GET has no body to replay, so the same hop is fine.
  assert_true(
    refused(
      307,
      "/c",
      "https://example.com/a",
      @method.Method::Get,
      body=false,
      replay=false,
    )
    is None,
  )
}

///|
test "a status a client does not follow is not a redirect" {
  for status in [200, 201, 300, 304, 305, 400, 500] {
    assert_true(
      refused(status, "/c", "https://example.com/a", @method.Method::Get)
      is Some(@client.NotARedirect(..)),
    )
  }
}

///|
test "a Location that is missing or unreadable is refused" {
  assert_true(
    refused(302, "", "https://example.com/a", @method.Method::Get)
    is Some(@client.Location(..)),
  )
  assert_true(
    refused(302, "http://[::1", "https://example.com/a", @method.Method::Get)
    is Some(@client.Location(..)),
  )
  // The field itself, when a response has one.
  assert_eq(
    @client.location([("Location", " /next "), ("Content-Length", "0")]),
    Some("/next"),
  )
  assert_eq(@client.location([("Content-Length", "0")]), None)
}

///|
test "a relative Location is resolved against the request, as §7.1 of RFC 9110 asks" {
  let from = "https://example.com/a/b?q=1"
  for
    (location, path, query) in [
      ("/c", "/c", None),
      ("c", "/a/c", None),
      ("../c", "/c", None),
      ("?x=2", "/a/b", Some("x=2")),
      ("//other.test/c", "/c", None),
    ] {
    let step = @client.follow(
      status=302,
      location~,
      from=url(from),
      verb=@method.Method::Get,
      visited=[url(from)][:],
    ) catch {
      e => fail("Location \{location} was not followed: " + e.to_string())
    }
    assert_eq(step.url.path, path)
    assert_eq(step.url.query, query)
  }
}

///|
test "credentials stop at the origin they were meant for" {
  let origin = "https://example.com/a"
  let get = @method.Method::Get
  // Same host, same scheme, the default port written out: still the same origin,
  // so nothing is dropped.
  let same = @client.follow(
    status=302,
    location="https://example.com:443/b",
    from=url(origin),
    verb=get,
    visited=[url(origin)][:],
  ) catch {
    e => fail("a same-origin redirect was not followed: " + e.to_string())
  }
  assert_eq(same.strip.length(), 0)
  // Another host, another scheme, another port: the credentials were for the
  // origin, and §15.4 stops them there.
  for
    location in [
      "https://other.example/b", "http://example.com/b", "https://example.com:8443/b",
      "https://sub.example.com/b",
    ] {
    let step = @client.follow(
      status=302,
      location~,
      from=url(origin),
      verb=get,
      visited=[url(origin)][:],
    ) catch {
      e => fail("a cross-origin redirect was not followed: " + e.to_string())
    }
    assert_eq(step.strip, ["authorization", "cookie", "proxy-authorization"])
  }
  // The origin comparison itself, which is what the stripping turns on.
  assert_true(
    @client.same_origin(
      url("https://Example.com/a"),
      url("https://example.com:443/b"),
    ),
  )
  assert_false(
    @client.same_origin(
      url("http://example.com/a"),
      url("https://example.com/a"),
    ),
  )
  assert_false(
    @client.same_origin(
      url("https://example.com/a"),
      url("https://example.com:8443/a"),
    ),
  )
}

///|
test "a chain that comes back to where it has been is a loop" {
  let a = url("https://example.com/a")
  let b = url("https://example.com/b")
  assert_true(
    refused(302, "/a", "https://example.com/b", @method.Method::Get, visited=[
      a, b,
    ])
    is Some(@client.Loop(..)),
  )
  // The same target written another way is the same loop.
  assert_true(
    refused(
      302,
      "https://example.com:443/a",
      "https://example.com/b",
      @method.Method::Get,
      visited=[a, b],
    )
    is Some(@client.Loop(..)),
  )
  // A new target is not.
  assert_true(
    refused(302, "/c", "https://example.com/b", @method.Method::Get, visited=[
      a, b,
    ])
    is None,
  )
}

///|
test "a chain longer than the ceiling stops there" {
  let chain : Array[@moonurl.Url] = []
  for i in 0..<@client.hops {
    chain.push(url("https://example.com/\{i}"))
  }
  assert_true(
    refused(
      302,
      "/last",
      "https://example.com/0",
      @method.Method::Get,
      visited=chain,
    )
    is Some(@client.TooMany(..)),
  )
  // One fewer hop is still a chain worth following.
  let shorter = chain[:chain.length() - 1].to_owned()
  assert_true(
    refused(
      302,
      "/last",
      "https://example.com/0",
      @method.Method::Get,
      visited=shorter,
    )
    is None,
  )
}

///|
test "the Alt-Svc examples §3 prints are read as written" {
  // Same host, another port.
  match @client.altsvc("h2=\":8000\"") {
    Some([alternative]) => {
      assert_eq(alternative.protocol, "h2")
      assert_eq(alternative.host, None)
      assert_eq(alternative.port, 8000)
      assert_eq(alternative.lifespan, @client.lifespan)
      assert_false(alternative.persist)
    }
    _ => fail("the first example of §3 did not read")
  }
  // Another host and port.
  match @client.altsvc("h2=\"new.example.org:80\"") {
    Some([alternative]) => {
      assert_eq(alternative.host, Some("new.example.org"))
      assert_eq(alternative.port, 80)
    }
    _ => fail("the second example of §3 did not read")
  }
  // Two values, in the server's order of preference.
  match @client.altsvc("h2=\"alt.example.com:8000\", h2=\":443\"") {
    Some([first, second]) => {
      assert_eq(first.host, Some("alt.example.com"))
      assert_eq(second.host, None)
      assert_eq(second.port, 443)
    }
    _ => fail("the third example of §3 did not read")
  }
  // The parameters §3.1 defines.
  match @client.altsvc("h3=\":443\"; ma=3600; persist=1") {
    Some([alternative]) => {
      assert_eq(alternative.lifespan, 3600)
      assert_true(alternative.persist)
    }
    _ => fail("an advertisement with parameters did not read")
  }
  // `persist` means one thing only (§3.1).
  match @client.altsvc("h2=\":443\"; persist=0") {
    Some([alternative]) => assert_false(alternative.persist)
    _ => fail("an advertisement with persist=0 did not read")
  }
}

///|
test "clear forgets everything, and a member that does not parse is dropped" {
  assert_eq(@client.altsvc("clear"), None)
  assert_eq(@client.altsvc(" Clear "), None)
  // A member with no authority, one with no port, and one with no protocol.
  match
    @client.altsvc(
      "h2, h2=\"alt.example.com\", =\"alt.example.com:80\", h3=\":443\"",
    ) {
    Some(alternatives) => assert_eq(alternatives.length(), 1)
    None => fail("a field with one good member was read as clear")
  }
  // An unknown parameter is ignored (§3.1), not a reason to drop the value.
  match @client.altsvc("h2=\":443\"; unknown=1") {
    Some([alternative]) => assert_eq(alternative.port, 443)
    _ => fail("an unknown parameter dropped the whole value")
  }
  // A protocol-id is percent-encoded where a token cannot hold the octet.
  match @client.altsvc("x%25y=\":443\"") {
    Some([alternative]) => assert_eq(alternative.protocol, "x%y")
    _ => fail("a percent-encoded protocol id did not read")
  }
}

///|
test "an alternative is written the way it was read" {
  for
    value in [
      "h2=\":8000\"", "h2=\"new.example.org:80\"", "h3=\":443\"; ma=3600", "h3=\":443\"; persist=1",
      "h3=\":443\"; ma=60; persist=1",
    ] {
    match @client.altsvc(value) {
      Some([alternative]) => assert_eq(alternative.encode(), value)
      _ => fail("did not read: " + value)
    }
  }
  // A host with a colon in it is an IPv6 literal and keeps its brackets.
  match @client.altsvc("h2=\"[::1]:443\"") {
    Some([alternative]) => {
      assert_eq(alternative.host, Some("::1"))
      assert_eq(alternative.encode(), "h2=\"[::1]:443\"")
    }
    _ => fail("an IPv6 alternative did not read")
  }
}

///|
test "an advertisement is fresh for its ma, and picked by protocol" {
  let issued = @moondate.http("Sun, 06 Nov 1994 08:49:37 GMT") catch {
    _ => abort("not a date")
  }
  let soon = issued.plus(@moondate.Span::new(seconds=30L))
  let later = issued.plus(@moondate.Span::new(seconds=3000L))
  let alternatives = match
    @client.altsvc("h2=\":443\"; ma=60, h3=\":443\"; ma=3600") {
    Some(list) => list
    None => abort("not a list")
  }
  // The server prefers h2, and this client speaks it.
  match
    @client.best(alternatives[:], protocols=["h3", "h2"], issued~, now=soon) {
    Some(alternative) => assert_eq(alternative.protocol, "h2")
    None => fail("a fresh alternative was not chosen")
  }
  // Fifty minutes later h2 has expired and h3 has not.
  match
    @client.best(alternatives[:], protocols=["h3", "h2"], issued~, now=later) {
    Some(alternative) => assert_eq(alternative.protocol, "h3")
    None => fail("the longer-lived alternative was not chosen")
  }
  // A client that speaks neither stays on the origin.
  assert_eq(
    @client.best(alternatives[:], protocols=["hq-29"], issued~, now=soon),
    None,
  )
}

///|
test "the authority to connect to is the alternative's, or the origin's own host" {
  let origin = url("https://example.com/a")
  match @client.altsvc("h3=\":443\"") {
    Some([alternative]) =>
      assert_eq(alternative.authority(origin~), "example.com:443")
    _ => fail("did not read")
  }
  match @client.altsvc("h3=\"alt.example.com:8443\"") {
    Some([alternative]) =>
      assert_eq(alternative.authority(origin~), "alt.example.com:8443")
    _ => fail("did not read")
  }
}
