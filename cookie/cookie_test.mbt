// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The examples are RFC 6265's own (§3.1, §4.1.1, §5.4) plus the headers browsers
// and their servers actually exchange, which is where a reader that trims too much
// or too little shows itself.

///|
/// The moment `Expires` is written from in the tests below.
fn expiry() -> @moondate.Moment raise {
  @moondate.Moment::Zoned(
    date=@moondate.Date::new(2026, 11, 3),
    time=@moondate.Time::new(9, 5, second=1),
    zone=Utc,
  )
}

///|
test "a cookie by name carries the defaults a server wants" {
  let cookie = @cookie.Cookie::new("id", "42")
  assert_eq(cookie.encode(), "id=42; Path=/; SameSite=Lax")
  // And each default is a knob: passing None leaves the attribute out.
  assert_eq(
    @cookie.Cookie::new("id", "42", path=None, same_site=None).encode(),
    "id=42",
  )
}

///|
test "every attribute is written in the order RFC 6265 §4.1.1 prints them" {
  let cookie = @cookie.Cookie::new(
    "session",
    "abc123",
    expires=expiry(),
    max_age=3600,
    domain="example.com",
    path=Some("/app"),
    secure=true,
    http_only=true,
    same_site=Some(Strict),
  )
  assert_eq(
    cookie.encode(),
    "session=abc123; Expires=Tue, 03 Nov 2026 09:05:01 GMT; Max-Age=3600; Domain=example.com; Path=/app; Secure; HttpOnly; SameSite=Strict",
  )
}

///|
test "a Set-Cookie reads back as the cookie that wrote it" {
  let cookie = @cookie.Cookie::new(
    "session",
    "abc123",
    expires=expiry(),
    max_age=3600,
    domain="example.com",
    path=Some("/app"),
    secure=true,
    http_only=true,
    same_site=Some(Unrestricted),
  )
  assert_eq(@cookie.Cookie::decode(cookie.encode()[:]), Some(cookie))
}

///|
test "the Set-Cookie headers servers really send" {
  // A session cookie with the two flags, as a login answers with.
  let login = @cookie.Cookie::decode(
    "sid=Y3Jvd2Q; Path=/; HttpOnly; Secure; SameSite=Lax"[:],
  ).unwrap()
  assert_eq(login.name, "sid")
  assert_eq(login.value, "Y3Jvd2Q")
  assert_eq(login.path, Some("/"))
  assert_eq(login.http_only, true)
  assert_eq(login.secure, true)
  assert_eq(login.same_site, Some(Lax))
  assert_eq(login.expires, None)
  // A dated one, with the leading dot §5.2.3 says to drop and an attribute name
  // in whatever case the server felt like.
  let tracker = @cookie.Cookie::decode(
    "id=a3fWa; expires=Tue, 03 Nov 2026 09:05:01 GMT; Domain=.example.com; max-age=60"[:],
  ).unwrap()
  assert_eq(tracker.expires, Some(expiry()))
  assert_eq(tracker.domain, Some("example.com"))
  assert_eq(tracker.max_age, Some(60))
}

///|
test "what §5.2 says to ignore is ignored, not refused" {
  let cookie = @cookie.Cookie::decode(
    "a=1; Expires=never; Max-Age=soon; SameSite=sideways; Version=1; Priority=High"[:],
  ).unwrap()
  assert_eq(cookie.name, "a")
  assert_eq(cookie.value, "1")
  // Each unreadable attribute is left out; the cookie itself survives.
  assert_eq(cookie.expires, None)
  assert_eq(cookie.max_age, None)
  assert_eq(cookie.same_site, None)
  // A field with no cookie in it at all is the one case that answers None.
  assert_eq(@cookie.Cookie::decode(""[:]), None)
  assert_eq(@cookie.Cookie::decode("Secure; HttpOnly"[:]), None)
}

///|
test "a value that would have opened a header of its own cannot" {
  let cookie = @cookie.Cookie::new("sid", "a\r\nSet-Cookie: admin=1")
  assert_eq(cookie.encode(), "sid=aSet-Cookie:admin=1; Path=/; SameSite=Lax")
  // The separators the format reserves go the same way.
  assert_eq(
    @cookie.Cookie::new("a;b", "c,d\"e\\f").encode(),
    "ab=cdef; Path=/; SameSite=Lax",
  )
}

///|
test "the Cookie header is pairs and nothing else" {
  assert_eq(@cookie.decode("a=1; b=2; c=3"[:]), [
    ("a", "1"),
    ("b", "2"),
    ("c", "3"),
  ])
  // Spaces around a name or a value are the separators', not either's.
  assert_eq(@cookie.decode("  a = 1 ;b=2"[:]), [("a", "1"), ("b", "2")])
  // A piece with no `=` is not a cookie.
  assert_eq(@cookie.decode("a=1; broken; b=2"[:]), [("a", "1"), ("b", "2")])
  assert_eq(@cookie.decode(""[:]), [])
  assert_eq(@cookie.encode([("a", "1"), ("b", "2")][:]), "a=1; b=2")
}

///|
test "a cookie is looked up by name, the first of a repeat winning" {
  let header = "theme=dark; sid=abc; theme=light"
  assert_eq(@cookie.get(header[:], "sid"[:]), Some("abc"))
  assert_eq(@cookie.get(header[:], "theme"[:]), Some("dark"))
  assert_eq(@cookie.get(header[:], "missing"[:]), None)
  assert_eq(@cookie.get(""[:], "sid"[:]), None)
}

///|
test "SameSite goes to the wire and back, in whatever case it comes" {
  for value in [@cookie.SameSite::Strict, Lax, Unrestricted] {
    assert_eq(@cookie.SameSite::of(value.code()[:]), Some(value))
  }
  assert_eq(@cookie.SameSite::of("none"[:]), Some(Unrestricted))
  assert_eq(@cookie.SameSite::of("LAX"[:]), Some(Lax))
  assert_eq(@cookie.SameSite::of("sideways"[:]), None)
  // `None` on the wire is not the empty option.
  assert_eq(@cookie.SameSite::Unrestricted.code(), "None")
}

///|
test "the deletion a server writes is readable as one" {
  let gone = @cookie.Cookie::new(
    "sid",
    "",
    expires=@moondate.Moment::of_epoch(0L),
    max_age=0,
  )
  assert_eq(
    gone.encode(),
    "sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; SameSite=Lax",
  )
}

///|
test "panic a cookie cannot expire at a time with no date" {
  let clock = @cookie.Cookie::new(
    "sid",
    "1",
    expires=@moondate.Moment::Clock(time=@moondate.Time::new(1, 0)),
  )
  clock.encode() |> ignore
}
