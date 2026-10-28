// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9111 states rules rather than printing vectors, so the tests follow the
// sections one statement at a time: §5.2's directives read and written, §4.2.1's
// freshness lifetime in its order, §4.2.2's guess, §4.2.3's age arithmetic,
// §3's list of reasons not to store, and §4's list of reasons not to reuse.

///|
fn at(text : String) -> @moondate.Moment raise @moondate.Refused {
  @moondate.http(text[:])
}

///|
/// A time this many seconds after the same fixed instant, so that arithmetic in a
/// test reads as arithmetic.
fn later(base : @moondate.Moment, seconds : Int32) -> @moondate.Moment {
  base.plus(@moondate.Span::new(seconds=seconds.to_int64()))
}

///|
/// The instant every test counts from: the one RFC 9110 §5.6.7 prints.
fn epoch() -> @moondate.Moment raise @moondate.Refused {
  at("Sun, 06 Nov 1994 08:49:37 GMT")
}

///|
/// A stored 200 whose fields are the ones given, received at `epoch()`.
fn stored(
  headers : Array[(String, String)],
  request? : Array[(String, String)],
) -> @cache.Entry raise @moondate.Refused {
  let now = epoch()
  @cache.Entry::read(
    status=200,
    headers~,
    request=match request {
      Some(headers) => headers
      None => []
    },
    sent=now,
    received=now,
  )
}

///|
test "the directives §5.2 defines are read on either side" {
  let both = @cache.Control::decode(
    "max-age=60, s-maxage=120, max-stale=30, min-fresh=5, no-transform",
  )
  assert_eq(both.max_age, Some(60))
  assert_eq(both.s_maxage, Some(120))
  assert_eq(both.max_stale, Some(@cache.Stale::Within(30)))
  assert_eq(both.min_fresh, Some(5))
  assert_true(both.no_transform)
  // `max-stale` with no argument accepts any age at all, which is a different
  // thing from accepting thirty seconds of it.
  assert_eq(
    @cache.Control::decode("max-stale").max_stale,
    Some(@cache.Stale::Any),
  )
  let response = @cache.Control::decode(
    "public, private, no-cache, no-store, must-revalidate, proxy-revalidate, must-understand, immutable",
  )
  assert_true(response.public)
  assert_true(response.private_)
  assert_true(response.no_cache)
  assert_true(response.no_store)
  assert_true(response.must_revalidate)
  assert_true(response.proxy_revalidate)
  assert_true(response.must_understand)
  assert_true(response.immutable)
  // The two extensions RFC 5861 adds, which the registry carries.
  let stale = @cache.Control::decode(
    "stale-while-revalidate=10, stale-if-error=20",
  )
  assert_eq(stale.stale_while_revalidate, Some(10))
  assert_eq(stale.stale_if_error, Some(20))
}

///|
test "a directive's argument may be a token or a quoted string" {
  // §5.2 has a recipient accept either form, and a qualified `no-cache` names
  // fields, which is a quoted list.
  let quoted = @cache.Control::decode("no-cache=\"Set-Cookie, X-Trace\"")
  assert_true(quoted.no_cache)
  assert_eq(quoted.no_cache_fields, ["set-cookie", "x-trace"])
  let bare = @cache.Control::decode("no-cache")
  assert_true(bare.no_cache)
  assert_eq(bare.no_cache_fields.length(), 0)
  assert_eq(@cache.Control::decode("private=\"X-User\"").private_fields, [
    "x-user",
  ])
}

///|
test "an unknown directive is kept, and a broken one is not read as a default" {
  let unknown = @cache.Control::decode("community=\"UCI\", max-age=5")
  assert_eq(unknown.extensions.length(), 1)
  assert_eq(unknown.extensions[0].0, "community")
  assert_eq(unknown.max_age, Some(5))
  // §4.2.1: invalid freshness information leaves the response with none, which a
  // decision then treats as stale.
  assert_eq(@cache.Control::decode("max-age=abc").max_age, None)
  assert_eq(@cache.Control::decode("max-age=-5").max_age, None)
  assert_eq(@cache.Control::decode("max-age=").max_age, None)
}

///|
test "a repeated directive is read from its first occurrence" {
  // §4.2.1 allows either the first occurrence or calling the response stale.
  assert_eq(
    @cache.Control::decode("max-age=10, max-age=1000").max_age,
    Some(10),
  )
  // Two field lines are one field value (§5.3).
  assert_eq(
    @cache.Control::of([
      ("Cache-Control", "max-age=10"),
      ("cache-control", "no-store"),
    ]).max_age,
    Some(10),
  )
  assert_true(
    @cache.Control::of([
      ("Cache-Control", "max-age=10"),
      ("cache-control", "no-store"),
    ]).no_store,
  )
}

///|
test "the directives are written the way they were read" {
  for
    value in [
      "max-age=60", "max-age=60, s-maxage=120", "no-cache, no-store, public", "no-cache=\"set-cookie\"",
      "min-fresh=5, max-stale=30", "private=\"x-user\"", "stale-while-revalidate=10",
    ] {
    let terms = @cache.Control::decode(value)
    assert_eq(terms.encode(), value)
    assert_eq(@cache.Control::decode(terms.encode()[:]), terms)
  }
}

///|
test "the freshness lifetime follows §4.2.1's order" {
  let when = epoch()
  let entry = stored([
    ("Cache-Control", "max-age=60, s-maxage=120"),
    ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
    ("Expires", "Sun, 06 Nov 1994 08:59:37 GMT"),
  ])
  // A shared cache takes s-maxage over max-age, and both over Expires.
  assert_eq(entry.lifetime(shared=true), Some(120))
  assert_eq(entry.lifetime(), Some(60))
  // Without the directives, Expires minus Date is the lifetime.
  let expires = stored([
    ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
    ("Expires", "Sun, 06 Nov 1994 08:59:37 GMT"),
  ])
  assert_eq(expires.lifetime(), Some(600))
  // An Expires in the past is a lifetime that is already over, not an absence.
  let past = stored([
    ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
    ("Expires", "Sun, 06 Nov 1994 08:00:00 GMT"),
  ])
  assert_eq(past.lifetime(), Some(-2977))
  assert_false(past.fresh(now=when))
  // Nothing said at all leaves the lifetime unstated.
  assert_eq(stored([]).lifetime(), None)
}

///|
test "a heuristic lifetime is a tenth of the age of the representation" {
  // Forty seconds old when it arrived, so four seconds of freshness — and half of
  // it under a fraction a caller picks.
  let entry = stored([
    ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
    ("Last-Modified", "Sun, 06 Nov 1994 08:48:57 GMT"),
  ])
  assert_eq(entry.heuristic(), Some(4))
  assert_eq(entry.heuristic(fraction=50), Some(20))
  // §4.2.2 forbids guessing over an explicit time.
  let explicit = stored([
    ("Cache-Control", "max-age=600"),
    ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
    ("Last-Modified", "Sun, 06 Nov 1994 08:48:57 GMT"),
  ])
  assert_eq(explicit.heuristic(), None)
  assert_eq(explicit.fresh_for(), Some(600))
  // And only for a status the section calls heuristically cacheable, unless the
  // origin said `public`.
  let redirect = @cache.Entry::read(
    status=302,
    headers=[
      ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
      ("Last-Modified", "Sun, 06 Nov 1994 08:48:57 GMT"),
    ],
    request=[],
    sent=epoch(),
    received=epoch(),
  )
  assert_eq(redirect.heuristic(), None)
  let marked = @cache.Entry::read(
    status=302,
    headers=[
      ("Cache-Control", "public"),
      ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
      ("Last-Modified", "Sun, 06 Nov 1994 08:48:57 GMT"),
    ],
    request=[],
    sent=epoch(),
    received=epoch(),
  )
  assert_eq(marked.heuristic(), Some(4))
}

///|
test "the age of a response is §4.2.3's sum of everything it has lived through" {
  let request = epoch()
  // Sent at epoch, answered ten seconds later: the response spent ten seconds in
  // flight, which is part of its age.
  let entry = @cache.Entry::read(
    status=200,
    headers=[("Date", "Sun, 06 Nov 1994 08:49:37 GMT")],
    request=[],
    sent=request,
    received=later(request, 10),
  )
  assert_eq(entry.current_age(now=later(request, 10)), 10)
  // Ten more seconds sitting in the store.
  assert_eq(entry.current_age(now=later(request, 20)), 20)
  // An upstream cache said the response was already 30 seconds old, and the
  // clock here is ahead by ten: both count.
  let aged = @cache.Entry::read(
    status=200,
    headers=[("Date", "Sun, 06 Nov 1994 08:49:37 GMT"), ("Age", "30")],
    request=[],
    sent=request,
    received=later(request, 10),
  )
  assert_eq(aged.current_age(now=later(request, 10)), 40)
  // A Date in the future is clock skew, not a negative age.
  let skewed = @cache.Entry::read(
    status=200,
    headers=[("Date", "Sun, 06 Nov 1994 08:59:37 GMT")],
    request=[],
    sent=request,
    received=request,
  )
  assert_eq(skewed.current_age(now=request), 0)
  // The field a cache sends says what the age is now.
  assert_eq(entry.aged(now=later(request, 20)), ("age", "20"))
}

///|
test "a response is stored only when §3's list allows it" {
  let get = @method.Method::Get
  let post = @method.Method::Post
  let nothing = @cache.control
  // A 200 that says nothing is heuristically cacheable, so it may be kept.
  assert_true(stored([]).storable(verb=get, request=nothing))
  // A POST response is not something a response cache here understands.
  assert_false(stored([]).storable(verb=post, request=nothing))
  // `no-store` stops it, on either side.
  assert_false(
    stored([("Cache-Control", "no-store")]).storable(verb=get, request=nothing),
  )
  assert_false(
    stored([("Cache-Control", "max-age=60")]).storable(
      verb=get,
      request=@cache.Control::decode("no-store"),
    ),
  )
  // `must-understand` with `no-store`: a cache that knows the status ignores the
  // `no-store` (§5.2.2.3), and one that does not obeys it.
  let guarded = stored([("Cache-Control", "must-understand, no-store")])
  assert_true(guarded.storable(verb=get, request=nothing, understood=true))
  assert_false(guarded.storable(verb=get, request=nothing, understood=false))
  // A 302 says nothing and is not heuristically cacheable: not stored unless the
  // origin says something.
  let redirect = @cache.Entry::read(
    status=302,
    headers=[],
    request=[],
    sent=epoch(),
    received=epoch(),
  )
  assert_false(redirect.storable(verb=get, request=nothing))
  let marked = @cache.Entry::read(
    status=302,
    headers=[("Cache-Control", "public")],
    request=[],
    sent=epoch(),
    received=epoch(),
  )
  assert_true(marked.storable(verb=get, request=nothing))
}

///|
test "a shared cache keeps less than a private one, and needs permission for a credential" {
  let get = @method.Method::Get
  let nothing = @cache.control
  let private = stored([("Cache-Control", "private, max-age=60")])
  assert_true(private.storable(verb=get, request=nothing))
  assert_false(private.storable(verb=get, request=nothing, shared=true))
  // A qualified `private` lets a shared cache keep the rest of the response, so
  // the decision is yes with fields to strip.
  let qualified = stored([
    ("Cache-Control", "private=\"set-cookie\", max-age=60"),
  ])
  assert_true(qualified.storable(verb=get, request=nothing, shared=true))
  // §3.5: a request with credentials is not stuck in a shared cache unless the
  // response says so.
  let plain = stored([("Cache-Control", "max-age=60")])
  assert_false(
    plain.storable(verb=get, request=nothing, shared=true, authorized=true),
  )
  for allowed in ["public", "s-maxage=60", "must-revalidate"] {
    let permitted = stored([("Cache-Control", "max-age=60, " + allowed)])
    assert_true(
      permitted.storable(
        verb=get,
        request=nothing,
        shared=true,
        authorized=true,
      ),
    )
  }
}

///|
test "reuse follows §4's list, in the order it gives" {
  let now = epoch()
  let nothing = @cache.control
  let fresh = stored([("Cache-Control", "max-age=60")])
  assert_eq(fresh.verdict(request=nothing, presented=[], now~), @cache.Serve)
  // A second later than the lifetime: stale, and with no validator there is
  // nothing to ask about, so the response cannot answer.
  assert_eq(
    fresh.verdict(request=nothing, presented=[], now=later(now, 61)),
    @cache.Miss,
  )
  // With a validator, the same stale response is worth validating.
  let validated = stored([("Cache-Control", "max-age=60"), ("ETag", "\"v1\"")])
  assert_eq(
    validated.verdict(request=nothing, presented=[], now=later(now, 61)),
    @cache.Validate,
  )
  assert_eq(
    validated.verdict(
      request=nothing,
      presented=[],
      now=later(now, 61),
      connected=false,
    ),
    @cache.Validate,
  )
  // `no-cache` means validate every time, fresh or not.
  let revalidate = stored([
    ("Cache-Control", "no-cache, max-age=60"),
    ("ETag", "\"v1\""),
  ])
  assert_eq(
    revalidate.verdict(request=nothing, presented=[], now~),
    @cache.Validate,
  )
  // A client may say it will take something stale, and how stale.
  let stale = stored([("Cache-Control", "max-age=60")])
  assert_eq(
    stale.verdict(
      request=@cache.Control::decode("max-stale"),
      presented=[],
      now=later(now, 1000),
    ),
    @cache.Serve,
  )
  assert_eq(
    stale.verdict(
      request=@cache.Control::decode("max-stale=10"),
      presented=[],
      now=later(now, 65),
    ),
    @cache.Serve,
  )
  assert_eq(
    stale.verdict(
      request=@cache.Control::decode("max-stale=10"),
      presented=[],
      now=later(now, 80),
    ),
    @cache.Miss,
  )
  // `must-revalidate` takes that away (§5.2.2.2), and with the origin
  // unreachable too.
  let strict = stored([
    ("Cache-Control", "max-age=60, must-revalidate"),
    ("ETag", "\"v1\""),
  ])
  assert_eq(
    strict.verdict(
      request=@cache.Control::decode("max-stale"),
      presented=[],
      now=later(now, 100),
    ),
    @cache.Validate,
  )
  assert_eq(
    strict.verdict(
      request=nothing,
      presented=[],
      now=later(now, 100),
      connected=false,
    ),
    @cache.Validate,
  )
  // A client that wants at least this much freshness gets a validation when the
  // response is fresh but not fresh enough.
  assert_eq(
    fresh.verdict(
      request=@cache.Control::decode("min-fresh=120"),
      presented=[],
      now~,
    ),
    @cache.Validate,
  )
  // And one that puts a ceiling on the age it will take.
  assert_eq(
    fresh.verdict(
      request=@cache.Control::decode("max-age=5"),
      presented=[],
      now=later(now, 10),
    ),
    @cache.Validate,
  )
}

///|
test "a response is only reused for a request that matches what it was selected by" {
  let now = epoch()
  let nothing = @cache.control
  let entry = stored(
    [("Cache-Control", "max-age=60"), ("Vary", "Accept-Encoding, X-Tenant")],
    request=[("Accept-Encoding", "gzip"), ("X-Tenant", "a")],
  )
  assert_eq(entry.vary, ["accept-encoding", "x-tenant"])
  let same = [("accept-encoding", "gzip"), ("X-Tenant", "a")]
  assert_eq(entry.verdict(request=nothing, presented=same, now~), @cache.Serve)
  // A different value for a field the response varied on is a different
  // representation, which this stored one cannot answer.
  let other = [("accept-encoding", "br"), ("X-Tenant", "a")]
  assert_eq(entry.verdict(request=nothing, presented=other, now~), @cache.Miss)
  // A field the response varied on but the request did not send is the empty
  // value, which is not what was stored.
  assert_eq(
    entry.verdict(request=nothing, presented=[("x-tenant", "a")], now~),
    @cache.Miss,
  )
  // `*` never matches: §4.1 has the response treated as not reusable.
  let anything = stored([("Cache-Control", "max-age=60"), ("Vary", "*")], request=[
    ("X-Tenant", "a"),
  ])
  assert_eq(
    anything.verdict(request=nothing, presented=[("X-Tenant", "a")], now~),
    @cache.Miss,
  )
}

///|
test "the conditional request a cache sends carries both validators" {
  // §4.3.1: the entity tag in If-None-Match, and the timestamp in
  // If-Modified-Since, even where the tag would have been enough.
  let entry = stored([
    ("ETag", "W/\"v1\""),
    ("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT"),
  ])
  assert_eq(entry.conditional(), [
    ("if-none-match", "W/\"v1\""),
    ("if-modified-since", "Sun, 06 Nov 1994 08:49:37 GMT"),
  ])
  // A response with neither asks for nothing, and a cache that gets nothing back
  // has to fetch.
  assert_eq(stored([]).conditional().length(), 0)
}

///|
test "a 304 freshens what is stored without replacing the body" {
  let now = epoch()
  let entry = stored([
    ("Cache-Control", "max-age=60"),
    ("ETag", "\"v1\""),
    ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
  ])
  let stale = later(now, 120)
  let refreshed = entry.freshened(
    headers=[
      ("Cache-Control", "max-age=600"),
      ("Date", "Sun, 06 Nov 1994 08:51:37 GMT"),
    ],
    received=stale,
  )
  assert_eq(refreshed.control.max_age, Some(600))
  assert_eq(refreshed.etag, Some(@conditional.Tag::new("v1")))
  // The clock starts again, so what was stale is fresh.
  assert_true(refreshed.fresh(now=stale))
  assert_eq(refreshed.current_age(now=stale), 0)
}
