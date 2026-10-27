// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9110 §13 states its rules rather than printing vectors, so the tests
// follow the statements: §8.8.3.2's two comparisons on the table it gives, and
// §13.2.2's six steps one at a time and then against each other, since the
// order they are weighed in is the part an implementation gets wrong.

///|
fn at(text : String) -> @moondate.Moment raise @moondate.Refused {
  @moondate.http(text[:])
}

///|
/// The example table of RFC 9110 §8.8.3.2, entry for entry.
test "the comparison table of RFC 9110 §8.8.3.2" {
  let w1 = @conditional.Tag::new("1", weak=true)
  let w2 = @conditional.Tag::new("2", weak=true)
  let s1 = @conditional.Tag::new("1")
  let s2 = @conditional.Tag::new("2")
  // W/"1" vs W/"1": weak yes, strong no.
  assert_true(w1.alike(w1))
  assert_false(w1.same(w1))
  // W/"1" vs W/"2": neither.
  assert_false(w1.alike(w2))
  assert_false(w1.same(w2))
  // W/"1" vs "1": weak yes, strong no.
  assert_true(w1.alike(s1))
  assert_false(w1.same(s1))
  // "1" vs "1": both.
  assert_true(s1.alike(s1))
  assert_true(s1.same(s1))
  // "1" vs "2": neither.
  assert_false(s1.same(s2))
}

///|
test "a field value is written and read the same way round" {
  assert_eq(@conditional.Tag::new("xyzzy").encode(), "\"xyzzy\"")
  assert_eq(@conditional.Tag::new("xyzzy", weak=true).encode(), "W/\"xyzzy\"")
  assert_eq(@conditional.Tag::new("").encode(), "\"\"")
  for
    tag in [
      @conditional.Tag::new("xyzzy"),
      @conditional.Tag::new("xyzzy", weak=true),
      @conditional.Tag::new(""),
      @conditional.Tag::new("a,b"),
    ] {
    assert_eq(@conditional.Tag::decode(tag.encode()[:]), Some(tag))
  }
  // Unquoted is not an entity-tag, however much it looks like one.
  assert_eq(@conditional.Tag::decode("xyzzy"), None)
  assert_eq(@conditional.Tag::decode("W/xyzzy"), None)
  assert_eq(@conditional.Tag::decode("\"unclosed"), None)
  assert_eq(@conditional.Tag::decode(""), None)
}

///|
/// A comma inside an opaque-tag is allowed by `etagc` (§8.8.3), so the list is
/// split outside the quotes or not at all.
test "a list of tags splits outside the quotes" {
  assert_eq(@conditional.Tags::decode("*"), Some(@conditional.Any))
  assert_eq(
    @conditional.Tags::decode("\"a\", W/\"b\""),
    Some(
      @conditional.These([
        @conditional.Tag::new("a"),
        @conditional.Tag::new("b", weak=true),
      ]),
    ),
  )
  assert_eq(
    @conditional.Tags::decode("\"a,b\""),
    Some(@conditional.These([@conditional.Tag::new("a,b")])),
  )
  assert_eq(@conditional.Tags::decode("\"a\", bare"), None)
  assert_eq(@conditional.Tags::decode(""), None)
  assert_eq(
    @conditional.These([
      @conditional.Tag::new("a"),
      @conditional.Tag::new("b", weak=true),
    ]).encode(),
    "\"a\", W/\"b\"",
  )
  assert_eq(@conditional.Any.encode(), "*")
}

///|
/// §13.1.5: the first two characters say which kind it is.
test "If-Range takes a tag or a date" {
  assert_eq(
    @conditional.Validator::decode("\"xyzzy\""),
    Some(@conditional.Marked(@conditional.Tag::new("xyzzy"))),
  )
  assert_eq(
    @conditional.Validator::decode("W/\"xyzzy\""),
    Some(@conditional.Marked(@conditional.Tag::new("xyzzy", weak=true))),
  )
  let moment = at("Sun, 06 Nov 1994 08:49:37 GMT")
  assert_eq(
    @conditional.Validator::decode("Sun, 06 Nov 1994 08:49:37 GMT"),
    Some(@conditional.Dated(moment)),
  )
  assert_eq(@conditional.Validator::decode("not a date"), None)
  assert_eq(
    @conditional.Dated(moment).encode(),
    "Sun, 06 Nov 1994 08:49:37 GMT",
  )
}

// ---------------------------------------------------------------- generating

///|
/// The two generators, and the reason each is the strength it is.
test "an entity-tag from the octets, and one from the file system" {
  let body = b"hello"
  let tag = @conditional.hash(body[:], digest=@sha2.Hasher::new())
  // `"<length>-<digest>"`, both hexadecimal, and the digest is SHA-256's own
  // vector for "hello".
  assert_eq(
    tag.text,
    "5-2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  )
  assert_false(tag.weak)
  // Hashing the content is what lets it be strong: the same octets give the
  // same tag, and one octet's difference gives another.
  assert_eq(@conditional.hash(b"hello"[:], digest=@sha2.Hasher::new()), tag)
  assert_not_eq(@conditional.hash(b"hellp"[:], digest=@sha2.Hasher::new()), tag)
  // The stat-only tag is weak, because a second is long enough for two writes.
  let stamp = @conditional.stamp(
    length=1234L,
    modified=at("Sun, 06 Nov 1994 08:49:37 GMT"),
  )
  assert_true(stamp.weak)
  assert_eq(stamp.text, "2ebc98a1-4d2")
}

// ------------------------------------------------------------------ the five

///|
test "the five fields come off the headers" {
  let ask = @conditional.Ask::read(
    [
      ("If-Match", "\"a\""),
      ("if-match", "\"b\""),
      ("If-None-Match", "*"),
      ("If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT"),
      ("If-Range", "\"a\""),
      ("Accept", "text/html"),
    ][:],
  )
  // Two lines of one list-valued field are one list (§5.3).
  assert_eq(
    ask.matching,
    Some(
      @conditional.These([
        @conditional.Tag::new("a"),
        @conditional.Tag::new("b"),
      ]),
    ),
  )
  assert_eq(ask.none_matching, Some(@conditional.Any))
  assert_eq(ask.modified_since, Some(at("Sun, 06 Nov 1994 08:49:37 GMT")))
  assert_eq(ask.unmodified_since, None)
  assert_eq(ask.ranging, Some(@conditional.Marked(@conditional.Tag::new("a"))))
  // A field that will not parse comes back absent, per §13.1.3.
  let bad = @conditional.Ask::read(
    [("If-Modified-Since", "yesterday"), ("If-Match", "bare")][:],
  )
  assert_eq(bad.modified_since, None)
  assert_eq(bad.matching, None)
  // No preconditions at all.
  assert_eq(@conditional.Ask::read([][:]), @conditional.ask)
}

// ----------------------------------------------------------------- weighing

///|
/// §13.2.2 step 1, and the `*` that asks about existence rather than identity.
test "If-Match is the strong one" {
  let ours = @conditional.Tag::new("a")
  let asking = @conditional.Ask::new(
    matching=@conditional.These([@conditional.Tag::new("a")]),
  )
  assert_eq(asking.evaluate(verb="PUT", etag=ours), @conditional.Go)
  assert_eq(
    asking.evaluate(verb="PUT", etag=@conditional.Tag::new("b")),
    @conditional.Failed,
  )
  // No current tag at all: nothing to match.
  assert_eq(asking.evaluate(verb="PUT"), @conditional.Failed)
  // A weak tag never satisfies If-Match (§8.8.3.2).
  assert_eq(
    asking.evaluate(verb="PUT", etag=@conditional.Tag::new("a", weak=true)),
    @conditional.Failed,
  )
  // `*` asks only whether something is there.
  let any = @conditional.Ask::new(matching=@conditional.Any)
  assert_eq(any.evaluate(verb="PUT", etag=ours), @conditional.Go)
  assert_eq(any.evaluate(verb="PUT", present=false), @conditional.Failed)
}

///|
/// §13.2.2 step 3, and the one place the method changes the answer.
test "If-None-Match answers 304 to a read and 412 to a write" {
  let ours = @conditional.Tag::new("a")
  let asking = @conditional.Ask::new(
    none_matching=@conditional.These([@conditional.Tag::new("a")]),
  )
  assert_eq(asking.evaluate(verb="GET", etag=ours), @conditional.Fresh)
  assert_eq(asking.evaluate(verb="HEAD", etag=ours), @conditional.Fresh)
  assert_eq(asking.evaluate(verb="PUT", etag=ours), @conditional.Failed)
  assert_eq(
    asking.evaluate(verb="GET", etag=@conditional.Tag::new("b")),
    @conditional.Go,
  )
  // Weak comparison here, unlike If-Match.
  assert_eq(
    asking.evaluate(verb="GET", etag=@conditional.Tag::new("a", weak=true)),
    @conditional.Fresh,
  )
  // `*` the other way round: fails when something is there.
  let any = @conditional.Ask::new(none_matching=@conditional.Any)
  assert_eq(any.evaluate(verb="PUT", etag=ours), @conditional.Failed)
  assert_eq(any.evaluate(verb="PUT", present=false), @conditional.Go)
}

///|
/// §13.2.2 steps 2 and 4, on the dates.
test "the two date conditions" {
  let then = at("Sun, 06 Nov 1994 08:49:37 GMT")
  let later = at("Mon, 07 Nov 1994 08:49:37 GMT")
  let fresh = @conditional.Ask::new(modified_since=then)
  // Unchanged since: the copy is still good.
  assert_eq(fresh.evaluate(verb="GET", modified=then), @conditional.Fresh)
  assert_eq(fresh.evaluate(verb="GET", modified=later), @conditional.Go)
  // The field is for reads only (§13.1.3).
  assert_eq(fresh.evaluate(verb="POST", modified=then), @conditional.Go)
  // With no last-modified date the condition cannot be made false.
  assert_eq(fresh.evaluate(verb="GET"), @conditional.Go)
  let guarded = @conditional.Ask::new(unmodified_since=then)
  assert_eq(guarded.evaluate(verb="PUT", modified=then), @conditional.Go)
  assert_eq(guarded.evaluate(verb="PUT", modified=later), @conditional.Failed)
  assert_eq(guarded.evaluate(verb="PUT"), @conditional.Failed)
}

///|
/// The order itself: §13.2.2 says which field wins when two are sent.
test "the order the fields are weighed in" {
  let ours = @conditional.Tag::new("a")
  let then = at("Sun, 06 Nov 1994 08:49:37 GMT")
  let later = at("Mon, 07 Nov 1994 08:49:37 GMT")
  // Step 2 only runs when If-Match is absent, so a satisfied If-Match makes a
  // failing If-Unmodified-Since irrelevant.
  let both = @conditional.Ask::new(
    matching=@conditional.These([@conditional.Tag::new("a")]),
    unmodified_since=then,
  )
  assert_eq(
    both.evaluate(verb="PUT", etag=ours, modified=later),
    @conditional.Go,
  )
  // Step 4 only runs when If-None-Match is absent, so a satisfied
  // If-None-Match makes a 304-worthy If-Modified-Since irrelevant.
  let reading = @conditional.Ask::new(
    none_matching=@conditional.These([@conditional.Tag::new("b")]),
    modified_since=then,
  )
  assert_eq(
    reading.evaluate(verb="GET", etag=ours, modified=then),
    @conditional.Go,
  )
  // Nothing asked, nothing in the way.
  assert_eq(@conditional.ask.evaluate(verb="GET", etag=ours), @conditional.Go)
}

///|
/// §13.1.5, which is why this package and `range` were written together.
test "If-Range decides whether a Range may be honoured" {
  let ours = @conditional.Tag::new("a")
  let then = at("Sun, 06 Nov 1994 08:49:37 GMT")
  let later = at("Mon, 07 Nov 1994 08:49:37 GMT")
  // Absent: nothing stands in the way.
  assert_true(@conditional.ask.unchanged(etag=ours))
  let tagged = @conditional.Ask::new(ranging=@conditional.Marked(ours))
  assert_true(tagged.unchanged(etag=ours))
  assert_false(tagged.unchanged(etag=@conditional.Tag::new("b")))
  assert_false(tagged.unchanged())
  // A weak tag may not answer this question, even against itself.
  let weak = @conditional.Ask::new(
    ranging=@conditional.Marked(@conditional.Tag::new("a", weak=true)),
  )
  assert_false(weak.unchanged(etag=@conditional.Tag::new("a", weak=true)))
  assert_false(weak.unchanged(etag=ours))
  // A date has to be the same date, not merely no older.
  let dated = @conditional.Ask::new(ranging=@conditional.Dated(then))
  assert_true(dated.unchanged(modified=then))
  assert_false(dated.unchanged(modified=later))
  assert_false(dated.unchanged())
}
