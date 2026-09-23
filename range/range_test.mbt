// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Every example RFC 9110 §14 prints is a test here, by the length the section
// states: 10000 octets for the Range examples of §14.1.2, 1234 for the
// Content-Range examples of §14.4.

///|
/// The Range examples of RFC 9110 §14.1.2, in the order the section gives them.
test "the field reads the way RFC 9110 §14.1.2 writes it" {
  assert_eq(@range.decode("bytes=0-499"), Some([@range.Between(0L, 499L)]))
  assert_eq(@range.decode("bytes=500-999"), Some([@range.Between(500L, 999L)]))
  assert_eq(@range.decode("bytes=-500"), Some([@range.Last(500L)]))
  assert_eq(@range.decode("bytes=9500-"), Some([@range.From(9500L)]))
  assert_eq(
    @range.decode("bytes=0-0,-1"),
    Some([@range.Between(0L, 0L), @range.Last(1L)]),
  )
  assert_eq(
    @range.decode("bytes= 0-999, 4500-5499, -1000"),
    Some([
      @range.Between(0L, 999L),
      @range.Between(4500L, 5499L),
      @range.Last(1000L),
    ]),
  )
  assert_eq(
    @range.decode("bytes=500-600,601-999"),
    Some([@range.Between(500L, 600L), @range.Between(601L, 999L)]),
  )
  assert_eq(
    @range.decode("bytes=500-700,601-999"),
    Some([@range.Between(500L, 700L), @range.Between(601L, 999L)]),
  )
}

///|
test "a field that is written back reads the same" {
  for
    value in [
      "bytes=0-499", "bytes=-500", "bytes=9500-", "bytes=0-0, -1", "bytes=0-999, 4500-5499, -1000",
    ] {
    guard @range.decode(value) is Some(specs) else {
      fail("a valid Range did not read: " + value)
    }
    assert_eq(@range.encode(specs[:]), value)
  }
}

///|
/// RFC 9110 §14.2: a unit the server does not implement, and a value that does
/// not parse, are both ignored — which here is `None` and means status 200.
test "a field to be ignored reads as nothing" {
  // Not the bytes unit.
  assert_eq(@range.decode("items=0-499"), None)
  assert_eq(@range.decode("BYTES=0-499"), None)
  // No unit at all.
  assert_eq(@range.decode("0-499"), None)
  assert_eq(@range.decode(""), None)
  // §14.1.1: an int-range whose last position precedes its first is invalid.
  assert_eq(@range.decode("bytes=500-499"), None)
  // Neither position is a number.
  assert_eq(@range.decode("bytes=-"), None)
  assert_eq(@range.decode("bytes=abc-def"), None)
  assert_eq(@range.decode("bytes=0-4x9"), None)
  // A range-set naming nothing.
  assert_eq(@range.decode("bytes="), None)
  assert_eq(@range.decode("bytes=,"), None)
  // One bad spec spoils the field rather than being dropped from it.
  assert_eq(@range.decode("bytes=0-499,900-100"), None)
}

///|
/// A different unit is a parameter, not a constant, so a caller that does
/// implement one can say so.
test "the unit is a knob" {
  assert_eq(
    @range.decode("items=0-4", unit="items"),
    Some([@range.Between(0L, 4L)]),
  )
  assert_eq(@range.decode("bytes=0-4", unit="items"), None)
  assert_eq(
    @range.encode([@range.Between(0L, 4L)][:], unit="items"),
    "items=0-4",
  )
}

///|
/// RFC 9110 §14.1.2 works its examples against a representation of 10000
/// octets, and names the offsets each one resolves to.
test "the examples resolve to the offsets §14.1.2 names" {
  let ten = 10000L
  assert_eq(
    @range.measure([@range.Last(500L)][:], length=ten),
    Some([{ at: 9500L, last: 9999L, }]),
  )
  assert_eq(
    @range.measure([@range.From(9500L)][:], length=ten),
    Some([{ at: 9500L, last: 9999L, }]),
  )
  assert_eq(
    @range.measure([@range.Between(0L, 0L), @range.Last(1L)][:], length=ten),
    Some([{ at: 0L, last: 0L, }, { at: 9999L, last: 9999L, }]),
  )
  assert_eq(
    @range.measure(
      [
        @range.Between(0L, 999L),
        @range.Between(4500L, 5499L),
        @range.Last(1000L),
      ][:],
      length=ten,
    ),
    Some([
      { at: 0L, last: 999L, },
      { at: 4500L, last: 5499L, },
      { at: 9000L, last: 9999L, },
    ]),
  )
  // §14.1.2 calls these two "other valid (but not canonical) specifications of
  // the second 500 bytes" — coalescing is what makes them canonical again.
  assert_eq(
    @range.measure(
      [@range.Between(500L, 600L), @range.Between(601L, 999L)][:],
      length=ten,
    ),
    Some([{ at: 500L, last: 999L, }]),
  )
  assert_eq(
    @range.measure(
      [@range.Between(500L, 700L), @range.Between(601L, 999L)][:],
      length=ten,
    ),
    Some([{ at: 500L, last: 999L, }]),
  )
}

///|
/// §14.1.2: an absent or too-large last position is replaced by the end of the
/// representation, and a suffix longer than the representation takes all of it.
test "a range past the end is clipped to the end" {
  assert_eq(
    @range.measure([@range.Between(0L, 99999L)][:], length=100L),
    Some([{ at: 0L, last: 99L, }]),
  )
  assert_eq(
    @range.measure([@range.From(0L)][:], length=100L),
    Some([{ at: 0L, last: 99L, }]),
  )
  assert_eq(
    @range.measure([@range.Last(99999L)][:], length=100L),
    Some([{ at: 0L, last: 99L, }]),
  )
}

///|
/// §14.1.2 gives the satisfiability rule exactly: an int-range whose first
/// position is inside the representation, or a suffix-range of non-zero length.
test "what §14.1.2 calls unsatisfiable is refused" {
  // A first position at or past the end.
  assert_eq(@range.measure([@range.Between(100L, 200L)][:], length=100L), None)
  assert_eq(@range.measure([@range.From(100L)][:], length=100L), None)
  // A suffix of nothing.
  assert_eq(@range.measure([@range.Last(0L)][:], length=100L), None)
  // "When a selected representation has zero length, the only satisfiable form
  // of range-spec in a GET request is a suffix-range with a non-zero
  // suffix-length" — and even that has nothing to return.
  assert_eq(@range.measure([@range.From(0L)][:], length=0L), None)
  assert_eq(@range.measure([@range.Between(0L, 0L)][:], length=0L), None)
  assert_eq(@range.measure([@range.Last(10L)][:], length=0L), None)
}

///|
/// §14.1.1: a ranges-specifier is satisfiable if *any* of its specs is, so the
/// ones that cannot be met are dropped and the rest are served.
test "one satisfiable range carries a request whose others are not" {
  assert_eq(
    @range.measure(
      [@range.Between(500L, 600L), @range.Between(0L, 9L)][:],
      length=100L,
    ),
    Some([{ at: 0L, last: 9L, }]),
  )
  assert_eq(
    @range.measure([@range.Last(0L), @range.From(90L)][:], length=100L),
    Some([{ at: 90L, last: 99L, }]),
  )
}

///|
/// Coalescing is what §14.2 permits and is on by default; turning it off sends
/// what was asked for, overlaps and all.
test "coalescing is a knob and touching ranges count as overlapping" {
  let asked = [@range.Between(0L, 99L), @range.Between(100L, 199L)]
  assert_eq(
    @range.measure(asked[:], length=1000L),
    Some([{ at: 0L, last: 199L, }]),
  )
  assert_eq(
    @range.measure(asked[:], length=1000L, merge=false),
    Some([{ at: 0L, last: 99L, }, { at: 100L, last: 199L, }]),
  )
  // Out of order in, in order out.
  assert_eq(
    @range.measure(
      [@range.Between(50L, 59L), @range.Between(0L, 9L)][:],
      length=1000L,
    ),
    Some([{ at: 0L, last: 9L, }, { at: 50L, last: 59L, }]),
  )
  // One range wholly inside another is absorbed, not duplicated.
  assert_eq(
    @range.measure(
      [@range.Between(0L, 99L), @range.Between(10L, 20L)][:],
      length=1000L,
    ),
    Some([{ at: 0L, last: 99L, }]),
  )
}

///|
/// A request naming thousands of ranges is the shape of the 2011 Apache range
/// attack. Past the limit the answer is the whole representation, which reads
/// here as no ranges at all.
test "too many ranges is not a range request" {
  let many = []
  for i = 0L; i < 40L; i = i + 1L {
    many.push(@range.Between(i * 10L, i * 10L + 1L))
  }
  assert_eq(@range.measure(many[:], length=10000L, limit=100) is Some(_), true)
  assert_eq(@range.measure(many[:], length=10000L, limit=10), None)
  assert_eq(@range.measure(many[:], length=10000L, limit=40) is Some(_), true)
  assert_eq(@range.measure(many[:], length=10000L, limit=39), None)
}

///|
/// §14.1.2: "recipients MUST anticipate potentially large decimal numerals and
/// prevent parsing errors due to integer conversion overflows."
test "a numeral too large to hold does not wrap" {
  guard @range.decode("bytes=0-99999999999999999999999999") is Some(specs) else {
    fail("a huge last position should still parse")
  }
  assert_eq(specs.length(), 1)
  assert_eq(
    @range.measure(specs[:], length=100L),
    Some([{ at: 0L, last: 99L, }]),
  )
  guard @range.decode("bytes=99999999999999999999999999-") is Some(big) else {
    fail("a huge first position should still parse")
  }
  assert_eq(@range.measure(big[:], length=100L), None)
}

///|
/// The Content-Range examples of RFC 9110 §14.4, against the 1234 octets the
/// section names.
test "Content-Range is written the way §14.4 writes it" {
  assert_eq(
    @range.Content::new({ at: 42L, last: 1233L, }, complete=1234L).encode(),
    "bytes 42-1233/1234",
  )
  assert_eq(
    @range.Content::new({ at: 42L, last: 1233L, }).encode(),
    "bytes 42-1233/*",
  )
  assert_eq(@range.unsatisfied(1234L).encode(), "bytes */1234")
  assert_eq(
    @range.Content::new({ at: 0L, last: 499L, }, complete=1234L).encode(),
    "bytes 0-499/1234",
  )
  assert_eq(
    @range.Content::new({ at: 500L, last: 999L, }, complete=1234L).encode(),
    "bytes 500-999/1234",
  )
  assert_eq(
    @range.Content::new({ at: 500L, last: 1233L, }, complete=1234L).encode(),
    "bytes 500-1233/1234",
  )
  assert_eq(
    @range.Content::new({ at: 734L, last: 1233L, }, complete=1234L).encode(),
    "bytes 734-1233/1234",
  )
}

///|
test "a Content-Range round-trips" {
  for
    value in [
      "bytes 42-1233/1234", "bytes 42-1233/*", "bytes */1234", "bytes 0-0/1",
    ] {
    guard @range.Content::decode(value) is Some(back) else {
      fail("a valid Content-Range did not read: " + value)
    }
    assert_eq(back.encode(), value)
  }
}

///|
/// §14.4: "A Content-Range field value is invalid if it contains a range-resp
/// that has a last-pos value less than its first-pos value, or a
/// complete-length value less than or equal to its last-pos value."
test "an invalid Content-Range is refused rather than repaired" {
  assert_eq(@range.Content::decode("bytes 100-50/1234"), None)
  assert_eq(@range.Content::decode("bytes 0-1233/1233"), None)
  assert_eq(@range.Content::decode("bytes 0-1233/100"), None)
  // The unsatisfied form has to carry a length, or it says nothing.
  assert_eq(@range.Content::decode("bytes */*"), None)
  // Shapes that are not the grammar.
  assert_eq(@range.Content::decode("bytes 0-499"), None)
  assert_eq(@range.Content::decode("bytes0-499/1234"), None)
  assert_eq(@range.Content::decode(""), None)
  assert_eq(@range.Content::decode("bytes x-y/1234"), None)
}

///|
/// §14.4 again: a length exactly one past the last position is the boundary
/// case, and it is valid.
test "a complete length one past the last position is valid" {
  guard @range.Content::decode("bytes 0-1233/1234") is Some(ok) else {
    fail("the boundary case should read")
  }
  assert_eq(ok.part, Some({ at: 0L, last: 1233L, }))
  assert_eq(ok.complete, Some(1234L))
}

///|
test "Accept-Ranges says bytes or says none" {
  assert_eq(@range.accept(), "bytes")
  assert_eq(@range.accept(ranges=true), "bytes")
  assert_eq(@range.accept(ranges=false), "none")
  assert_eq(@range.accept(unit="items"), "items")
}

///|
/// RFC 9110 §13.1.5: the range is served only on a strong entity-tag match or
/// an exact date match. A weak tag never matches, because stitching a range
/// from an equivalent representation onto a copy of another produces a file
/// that never existed.
test "If-Range serves the range only when nothing has changed" {
  assert_true(@range.unchanged("\"abc\"", etag="\"abc\""))
  assert_false(@range.unchanged("\"abc\"", etag="\"xyz\""))
  assert_false(@range.unchanged("\"abc\""))
  // Weak on either side.
  assert_false(@range.unchanged("W/\"abc\"", etag="\"abc\""))
  assert_false(@range.unchanged("\"abc\"", etag="W/\"abc\""))
  assert_false(@range.unchanged("W/\"abc\"", etag="W/\"abc\""))
  // A date matches exactly or not at all.
  let when = "Wed, 21 Oct 2015 07:28:00 GMT"
  assert_true(@range.unchanged(when, modified=when))
  assert_false(@range.unchanged(when, modified="Thu, 22 Oct 2015 07:28:00 GMT"))
  assert_false(@range.unchanged(when))
  assert_false(@range.unchanged(""))
  // An entity tag is never compared against a date, or the other way round.
  assert_false(@range.unchanged("\"abc\"", modified=when))
  assert_false(@range.unchanged(when, etag="\"abc\""))
}

///|
/// RFC 9110 §14.6: each part carries the representation's own media type and
/// its own Content-Range, and the last boundary is the one with two trailing
/// hyphens.
test "a multi-range body is the shape §14.6 describes" {
  let head : @range.Part = { at: 0L, last: 3L, }
  let tail : @range.Part = { at: 10L, last: 12L, }
  let body = @range.parts(
    [(head, b"0123"), (tail, b"abc")][:],
    boundary="SEP",
    kind="text/plain",
    complete=100L,
  )
  let want =
    #|
    #|--SEP
    #|Content-Type: text/plain
    #|Content-Range: bytes 0-3/100
    #|
    #|0123
    #|--SEP
    #|Content-Type: text/plain
    #|Content-Range: bytes 10-12/100
    #|
    #|abc
    #|--SEP--
    #|
  let text = StringBuilder()
  for byte in body {
    if byte != b'\r' {
      text.write_char(byte.to_int().unsafe_to_char())
    }
  }
  assert_eq(text.to_string(), want)
  assert_eq(@range.multipart("SEP"), "multipart/byteranges; boundary=SEP")
}

///|
test "a part knows how long it is" {
  assert_eq(({ at: 0L, last: 0L, } : @range.Part).length(), 1L)
  assert_eq(({ at: 0L, last: 499L, } : @range.Part).length(), 500L)
  assert_eq(({ at: 9500L, last: 9999L, } : @range.Part).length(), 500L)
}
