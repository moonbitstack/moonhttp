// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The hash decides how many candidates a search has to look at, and one that
/// puts distinct three-octet keys in the same bucket turns every search into a
/// walk over that bucket. A text's keys are mostly distinct, so the comparison is
/// between how many keys there are and how many buckets they land in: a hash that
/// spreads them leaves the two nearly equal, and one that keeps only the low bits
/// of the key — the multiply taken out — leaves far more keys than buckets.
test "the hash spreads a text's three-octet keys over its table" {
  let prose = b"WE THE PEOPLE of the United States, in Order to form a more perfect Union, establish Justice, insure domestic Tranquility, provide for the common defence, promote the general Welfare, and secure the Blessings of Liberty to ourselves and our Posterity, do ordain and establish this Constitution for the United States of America. Article I. Section 1. All legislative Powers herein granted shall be vested in a Congress of the United States, which shall consist of a Senate and House of Representatives."
  let keys : Map[Int32, Unit] = Map([])
  let buckets : Map[Int32, Unit] = Map([])
  let total = prose.length()
  for i in 0..<(total - 3) {
    let key = key_at(prose[:], i, total)
    keys[(key & 0xFFFFFF).reinterpret_as_int()] = ()
    buckets[hash_at(prose[:], i, total)] = ()
  }
  // Every key in a bucket of its own, give or take the birthday problem: a
  // hundred keys fewer than that is not a spread but a collapse.
  assert_true(keys.length() > 300)
  assert_true(buckets.length() + 8 >= keys.length())
}

///|
test "a short match waits for the longer one that starts on the next octet" {
  // "XYZW" twice: the first copy is followed by an octet the second is not, so the
  // search there finds four octets. One octet later the message repeats "YZW" and
  // twenty octets after it, which is the match worth taking.
  let tail = b"0123456789ABCDEFGHIJ"
  let out = Buffer::Buffer(size_hint=52)
  out.write_bytes(b"XYZW")
  out.write_bytes(b"j")
  out.write_bytes(b"YZW")
  out.write_bytes(tail[:])
  out.write_bytes(b"XYZW")
  out.write_bytes(tail[:])
  let payload = out.to_bytes()
  let parsed = parse(payload[:], 0, payload.length(), 32768)
  assert_eq(parsed.tokens.length(), 30)
  // The "X" at 28 is written out although it starts a four-octet match with the
  // one at 0, because the match that starts on the octet after it is twenty-three
  // long. A parse that took the four would spend the same octets on a sixth of the
  // run.
  assert_eq(parsed.tokens[28], 88)
  assert_eq(-parsed.tokens[29], (24 << 9) | 23)
}
