// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The stream the WHATWG specification prints as its first example.
let stream : String =
  #|: test stream
  #|
  #|data: first event
  #|id: 1
  #|
  #|data:second event
  #|id
  #|
  #|data:  third event
  #|
  #|

///|
test "the specification's own example stream" {
  let events = @sse.decode(stream[:])
  assert_eq(events.length(), 4)
  assert_eq(events[0], @sse.Event::new(comment="test stream"))
  assert_eq(events[1], @sse.Event::new(data="first event", id="1"))
  // A field with no colon has an empty value, so this id is the empty string —
  // which is how a stream tells a client to forget its last event id.
  assert_eq(events[2], @sse.Event::new(data="second event", id=""))
  // Exactly one space after the colon belongs to the format; the second is data.
  assert_eq(events[3], @sse.Event::new(data=" third event"))
}

///|
/// The specification's second example, which is about what a bare `data` field
/// means and is where an implementation that trims too much goes wrong.
test "empty data fields" {
  let text =
    #|data
    #|
    #|data
    #|data
    #|
    #|data:
    #|
  let events = @sse.decode(text[:])
  assert_eq(events.length(), 3)
  assert_eq(events[0].data, "")
  assert_eq(events[1].data, "\n")
  assert_eq(events[2].data, "")
}

///|
/// Every frame this library writes must read back as the event that wrote it.
test "a frame reads back as itself" {
  let cases = [
    @sse.Event::of("hello"),
    @sse.Event::of(""),
    @sse.Event::of("two\nlines"),
    @sse.Event::of("three\nlines\nhere"),
    @sse.Event::new(data="payload", kind="update"),
    @sse.Event::new(data="payload", id="42", retry=3000),
    @sse.Event::new(
      data="everything",
      kind="tick",
      id="7",
      retry=250,
      comment="a note",
    ),
    @sse.Event::ping(),
    @sse.Event::ping(comment="keeping warm"),
  ]
  for event in cases {
    let back = @sse.decode(event.encode()[:])
    assert_eq(back.length(), 1)
    assert_eq(back[0], event)
  }
}

///|
/// What the frames actually look like, since a round trip through one
/// implementation would pass even if both halves were wrong.
test "the bytes on the wire" {
  assert_eq(@sse.Event::of("hello").encode(), "data: hello\n\n")
  assert_eq(@sse.Event::of("").encode(), "data: \n\n")
  assert_eq(@sse.Event::of("a\nb").encode(), "data: a\ndata: b\n\n")
  assert_eq(@sse.Event::ping().encode(), ": \n\n")
  assert_eq(@sse.Event::ping(comment="hi").encode(), ": hi\n\n")
  assert_eq(
    @sse.Event::new(data="x", kind="t", id="9", retry=5).encode(),
    "id: 9\nevent: t\nretry: 5\ndata: x\n\n",
  )
  assert_eq(@sse.media_type, "text/event-stream")
}

///|
/// All three line endings, because a proxy or a library on the way will have
/// rewritten them.
test "line endings" {
  for
    text in [
      "data: a\n\ndata: b\n\n", "data: a\r\n\r\ndata: b\r\n\r\n", "data: a\r\rdata: b\r\r",
    ] {
    let events = @sse.decode(text[:])
    assert_eq(events.length(), 2)
    assert_eq(events[0].data, "a")
    assert_eq(events[1].data, "b")
  }
}

///|
/// What a reader must ignore rather than refuse — the specification says so,
/// and it is what lets the format grow a field without breaking every client.
test "unknown input is ignored" {
  let text =
    #|unknown: field
    #|data: kept
    #|no-colon-at-all
    #|retry: not a number
    #|retry: -5
    #|
  let events = @sse.decode(text[:])
  assert_eq(events.length(), 1)
  assert_eq(events[0].data, "kept")
  assert_eq(events[0].retry, None)
}

///|
/// A frame not yet closed by a blank line has not been dispatched, so it is not
/// an event and does not come back as one.
test "a partial frame is not an event" {
  assert_eq(@sse.decode("data: half").length(), 0)
  assert_eq(@sse.decode("data: whole\n\ndata: half").length(), 1)
  assert_eq(@sse.decode("").length(), 0)
  assert_eq(@sse.decode("\n\n\n").length(), 0)
}

///|
/// An id carrying a NUL is dropped, which the specification calls out because
/// it is what a broken intermediary sends.
test "an id with a NUL is dropped" {
  let events = @sse.decode("data: x\nid: a\u{00}b\n\n")
  assert_eq(events.length(), 1)
  assert_eq(events[0].id, None)
}

///|
/// The space after each colon is optional in the format and universal on the
/// wire, so it is written by default and can be turned off.
test "the optional space is a knob" {
  let event = @sse.Event::new(data="x", kind="t", id="9", retry=5)
  assert_eq(event.encode(), "id: 9\nevent: t\nretry: 5\ndata: x\n\n")
  assert_eq(event.encode(space=false), "id:9\nevent:t\nretry:5\ndata:x\n\n")
  // A reader strips it either way, so the two frames carry the same event.
  assert_eq(@sse.decode(event.encode()[:]), [event])
  assert_eq(@sse.decode(event.encode(space=false)[:]), [event])
  // Comments too.
  let ping = @sse.Event::ping(comment="keep-alive")
  assert_eq(ping.encode(), ": keep-alive\n\n")
  assert_eq(ping.encode(space=false), ":keep-alive\n\n")
  // What it saves: one byte per field written.
  assert_eq(event.encode().length() - event.encode(space=false).length(), 4)
}

///|
/// A field that is either given or not is given plainly, without a wrapper.
test "an absent field is absent, not wrapped" {
  assert_eq(@sse.Event::new(data="x"), @sse.Event::of("x"))
  let named = @sse.Event::new(data="x", kind="t")
  assert_eq(named.kind, Some("t"))
  assert_eq(named.id, None)
  assert_eq(@sse.Event::new().data, "")
}

///|
test "events: the specification's example stream, as a browser dispatches it" {
  let events = @sse.events(stream[:])
  // The comment-only frame dispatches nothing.
  assert_eq(events.length(), 3)
  assert_eq(
    events[0],
    @sse.Event::new(data="first event", kind="message", id="1"),
  )
  assert_eq(
    events[1],
    @sse.Event::new(data="second event", kind="message", id=""),
  )
  // The id is the stream's: the third frame names none and keeps the second's.
  assert_eq(
    events[2],
    @sse.Event::new(data=" third event", kind="message", id=""),
  )
}

///|
test "events: a frame with no data line is not an event" {
  let text =
    #|data
    #|
    #|data
    #|data
    #|
    #|retry: 500
    #|
    #|: keep-alive
    #|
    #|data:
    #|
  let events = @sse.events(text[:])
  assert_eq(events.map(e => e.data), ["", "\n", ""])
  // `decode` answers the two data-less frames as well.
  assert_eq(@sse.decode(text[:]).length(), 5)
}

///|
test "events: the id and the retry carry over, the type does not" {
  let text =
    #|event: add
    #|id: 7
    #|retry: 3000
    #|data: 73857293
    #|
    #|data: 2153
    #|
    #|event:
    #|id: 8
    #|data: 113411
    #|
  let events = @sse.events(text[:])
  assert_eq(events.length(), 3)
  assert_eq(
    events[0],
    @sse.Event::new(data="73857293", kind="add", id="7", retry=3000),
  )
  assert_eq(
    events[1],
    @sse.Event::new(data="2153", kind="message", id="7", retry=3000),
  )
  // An empty type is no type.
  assert_eq(
    events[2],
    @sse.Event::new(data="113411", kind="message", id="8", retry=3000),
  )
  // Frame by frame, only the first carries them.
  let frames = @sse.decode(text[:])
  assert_eq(frames[1].id, None)
  assert_eq(frames[1].kind, None)
}

///|
test "events: several data lines join, and the last partial frame waits" {
  let text = "data: YHOO\ndata: +2\ndata: 10\n\ndata: not yet"
  assert_eq(@sse.events(text[:]), [
    @sse.Event::new(data="YHOO\n+2\n10", kind="message"),
  ])
}
