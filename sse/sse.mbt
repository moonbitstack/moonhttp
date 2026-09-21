// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One event on the wire.
///
/// A field left `None` is left out of the frame. `data` carrying newlines goes
/// out as several `data:` lines and comes back joined, which is the format's own
/// rule and the reason a payload with a blank line in it cannot be sent as one.
pub(all) struct Event {
  data : String
  /// The type an `addEventListener` binds to. Absent means `message`.
  kind : String?
  /// Sets the client's `lastEventId`, which it sends back on reconnection.
  id : String?
  /// How long the client should wait before reconnecting, in milliseconds.
  retry : Int?
  /// A `:`-prefixed line. It dispatches nothing and exists to keep a connection
  /// warm through a proxy that would otherwise close it.
  comment : String?
} derive(Eq, Debug)

///|
pub extend Event with Eq::{equal, not_equal}

///|
pub extend Event with Debug::{to_repr}

///|
/// An event carrying only data, which is the common case.
pub fn Event::of(data : String) -> Event {
  { data, kind: None, id: None, retry: None, comment: None, }
}

///|
/// An event with whichever fields are wanted.
pub fn Event::new(
  data? : String = "",
  kind? : String,
  id? : String,
  retry? : Int,
  comment? : String,
) -> Event {
  { data, kind, id, retry, comment, }
}

///|
/// A comment-only frame: nothing is dispatched and the connection stays warm.
pub fn Event::ping(comment? : String = "") -> Event {
  { data: "", kind: None, id: None, retry: None, comment: Some(comment), }
}

///|
/// The frame this event is sent as, ending in the blank line that dispatches it.
///
/// `space` writes the one optional space after each colon, which every stream in
/// the wild carries and which a reader strips again. Turning it off saves a byte
/// per field on a stream where that matters, and changes nothing a client sees.
pub fn Event::encode(self : Event, space? : Bool = true) -> String {
  let gap = if space { " " } else { "" }
  let out = StringBuilder()
  match self.comment {
    Some(text) =>
      for line in lines(text[:]) {
        field(out, ":", line, gap)
      }
    None => ()
  }
  match self.id {
    Some(id) => field(out, "id:", id, gap)
    None => ()
  }
  match self.kind {
    Some(kind) => field(out, "event:", kind, gap)
    None => ()
  }
  match self.retry {
    Some(ms) => field(out, "retry:", ms.to_string(), gap)
    None => ()
  }
  // An entirely empty frame would dispatch an event with no data, so a `data:`
  // line goes out when there is data, or when there is nothing else at all.
  let bare = self.comment is None &&
    self.id is None &&
    self.kind is None &&
    self.retry is None
  if self.data != "" || bare {
    for line in lines(self.data[:]) {
      field(out, "data:", line, gap)
    }
  }
  out.write_char('\n')
  out.to_string()
}

///|
/// Read a stream of frames.
///
/// Anything the format does not define is ignored rather than refused — an
/// unknown field name, a line with no colon, a stray carriage return. That is
/// what the specification says to do, and it is what lets the format grow.
///
/// A trailing partial frame, one not yet closed by a blank line, is left out:
/// it has not been dispatched and is not an event yet.
pub fn decode(input : StringView) -> Array[Event] {
  let out : Array[Event] = []
  let data = StringBuilder()
  let comment = StringBuilder()
  let mut kind : String? = None
  let mut id : String? = None
  let mut retry : Int? = None
  let mut started = false
  for line in lines(input) {
    if line == "" {
      if started {
        let text = data.to_string()
        out.push({
          // The joined lines end in the separator the last one added.
          data: if text.length() > 0 {
            text[0:text.length() - 1].to_owned()
          } else {
            text
          },
          kind,
          id,
          retry,
          comment: if comment.is_empty() {
            None
          } else {
            let c = comment.to_string()
            Some(c[0:c.length() - 1].to_owned())
          },
        })
      }
      data.reset()
      comment.reset()
      kind = None
      id = None
      retry = None
      started = false
      continue
    }
    started = true
    let colon = find(line, ':')
    let name = if colon < 0 { line[:] } else { line[0:colon] }
    // One optional space after the colon belongs to the format, not the value.
    let mut from = colon + 1
    if colon >= 0 && from < line.length() && line.at(from).to_int() == 0x20 {
      from += 1
    }
    let value = if colon < 0 { "" } else { line[from:].to_owned() }
    match name {
      "" => {
        comment.write_string(value)
        comment.write_char('\n')
      }
      "data" => {
        data.write_string(value)
        data.write_char('\n')
      }
      "event" => kind = Some(value)
      // An id containing a NUL is ignored, which the specification says
      // explicitly because it is what a broken proxy sends.
      "id" => if !value.contains_char('\u{00}') { id = Some(value) }
      "retry" =>
        if value.length() > 0 && all_digits(value[:]) {
          retry = Some(@string.parse_int(value[:]) catch { _ => 0 })
        }
      _ => ()
    }
  }
  out
}

///|
/// The media type an event stream is served as.
pub let media_type : String = "text/event-stream"

///|
/// The space after the colon is the optional one a reader strips again. It is
/// written because every stream in the wild has it.
fn field(
  out : StringBuilder,
  name : String,
  value : String,
  gap : String,
) -> Unit {
  out.write_string(name)
  out.write_string(gap)
  out.write_string(value)
  out.write_char('\n')
}

///|
/// Split on the line endings the format allows: a line feed, a carriage return,
/// or the two together counting once.
fn lines(s : StringView) -> Array[String] {
  let out : Array[String] = []
  let piece = StringBuilder()
  let mut i = 0
  while i < s.length() {
    let c = s.at(i).to_int()
    if c == 0x0D {
      out.push(piece.to_string())
      piece.reset()
      if i + 1 < s.length() && s.at(i + 1).to_int() == 0x0A {
        i += 1
      }
    } else if c == 0x0A {
      out.push(piece.to_string())
      piece.reset()
    } else {
      piece.write_view(s[i:i + 1])
    }
    i += 1
  }
  out.push(piece.to_string())
  out
}

///|
fn find(s : String, c : Char) -> Int {
  for i in 0..<s.length() {
    if s.at(i).to_int() == c.to_int() {
      return i
    }
  }
  -1
}

///|
fn all_digits(s : StringView) -> Bool {
  for i in 0..<s.length() {
    let c = s.at(i).to_int()
    if c < 0x30 || c > 0x39 {
      return false
    }
  }
  true
}
