// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An entity-tag (RFC 9110 §8.8.3).
///
/// `text` is what is inside the quotes. Keeping the quotes would put a piece of
/// the field's syntax inside the value, and then every comparison would have to
/// remember whether this particular tag had been stripped yet.
///
/// `weak` is the `W/` in front: the representations two weak tags mark are
/// equivalent, not identical. A weak tag is enough to answer "has this changed
/// at all" and not enough to answer "may I splice these two byte ranges".
pub(all) struct Tag {
  text : String
  weak : Bool
} derive(Eq, Debug)

///|
pub extend Tag with Eq::{equal, not_equal}

///|
pub extend Tag with Debug::{to_repr}

///|
/// What a precondition field names (§13.1.1): every representation, or these
/// tags.
///
/// `*` is not a tag that matches everything — §13.1.1 and §13.1.2 read it as a
/// question about whether a representation exists at all, and they answer it in
/// opposite directions.
pub(all) enum Tags {
  Any
  These(Array[Tag])
} derive(Eq, Debug)

///|
pub extend Tags with Eq::{equal, not_equal}

///|
pub extend Tags with Debug::{to_repr}

///|
/// Either kind of validator (§8.8).
///
/// `If-Range` takes one or the other (§13.1.5), which is the reason they need a
/// common type; the other four fields each take only one kind.
pub(all) enum Validator {
  Marked(Tag)
  Dated(@moondate.Moment)
} derive(Eq, Debug)

///|
pub extend Validator with Eq::{equal, not_equal}

///|
pub extend Validator with Debug::{to_repr}

///|
/// What §13.2.2 says to do with the request once the preconditions are weighed.
pub(all) enum Verdict {
  /// No precondition failed: carry on with the method.
  Go
  /// The client's copy is still good — 304, with no body (§15.4.5).
  Fresh
  /// A precondition failed — 412 (§15.5.13).
  Failed
} derive(Eq, Debug)

///|
pub extend Verdict with Eq::{equal, not_equal}

///|
pub extend Verdict with Debug::{to_repr}

///|
/// A tag with this text.
pub fn Tag::new(text : String, weak? : Bool = false) -> Tag {
  { text, weak, }
}

// ----------------------------------------------------------------- comparing

///|
/// Strong comparison (§8.8.3.2): neither tag is weak, and the texts match
/// character by character.
///
/// This is the one `If-Match` and `If-Range` use, because both of them are
/// about splicing or replacing octets and a weak tag does not promise the
/// octets are the same.
pub fn Tag::same(self : Tag, other : Tag) -> Bool {
  !self.weak && !other.weak && self.text == other.text
}

///|
/// Weak comparison (§8.8.3.2): the texts match, whether or not either is weak.
///
/// This is the one `If-None-Match` uses, because "has it changed at all" is a
/// question a weak tag can answer.
pub fn Tag::alike(self : Tag, other : Tag) -> Bool {
  self.text == other.text
}

// ---------------------------------------------------------------- generating

///|
/// The hexadecimal the two generators write their numbers in.
let hex : @moonbase.Alphabet = @moonbase.Alphabet::of("0123456789abcdef")

///|
/// An entity-tag derived from the octets themselves: their count and their
/// digest, both in hexadecimal.
///
/// Strong by default, which is the whole point of hashing the content — two
/// representations with this tag are identical octet for octet.
///
/// `digest` is a parameter rather than a choice made here. Which hash a server
/// spends on every response is that server's trade, and a package that picked
/// one would be making it for everybody. The shape follows the `etag` package
/// Express serves static files with, `"<length>-<digest>"`, except that the
/// digest is hexadecimal rather than base64, the spelling nginx and Apache use.
pub fn hash(
  raw : BytesView,
  digest~ : &@spec.Hash,
  weak? : Bool = false,
) -> Tag {
  digest.reset()
  digest.write(raw)
  let text = number(raw.length().to_int64()) +
    "-" +
    @base16.encode(digest.finish()[:])
  { text, weak, }
}

///|
/// An entity-tag derived from what a file system knows without opening the
/// file: when it last changed and how long it is.
///
/// This is nginx's `"<mtime>-<length>"`, and its point is that it costs one
/// stat. Weak by default, as a timestamp with one-second resolution has to be:
/// two writes inside the same second leave the length and the mtime unchanged,
/// so the tag cannot promise the octets are the same.
pub fn stamp(
  length~ : Int64,
  modified~ : @moondate.Moment,
  weak? : Bool = true,
) -> Tag {
  let seconds = match modified.epoch() {
    Some(epoch) => epoch
    None => 0L
  }
  { text: number(seconds) + "-" + number(length), weak, }
}

///|
fn number(value : Int64) -> String {
  let value = if value < 0L { 0L } else { value }
  @moonbase.encode_int(value.reinterpret_as_uint64(), hex)
}

// ------------------------------------------------------- fields, both ways

///|
/// Write the tag as a field value: `"x"`, or `W/"x"` (§8.8.3).
pub fn Tag::encode(self : Tag) -> String {
  if self.weak {
    "W/\"" + self.text + "\""
  } else {
    "\"" + self.text + "\""
  }
}

///|
/// Read one entity-tag. `None` when it is not one — an unquoted value is the
/// usual way this happens, and §8.8.3 has no room for it.
pub fn Tag::decode(text : StringView) -> Tag? {
  let text = trim(text)
  let (text, weak) = if text.length() >= 2 &&
    text[0].to_int() == 0x57 &&
    text[1].to_int() == 0x2F {
    (text[2:], true)
  } else {
    (text, false)
  }
  if text.length() < 2 ||
    text[0].to_int() != 0x22 ||
    text[text.length() - 1].to_int() != 0x22 {
    return None
  }
  Some({ text: text[1:text.length() - 1].to_owned(), weak, })
}

///|
/// Write a whole field value: `*`, or the tags separated by commas.
pub fn Tags::encode(self : Tags) -> String {
  match self {
    Any => "*"
    These(tags) => {
      let out = StringBuilder()
      for i = 0; i < tags.length(); i = i + 1 {
        if i > 0 {
          out.write_string(", ")
        }
        out.write_string(tags[i].encode())
      }
      out.to_string()
    }
  }
}

///|
/// Read a whole field value.
///
/// The commas are found outside the quotes, because `,` is in the `etagc` set
/// (§8.8.3) and a tag is allowed to contain one. `None` when any member is not
/// an entity-tag: §13.1.1 has no reading for a half-valid list, and taking the
/// members that did parse would answer a question nobody asked.
pub fn Tags::decode(text : StringView) -> Tags? {
  let text = trim(text)
  if text.length() == 0 {
    return None
  }
  if text == "*" {
    return Some(Any)
  }
  let tags = []
  let mut start = 0
  let mut quoted = false
  for i = 0; i < text.length(); i = i + 1 {
    let c = text[i].to_int()
    if c == 0x22 {
      quoted = !quoted
    } else if c == 0x2C && !quoted {
      guard Tag::decode(text[start:i]) is Some(tag) else { return None }
      tags.push(tag)
      start = i + 1
    }
  }
  guard Tag::decode(text[start:]) is Some(tag) else { return None }
  tags.push(tag)
  Some(These(tags))
}

///|
/// Read an `If-Range` value (§13.1.5).
///
/// A tag and a date are told apart by the first two characters, which is what
/// §13.1.5 says to do: only an entity-tag can start with a quote, and only a
/// weak one can start with `W/`.
pub fn Validator::decode(text : StringView) -> Validator? {
  let text = trim(text)
  if text.length() == 0 {
    return None
  }
  if text[0].to_int() == 0x22 ||
    (text.length() >= 2 && text[0].to_int() == 0x57 && text[1].to_int() == 0x2F) {
    return match Tag::decode(text) {
      Some(tag) => Some(Marked(tag))
      None => None
    }
  }
  Some(Dated(@moondate.http(text))) catch {
    _ => None
  }
}

///|
/// Write an `If-Range` value.
///
/// Raises for a moment with no zone: an HTTP-date is GMT by definition
/// (§5.6.7), and there is no honest way to write one from a moment that never
/// said where it was.
pub fn Validator::encode(self : Validator) -> String raise @moondate.Refused {
  match self {
    Marked(tag) => tag.encode()
    Dated(moment) => moment.http_text()
  }
}

// ------------------------------------------------------------ what was asked

///|
/// The five precondition fields of one request (§13.1), already read.
pub(all) struct Ask {
  /// `If-Match` (§13.1.1).
  matching : Tags?
  /// `If-None-Match` (§13.1.2).
  none_matching : Tags?
  /// `If-Modified-Since` (§13.1.3).
  modified_since : @moondate.Moment?
  /// `If-Unmodified-Since` (§13.1.4).
  unmodified_since : @moondate.Moment?
  /// `If-Range` (§13.1.5).
  ranging : Validator?
} derive(Eq, Debug)

///|
pub extend Ask with Eq::{equal, not_equal}

///|
pub extend Ask with Debug::{to_repr}

///|
/// A request that carried no preconditions at all.
pub let ask : Ask = {
  matching: None,
  none_matching: None,
  modified_since: None,
  unmodified_since: None,
  ranging: None,
}

///|
/// The preconditions a request carried, named one at a time.
pub fn Ask::new(
  matching? : Tags,
  none_matching? : Tags,
  modified_since? : @moondate.Moment,
  unmodified_since? : @moondate.Moment,
  ranging? : Validator,
) -> Ask {
  { matching, none_matching, modified_since, unmodified_since, ranging, }
}

///|
/// Pull the five fields out of a request's headers.
///
/// Field names are matched without regard to case (§5.1). Two lines of the same
/// list-valued field are one list (§5.3), which is why the tag fields are joined
/// before they are read; the date fields are not lists, so a repeat is ignored
/// rather than combined into something the grammar has no reading for.
///
/// A field that is present but unreadable comes back absent, which is what
/// §13.1.3 and §13.1.4 tell a recipient to do with one.
pub fn Ask::read(headers : ArrayView[(String, String)]) -> Ask {
  let matching = StringBuilder()
  let none_matching = StringBuilder()
  let mut modified_since = None
  let mut unmodified_since = None
  let mut ranging = None
  for pair in headers {
    match lower(pair.0) {
      "if-match" => join(matching, pair.1)
      "if-none-match" => join(none_matching, pair.1)
      "if-modified-since" =>
        if modified_since is None {
          modified_since = date(pair.1)
        }
      "if-unmodified-since" =>
        if unmodified_since is None {
          unmodified_since = date(pair.1)
        }
      "if-range" => if ranging is None { ranging = Validator::decode(pair.1) }
      _ => ()
    }
  }
  {
    matching: Tags::decode(matching.to_string()),
    none_matching: Tags::decode(none_matching.to_string()),
    modified_since,
    unmodified_since,
    ranging,
  }
}

///|
fn join(out : StringBuilder, value : String) -> Unit {
  if out.to_string().length() > 0 {
    out.write_string(", ")
  }
  out.write_string(value)
}

///|
fn date(value : String) -> @moondate.Moment? {
  Some(@moondate.http(value)) catch {
    _ => None
  }
}

// -------------------------------------------------------------- the verdict

///|
/// Weigh the preconditions in the order §13.2.2 sets out.
///
/// `verb` is the request method — the word `method` is reserved. It decides what
/// a failed `If-None-Match` means: a 304 for a `GET` or a
/// `HEAD`, a 412 for anything else. It has no default because there is no
/// answer that is right when nobody said — defaulting to `GET` would turn a
/// `PUT` whose precondition failed into "your copy is current", which is the
/// opposite of what happened.
///
/// `etag` and `modified` are what the server holds right now; `present` is
/// whether it holds anything at all, which is the whole of what `*` asks about.
pub fn Ask::evaluate(
  self : Ask,
  verb~ : String,
  etag? : Tag,
  modified? : @moondate.Moment,
  present? : Bool = true,
) -> Verdict {
  let reading = verb == "GET" || verb == "HEAD"
  match self.matching {
    Some(matching) => if !matches(matching, etag, present) { return Failed }
    None =>
      match self.unmodified_since {
        Some(since) => if changed(modified, since) { return Failed }
        None => ()
      }
  }
  match self.none_matching {
    Some(none_matching) =>
      if matches_weakly(none_matching, etag, present) {
        return if reading { Fresh } else { Failed }
      }
    None =>
      if reading {
        match self.modified_since {
          Some(since) => if !changed(modified, since) { return Fresh }
          None => ()
        }
      }
  }
  Go
}

///|
/// Whether `If-Range` still holds, and so whether a `Range` may be honoured
/// (§13.1.5).
///
/// An absent `If-Range` holds: a client that stated no condition put nothing in
/// the way of the range it asked for.
///
/// Both kinds compare strongly. A weak tag is refused outright rather than
/// compared, because the question `If-Range` asks — may these octets be spliced
/// onto the ones you already have — is exactly the one a weak tag may not
/// answer.
pub fn Ask::unchanged(
  self : Ask,
  etag? : Tag,
  modified? : @moondate.Moment,
) -> Bool {
  match self.ranging {
    None => true
    Some(Marked(given)) =>
      match etag {
        Some(etag) => given.same(etag)
        None => false
      }
    Some(Dated(given)) =>
      match (modified.bind(fn(m) { m.epoch() }), given.epoch()) {
        (Some(ours), Some(theirs)) => ours == theirs
        _ => false
      }
  }
}

///|
/// `If-Match` (§13.1.1): `*` asks whether anything is there; a list asks whether
/// one of its members is the strong equal of what is there.
fn matches(tags : Tags, etag : Tag?, present : Bool) -> Bool {
  match (tags, etag) {
    (Any, _) => present
    (These(_), None) => false
    (These(tags), Some(etag)) => {
      for tag in tags {
        if tag.same(etag) {
          return true
        }
      }
      false
    }
  }
}

///|
/// `If-None-Match` (§13.1.2), answered the way round the field is named: true
/// here means one of them matched, which is what makes the condition fail.
fn matches_weakly(tags : Tags, etag : Tag?, present : Bool) -> Bool {
  match (tags, etag) {
    (Any, _) => present
    (These(_), None) => false
    (These(tags), Some(etag)) => {
      for tag in tags {
        if tag.alike(etag) {
          return true
        }
      }
      false
    }
  }
}

///|
/// Whether the representation changed after `since` (§13.1.3, §13.1.4).
///
/// Unknown counts as changed: without a last-modified date neither field can be
/// made false, and the request goes through as if it had not been asked. Both
/// sections are written that way round — they say when the condition is false,
/// and say nothing about a representation that has no date.
fn changed(modified : @moondate.Moment?, since : @moondate.Moment) -> Bool {
  match (modified.bind(fn(m) { m.epoch() }), since.epoch()) {
    (Some(ours), Some(theirs)) => ours > theirs
    _ => true
  }
}

// ------------------------------------------------------------------ plumbing

///|
fn trim(text : StringView) -> StringView {
  let mut lo = 0
  let mut hi = text.length()
  while lo < hi && space(text[lo].to_int()) {
    lo += 1
  }
  while hi > lo && space(text[hi - 1].to_int()) {
    hi -= 1
  }
  text[lo:hi]
}

///|
fn space(c : Int) -> Bool {
  c == 0x20 || c == 0x09
}

///|
fn lower(text : String) -> String {
  let out = StringBuilder()
  for i = 0; i < text.length(); i = i + 1 {
    let b = text[i].to_int()
    if b >= 0x41 && b <= 0x5A {
      out.write_char((b + 32).unsafe_to_char())
    } else {
      out.write_char(b.unsafe_to_char())
    }
  }
  out.to_string()
}
