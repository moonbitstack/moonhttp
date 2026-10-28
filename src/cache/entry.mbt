// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What a cache holds of a response, read off the fields that decide what may be
/// done with it (RFC 9111 §3 to §4).
///
/// A stored response is not the message; it is the fields a decision is made from,
/// which is why this type exists at all. The octets are the caller's, and this
/// package never sees them: where a cache keeps a body and how it evicts one is a
/// store, and there is no store here.
pub(all) struct Entry {
  status : Int32
  control : Control
  /// `Date` (§6.6.1 of RFC 9110): when the origin says it generated the response.
  date : @moondate.Moment?
  /// `Age` (§5.1): how long the response had already been in caches before it
  /// arrived here.
  age : Int32?
  /// `Expires` (§5.3), the older way of saying when the response stops being fresh.
  expires : @moondate.Moment?
  /// `Last-Modified`, which is both a validator and the input to a heuristic
  /// freshness lifetime (§4.2.2).
  last_modified : @moondate.Moment?
  /// `ETag`, the validator a conditional request repeats (§8.8.3 of RFC 9110).
  etag : @conditional.Tag?
  /// The field names `Vary` nominates (§4.1), lowercased.
  vary : Array[String]
  /// Those fields' values in the request that produced the response, which is
  /// what a later request has to match.
  selects : Array[(String, String)]
  /// When the request that produced this was sent — `request_time` in §4.2.3.
  sent : @moondate.Moment
  /// When the response arrived — `response_time` in §4.2.3.
  received : @moondate.Moment
} derive(Eq, Debug)

///|
pub extend Entry with Eq::{equal, not_equal}

///|
pub extend Entry with Debug::{to_repr}

///|
/// What a cache may do with a stored response for a request it has been given
/// (§4).
pub(all) enum Verdict {
  /// Answer from the store, with an `Age` field (§4).
  Serve
  /// Ask the origin whether the stored response is still the one it holds, with
  /// the validators from `Entry::conditional` (§4.3.1).
  Validate
  /// The stored response cannot answer this request: fetch it, or fail it.
  Miss
} derive(Eq, Debug)

///|
pub extend Verdict with Eq::{equal, not_equal}

///|
pub extend Verdict with Debug::{to_repr}

///|
/// The status codes §4.2.2 calls heuristically cacheable — "cacheable by default"
/// in the older specs — with the meaning RFC 9110 §15.1 gives each.
///
/// They are the ones an origin is assumed to have meant as reusable when it said
/// nothing: a 200 or a 404, not a 302 that might have been meant as temporary
/// routing.
pub fn heuristically_cacheable(status : Int32) -> Bool {
  match status {
    200 | 203 | 204 | 206 | 300 | 301 | 308 | 404 | 405 | 410 | 414 | 501 =>
      true
    _ => false
  }
}

///|
/// Read the fields that decide what may be done with a response.
///
/// `request` is the header list that produced it, which `Vary` makes part of the
/// stored state: what a later request must match is what this one sent in the
/// fields the response nominated (§4.1).
pub fn Entry::read(
  status~ : Int32,
  headers~ : ArrayView[(String, String)],
  request~ : ArrayView[(String, String)],
  sent~ : @moondate.Moment,
  received~ : @moondate.Moment,
) -> Entry {
  let control = Control::of(headers)
  let vary = match find(headers, "vary") {
    Some(value) => names(value)
    None => []
  }
  let selects : Array[(String, String)] = []
  for name in vary {
    selects.push((name, find(request, name).unwrap_or("")))
  }
  {
    status,
    control,
    date: date(headers, "date"),
    age: match find(headers, "age") {
      Some(text) =>
        match digits(trim(text)) {
          Some(n) => Some(n)
          None => None
        }
      None => None
    },
    expires: date(headers, "expires"),
    last_modified: date(headers, "last-modified"),
    etag: match find(headers, "etag") {
      Some(text) =>
        match @conditional.Tag::decode(trim(text)[:]) {
          Some(tag) => Some(tag)
          None => None
        }
      None => None
    },
    vary,
    selects,
    sent,
    received,
  }
}

///|
/// The freshness lifetime in seconds, as §4.2.1 computes it, or `None` when the
/// response carries no explicit expiration time.
///
/// The rules are tried in the order the section gives them: `s-maxage` for a
/// shared cache, then `max-age`, then `Expires` minus `Date`. `Date` is the time
/// the message was received when the origin did not send one (§6.6.1 of
/// RFC 9110).
pub fn Entry::lifetime(self : Entry, shared~ : Bool = false) -> Int32? {
  if shared {
    match self.control.s_maxage {
      Some(n) => return Some(n)
      None => ()
    }
  }
  match self.control.max_age {
    Some(n) => return Some(n)
    None => ()
  }
  match self.expires {
    Some(expires) => {
      let from = match self.date {
        Some(date) => date
        None => self.received
      }
      Some(seconds(expires, from))
    }
    None => None
  }
}

///|
/// The freshness lifetime §4.2.2 would guess, or `None` when no guess is allowed.
///
/// A guess needs a `Last-Modified` to measure from and a response the specification
/// says may be guessed at: one whose status is heuristically cacheable, or one the
/// origin marked `public`. The fraction is the usual 10% of the age of the
/// representation when it arrived — the number the section suggests, and the one
/// browsers and squid settled on.
pub fn Entry::heuristic(self : Entry, fraction~ : Int32 = 10) -> Int32? {
  // An explicit time is never second-guessed (§4.2.2), and the guess needs a
  // response it is allowed to guess at.
  if self.lifetime() is Some(_) {
    return None
  }
  if !heuristically_cacheable(self.status) && !self.control.public {
    return None
  }
  match self.last_modified {
    None => None
    Some(modified) => {
      let from = match self.date {
        Some(date) => date
        None => self.received
      }
      let age = seconds(from, modified)
      if age <= 0 {
        Some(0)
      } else {
        Some(age * fraction / 100)
      }
    }
  }
}

///|
/// The lifetime a decision uses: the explicit one when there is one, and the guess
/// only when there is not (§4.2.2 forbids guessing over an explicit time).
pub fn Entry::fresh_for(self : Entry, shared~ : Bool = false) -> Int32? {
  match self.lifetime(shared~) {
    Some(n) => Some(n)
    None => self.heuristic()
  }
}

///|
/// How old the stored response is now, in seconds (§4.2.3).
///
/// The conservative form of the calculation: the apparent age from `Date` and the
/// corrected age from `Age` plus the time the response spent in flight, whichever
/// is larger, plus the time it has sat here.
pub fn Entry::current_age(self : Entry, now~ : @moondate.Moment) -> Int32 {
  let date_value = match self.date {
    Some(date) => date
    None => self.received
  }
  let apparent = if seconds(self.received, date_value) > 0 {
    seconds(self.received, date_value)
  } else {
    0
  }
  let delay = if seconds(self.received, self.sent) > 0 {
    seconds(self.received, self.sent)
  } else {
    0
  }
  let corrected = self.age.unwrap_or(0) + delay
  let initial = if apparent > corrected { apparent } else { corrected }
  let resident = if seconds(now, self.received) > 0 {
    seconds(now, self.received)
  } else {
    0
  }
  initial + resident
}

///|
/// The `Age` field to send with a response served from the store (§4): the
/// current age, replacing whatever `Age` the stored message carried.
pub fn Entry::aged(self : Entry, now~ : @moondate.Moment) -> (String, String) {
  ("age", self.current_age(now~).to_string())
}

///|
/// Whether the stored response is still fresh (§4.2).
pub fn Entry::fresh(
  self : Entry,
  now~ : @moondate.Moment,
  shared~ : Bool = false,
) -> Bool {
  match self.fresh_for(shared~) {
    Some(lifetime) => self.current_age(now~) < lifetime
    None => false
  }
}

///|
/// Whether the response may be written down at all, by §3's list.
///
/// Every condition is a reason not to store, so this reads as the section does:
/// the method has to be one a cache here understands, the status final, `no-store`
/// absent, and something in the response has to say it may be kept — an explicit
/// lifetime, a `public`, or a status that is heuristically cacheable.
///
/// `understood` is whether this cache knows what the status code means, which is
/// what `must-understand` and a stored 206 or 304 turn on. `authorized` is whether
/// the request carried `Authorization`: a shared cache may not store such a
/// response unless one of the directives that says so is present (§3.5).
pub fn Entry::storable(
  self : Entry,
  verb~ : @method.Method,
  request~ : Control,
  shared~ : Bool = false,
  understood~ : Bool = true,
  authorized~ : Bool = false,
) -> Bool {
  let cached_method = match verb {
    @method.Method::Get | @method.Method::Head => true
    _ => false
  }
  if !cached_method {
    return false
  }
  // §3: the status has to be final, and a 206 or a 304 needs a cache that knows
  // what it means.
  if self.status < 200 {
    return false
  }
  if (self.status == 206 || self.status == 304) && !understood {
    return false
  }
  if self.control.must_understand && !understood {
    return false
  }
  // §5.2.2.3: a response with `must-understand` should also carry `no-store`, and
  // a cache that understands the status ignores it. Anything else obeys it.
  if self.control.no_store && !(self.control.must_understand && understood) {
    return false
  }
  if request.no_store {
    return false
  }
  if shared &&
    self.control.private_ &&
    self.control.private_fields.length() == 0 {
    return false
  }
  if shared && authorized {
    let allowed = self.control.public ||
      self.control.s_maxage is Some(_) ||
      self.control.must_revalidate
    if !allowed {
      return false
    }
  }
  self.control.public ||
  (self.control.private_ && !shared) ||
  self.expires is Some(_) ||
  self.control.max_age is Some(_) ||
  (shared && self.control.s_maxage is Some(_)) ||
  heuristically_cacheable(self.status)
}

///|
/// Whether a request's fields match the ones the stored response was selected by
/// (§4.1).
///
/// `*` in `Vary` means the response varied on something the field names cannot
/// say, and never matches: §4.1 has a cache treat it as not reusable.
pub fn Entry::vary_matches(
  self : Entry,
  headers : ArrayView[(String, String)],
) -> Bool {
  for (name, want) in self.selects {
    if name == "*" {
      return false
    }
    let got = match find(headers, name) {
      Some(value) => trim(value)
      None => ""
    }
    if got != want {
      return false
    }
  }
  true
}

///|
/// What to do with the stored response for this request (§4), which is the whole
/// of the reuse decision.
///
/// The order is the section's: the request has to match what was stored, then the
/// response has to be fresh — or allowed to be served stale — or be worth
/// validating. `connected` is whether the origin can be reached at all, because
/// `must-revalidate` turns a stale response into an error rather than a reuse when
/// it cannot (§5.2.2.2).
///
/// `stale-if-error` and `stale-while-revalidate` are not folded in here: both are
/// about a request that has already gone to the origin, so the caller applies them
/// once it knows how that went.
pub fn Entry::verdict(
  self : Entry,
  request~ : Control,
  presented~ : ArrayView[(String, String)],
  now~ : @moondate.Moment,
  shared~ : Bool = false,
  connected~ : Bool = true,
) -> Verdict {
  if !self.vary_matches(presented) {
    return Miss
  }
  let age = self.current_age(now~)
  let lifetime = self.fresh_for(shared~)
  let fresh = match lifetime {
    Some(lifetime) => age < lifetime
    None => false
  }
  if fresh {
    // §5.2.2.4: an unqualified `no-cache` response is validated before every use,
    // and §5.2.1.4 is the client asking for the same thing.
    if self.control.no_cache && self.control.no_cache_fields.length() == 0 {
      return Validate
    }
    if request.no_cache {
      return Validate
    }
    match request.min_fresh {
      Some(wanted) =>
        match lifetime {
          Some(lifetime) => if lifetime < age + wanted { return Validate }
          None => ()
        }
      None => ()
    }
    match request.max_age {
      Some(ceiling) => if age > ceiling { return Validate }
      None => ()
    }
    return Serve
  }
  // Stale. §4.2.4: a directive may forbid serving it, and without one the client
  // has to have said it will take it.
  let forbidden = self.control.no_cache ||
    self.control.must_revalidate ||
    (shared && self.control.proxy_revalidate) ||
    (shared && self.control.s_maxage is Some(_))
  if !forbidden && connected {
    match request.max_stale {
      Some(Any) => return Serve
      Some(Within(extra)) =>
        match lifetime {
          Some(lifetime) => if age <= lifetime + extra { return Serve }
          None => ()
        }
      None => ()
    }
  }
  if self.etag is Some(_) || self.last_modified is Some(_) {
    Validate
  } else {
    Miss
  }
}

///|
/// The fields that turn this request into a conditional one (§4.3.1), ready to be
/// added to the ones already going.
///
/// The entity tag goes in `If-None-Match` when there is one, and the timestamp in
/// `If-Modified-Since` too — the section notes that both are usually sent, so that
/// an intermediary that predates entity tags still answers usefully.
pub fn Entry::conditional(self : Entry) -> Array[(String, String)] {
  let out : Array[(String, String)] = []
  match self.etag {
    Some(tag) => out.push(("if-none-match", tag.encode()))
    None => ()
  }
  match self.last_modified {
    Some(when) => {
      let text = when.http_text() catch { _ => "" }
      if text.length() > 0 {
        out.push(("if-modified-since", text))
      }
    }
    None => ()
  }
  out
}

///|
/// The freshening a 304 does to a stored response (§4.3.4): the new response's
/// fields replace the stored ones, and the stored body stays.
///
/// Only the fields a 304 may carry are taken, because that is all a 304 has. The
/// clock starts again from the validation.
pub fn Entry::freshened(
  self : Entry,
  headers~ : ArrayView[(String, String)],
  received~ : @moondate.Moment,
) -> Entry {
  let fresh = Entry::read(
    status=self.status,
    headers~,
    request=[],
    sent=received,
    received~,
  )
  {
    ..self,
    control: fresh.control,
    date: either(fresh.date, self.date),
    expires: either(fresh.expires, self.expires),
    last_modified: either(fresh.last_modified, self.last_modified),
    etag: either(fresh.etag, self.etag),
    age: fresh.age,
    received,
    sent: received,
  }
}

// --------------------------------------------------------------- the fields

///|
/// The first field of that name, matched without regard to case (§5.1).
fn find(headers : ArrayView[(String, String)], name : String) -> String? {
  for (field, value) in headers {
    if lower(field) == name {
      return Some(value)
    }
  }
  None
}

///|
/// A date field, or `None` when it is absent or unreadable.
fn date(
  headers : ArrayView[(String, String)],
  name : String,
) -> @moondate.Moment? {
  match find(headers, name) {
    None => None
    Some(text) => Some(@moondate.http(trim(text)[:])) catch { _ => None }
  }
}

///|
/// The field names a `Vary` value lists, lowercased (§4.1).
fn names(value : String) -> Array[String] {
  let out : Array[String] = []
  for piece in value.split(",") {
    let one = lower(trim(piece.to_owned()))
    if one.length() > 0 {
      out.push(one)
    }
  }
  out
}

///|
/// The seconds between two instants, truncated towards zero — HTTP counts in whole
/// seconds everywhere it counts (§1.2.2).
fn seconds(later : @moondate.Moment, earlier : @moondate.Moment) -> Int32 {
  match later.diff(earlier) {
    Some(span) => span.seconds().to_int()
    None => 0
  }
}

///|
/// A `delta-seconds` value: digits only (§1.2.2).
fn digits(text : String) -> Int32? {
  if text.length() == 0 {
    return None
  }
  let mut out = 0
  for c in text {
    let digit = c.to_int() - 0x30
    if digit < 0 || digit > 9 {
      return None
    }
    if out < 0x7FFFFFF {
      out = out * 10 + digit
    }
  }
  Some(out)
}

///|
/// The first of two optional values that is there, which is how a 304's fields
/// replace a stored response's only where the 304 carried them.
fn[T] either(first : T?, second : T?) -> T? {
  match first {
    Some(value) => Some(value)
    None => second
  }
}
