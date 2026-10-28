// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// `max-stale`: how far past its freshness lifetime a client will still take a
/// response (RFC 9111 §5.2.1.2).
///
/// The directive may be written with no argument, which is what "any age at all"
/// needs a word for.
pub(all) enum Stale {
  /// No argument: a response of any age will do.
  Any
  /// At most this many seconds past the freshness lifetime.
  Within(Int32)
} derive(Eq, Debug)

///|
pub extend Stale with Eq::{equal, not_equal}

///|
pub extend Stale with Debug::{to_repr}

///|
/// A `Cache-Control` field, both sides of the exchange, as directives
/// (RFC 9111 §5.2).
///
/// One struct for the request and the response because the field is one field:
/// which directives mean anything depends on which side wrote it, and the same
/// name can mean two different things — a response's `max-age` is a freshness
/// lifetime, a request's is a ceiling on the age the client will accept. A reader
/// therefore reads both and a decision picks out what it needs.
///
/// Unknown directives are kept in `extensions` rather than dropped: §5.2.3 says to
/// ignore them, and a proxy that has to pass the field on unchanged needs them to
/// still be there.
pub(all) struct Control {
  /// `max-age` (§5.2.1.1, §5.2.2.1).
  max_age : Int32?
  /// `s-maxage`, which a shared cache uses instead of `max-age` (§5.2.2.10).
  s_maxage : Int32?
  /// `max-stale`, a request's willingness to take something stale (§5.2.1.2).
  max_stale : Stale?
  /// `min-fresh`, how much freshness a client insists on (§5.2.1.3).
  min_fresh : Int32?
  /// `no-cache`, on either side (§5.2.1.4, §5.2.2.4).
  no_cache : Bool
  /// The field names a qualified `no-cache` names, if it named any.
  no_cache_fields : Array[String]
  /// `no-store`, which stops a response being written down at all (§5.2.1.5).
  no_store : Bool
  /// `no-transform`, a request to leave the representation alone (§5.2.1.6).
  no_transform : Bool
  /// `only-if-cached`: answer from the store or not at all (§5.2.1.7).
  only_if_cached : Bool
  /// `must-revalidate`: once stale, validate or fail (§5.2.2.2).
  must_revalidate : Bool
  /// `must-understand`: only a cache that knows this status may store it
  /// (§5.2.2.3).
  must_understand : Bool
  /// `private`: a shared cache must not store it (§5.2.2.7).
  private_ : Bool
  /// The field names a qualified `private` names, if it named any.
  private_fields : Array[String]
  /// `proxy-revalidate`, the shared cache's half of `must-revalidate` (§5.2.2.8).
  proxy_revalidate : Bool
  /// `public`, which lets a shared cache store what it otherwise could not
  /// (§5.2.2.9).
  public : Bool
  /// `immutable`: the representation will not change while fresh (§5.2.2.12).
  immutable : Bool
  /// `stale-while-revalidate`, from RFC 5861, which this registry carries: serve
  /// stale for this long while the response is refreshed in the background.
  stale_while_revalidate : Int32?
  /// `stale-if-error`, also RFC 5861: serve stale when the origin fails.
  stale_if_error : Int32?
  /// Directives this reader did not recognize, in the order they appeared, with
  /// the argument each had.
  extensions : Array[(String, String?)]
} derive(Eq, Debug)

///|
pub extend Control with Eq::{equal, not_equal}

///|
pub extend Control with Debug::{to_repr}

///|
/// A `Cache-Control` with nothing in it, which is what a message without the field
/// carries.
pub let control : Control = {
  max_age: None,
  s_maxage: None,
  max_stale: None,
  min_fresh: None,
  no_cache: false,
  no_cache_fields: [],
  no_store: false,
  no_transform: false,
  only_if_cached: false,
  must_revalidate: false,
  must_understand: false,
  private_: false,
  private_fields: [],
  proxy_revalidate: false,
  public: false,
  immutable: false,
  stale_while_revalidate: None,
  stale_if_error: None,
  extensions: [],
}

///|
/// The directives of one `Cache-Control` value (§5.2).
///
/// Names match without regard to case, and an argument may be a token or a quoted
/// string — §5.2 says a recipient ought to accept either even where generation
/// favours one. An unknown directive is kept, and so is one whose argument does
/// not parse: a cache ignores what it cannot read, and §4.2.1 leans towards
/// treating invalid freshness information as stale, which is what a missing
/// `max-age` leaves.
///
/// A directive repeated is read from its first occurrence, which §4.2.1 allows as
/// an alternative to calling the response stale.
pub fn Control::decode(value : StringView) -> Control {
  let mut out = control
  let mut seen_max_age = false
  let mut seen_s_maxage = false
  let mut seen_max_stale = false
  let mut seen_min_fresh = false
  for piece in pieces(value.to_owned(), ',') {
    let piece = trim(piece)
    if piece.length() == 0 {
      continue
    }
    // §5.2's grammar puts no space around the equals sign, so one there makes the
    // directive one this reader does not know rather than one it reads.
    let (key, raw) = match piece.find("=") {
      Some(at) => (piece[:at].to_owned(), Some(piece[at + 1:].to_owned()))
      None => (piece, None)
    }
    let name = lower(key)
    let value = match raw {
      Some(text) => Some(unquote(text))
      None => None
    }
    match name {
      "max-age" =>
        if !seen_max_age {
          seen_max_age = true
          out = { ..out, max_age: number(value), }
        }
      "s-maxage" =>
        if !seen_s_maxage {
          seen_s_maxage = true
          out = { ..out, s_maxage: number(value), }
        }
      "max-stale" =>
        if !seen_max_stale {
          seen_max_stale = true
          out = {
            ..out,
            max_stale: match value {
              None => Some(Any)
              Some(text) =>
                match number(Some(text)) {
                  Some(n) => Some(Within(n))
                  None => None
                }
            },
          }
        }
      "min-fresh" =>
        if !seen_min_fresh {
          seen_min_fresh = true
          out = { ..out, min_fresh: number(value), }
        }
      "no-cache" =>
        out = { ..out, no_cache: true, no_cache_fields: fields(value), }
      "no-store" => out = { ..out, no_store: true, }
      "no-transform" => out = { ..out, no_transform: true, }
      "only-if-cached" => out = { ..out, only_if_cached: true, }
      "must-revalidate" => out = { ..out, must_revalidate: true, }
      "must-understand" => out = { ..out, must_understand: true, }
      "private" =>
        out = { ..out, private_: true, private_fields: fields(value), }
      "proxy-revalidate" => out = { ..out, proxy_revalidate: true, }
      "public" => out = { ..out, public: true, }
      "immutable" => out = { ..out, immutable: true, }
      "stale-while-revalidate" =>
        out = { ..out, stale_while_revalidate: number(value), }
      "stale-if-error" => out = { ..out, stale_if_error: number(value), }
      _ => out = { ..out, extensions: push(out.extensions, (key, value)), }
    }
  }
  out
}

///|
/// The field's directives as one value, with the directives it carries written in
/// the order §5.2 lists them and nothing written twice.
pub fn Control::encode(self : Control) -> String {
  let out : Array[String] = []
  for
    (name, value) in [
      ("max-age", self.max_age),
      ("s-maxage", self.s_maxage),
      ("min-fresh", self.min_fresh),
      ("stale-while-revalidate", self.stale_while_revalidate),
      ("stale-if-error", self.stale_if_error),
    ] {
    match value {
      Some(n) => out.push(name + "=" + n.to_string())
      None => ()
    }
  }
  match self.max_stale {
    Some(Any) => out.push("max-stale")
    Some(Within(n)) => out.push("max-stale=" + n.to_string())
    None => ()
  }
  if self.no_cache {
    out.push(qualify("no-cache", self.no_cache_fields))
  }
  for
    flag in [
      (self.no_store, "no-store"),
      (self.no_transform, "no-transform"),
      (self.only_if_cached, "only-if-cached"),
      (self.public, "public"),
      (self.must_revalidate, "must-revalidate"),
      (self.must_understand, "must-understand"),
      (self.proxy_revalidate, "proxy-revalidate"),
      (self.immutable, "immutable"),
    ] {
    let (on, name) = flag
    if on {
      out.push(name)
    }
  }
  if self.private_ {
    out.push(qualify("private", self.private_fields))
  }
  for (name, value) in self.extensions {
    out.push(
      match value {
        Some(text) => name + "=" + text
        None => name
      },
    )
  }
  join(out, ", ")
}

///|
/// A directive with the field names it qualifies, quoted the way §5.2's grammar
/// asks for: an argument that is a list of names is a quoted string.
fn qualify(name : String, fields : Array[String]) -> String {
  if fields.length() == 0 {
    name
  } else {
    name + "=\"" + join(fields, ", ") + "\""
  }
}

///|
/// The `Cache-Control` fields of a header list, as one set of directives (§5.3:
/// repeated fields are one comma-separated value).
pub fn Control::of(headers : ArrayView[(String, String)]) -> Control {
  let parts : Array[String] = []
  for (name, value) in headers {
    if lower(name) == "cache-control" {
      parts.push(value)
    }
  }
  Control::decode(join(parts, ", ")[:])
}

///|
/// The seconds a `delta-seconds` argument names, or `None` when it names nothing
/// that parses (§1.2.2): digits only, and a value too large to matter is capped
/// rather than wrapped.
fn number(value : String?) -> Int32? {
  match value {
    None => None
    Some(text) =>
      if text.length() == 0 {
        None
      } else {
        let mut out = 0
        let mut i = 0
        let mut ok = true
        while i < text.length() && ok {
          let digit = text[i].to_int() - 0x30
          if digit < 0 || digit > 9 {
            ok = false
          } else {
            if out < 0x7FFFFFF {
              out = out * 10 + digit
            }
            i += 1
          }
        }
        if ok {
          Some(out)
        } else {
          None
        }
      }
  }
}

///|
/// The field names in a qualified `no-cache` or `private` argument.
fn fields(value : String?) -> Array[String] {
  let out : Array[String] = []
  match value {
    None => ()
    Some(text) =>
      for piece in pieces(text, ',') {
        let one = trim(piece)
        if one.length() > 0 {
          out.push(lower(one))
        }
      }
  }
  out
}

///|
fn push(
  items : Array[(String, String?)],
  item : (String, String?),
) -> Array[(String, String?)] {
  let out = items.copy()
  out.push(item)
  out
}
