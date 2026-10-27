// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A request method (RFC 9110 §9.1). The eight of RFC 9110 and PATCH (RFC 5789)
/// have their own constructors; any other token is `Other`.
///
/// Method names are case-sensitive, so `get` is an extension method and not
/// `Get`. Build a method from its name with `Method::of`, which picks the
/// constructor: `Other("GET")` written by hand is not equal to `Get`.
pub(all) enum Method {
  Get
  Head
  Post
  Put
  Delete
  Connect
  Options
  Trace
  Patch
  Other(String)
} derive(Eq, Debug)

///|
pub extend Method with Eq::{equal, not_equal}

///|
pub extend Method with Debug::{to_repr}

///|
/// Why a name is not a method.
pub(all) suberror Refused {
  /// Empty, or holding a character outside `tchar` (RFC 9110 §5.6.2).
  Token(String)
} derive(Eq, Debug)

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
fn tchar(c : Char) -> Bool {
  match c {
    'a'..<='z' | 'A'..<='Z' | '0'..<='9' => true
    '!'
    | '#'
    | '$'
    | '%'
    | '&'
    | '\''
    | '*'
    | '+'
    | '-'
    | '.'
    | '^'
    | '_'
    | '`'
    | '|'
    | '~' => true
    _ => false
  }
}

///|
/// The method named `name`.
pub fn Method::of(name : StringView) -> Method raise Refused {
  match name {
    "GET" => Get
    "HEAD" => Head
    "POST" => Post
    "PUT" => Put
    "DELETE" => Delete
    "CONNECT" => Connect
    "OPTIONS" => Options
    "TRACE" => Trace
    "PATCH" => Patch
    _ => {
      if name.is_empty() || !name.iter().all(tchar) {
        raise Token(name.to_owned())
      }
      Other(name.to_owned())
    }
  }
}

///|
/// The name sent on the request line or in `:method`.
pub fn Method::name(self : Method) -> String {
  match self {
    Get => "GET"
    Head => "HEAD"
    Post => "POST"
    Put => "PUT"
    Delete => "DELETE"
    Connect => "CONNECT"
    Options => "OPTIONS"
    Trace => "TRACE"
    Patch => "PATCH"
    Other(name) => name
  }
}

///|
/// Whether the method is read-only (RFC 9110 §9.2.1), so a crawler, a prefetch
/// or a cache may send it without the user asking. An extension method is not
/// assumed safe.
pub fn Method::is_safe(self : Method) -> Bool {
  self is (Get | Head | Options | Trace)
}

///|
/// Whether sending the request twice has the effect of sending it once (RFC 9110
/// §9.2.2), so a client may retry it after a connection fails before the
/// response arrives. An extension method is not assumed idempotent.
pub fn Method::is_idempotent(self : Method) -> Bool {
  self.is_safe() || self is (Put | Delete)
}
