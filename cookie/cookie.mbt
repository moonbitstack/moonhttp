// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How far a cross-site request may carry a cookie.
///
/// `Strict` sends it only on a same-site request, `Lax` also on a top-level
/// navigation, and `Unrestricted` sends it everywhere. `Unrestricted` is the wire
/// value `None`, spelled differently here because `None` is the empty option; a
/// browser honours it only on a `Secure` cookie.
pub(all) enum SameSite {
  Strict
  Lax
  Unrestricted
} derive(Eq, Debug)

///|
pub extend SameSite with Eq::{equal, not_equal}

///|
pub extend SameSite with Debug::{to_repr}

///|
/// The attribute's wire spelling.
pub fn SameSite::code(self : SameSite) -> String {
  match self {
    Strict => "Strict"
    Lax => "Lax"
    Unrestricted => "None"
  }
}

///|
/// The attribute a spelling names, or `None` for one no revision defines.
///
/// The comparison ignores case, as §5.2 says to do with every attribute value.
pub fn SameSite::of(text : StringView) -> SameSite? {
  match lower(text) {
    "strict" => Some(Strict)
    "lax" => Some(Lax)
    "none" => Some(Unrestricted)
    _ => None
  }
}

///|
/// One cookie, as `Set-Cookie` states it.
///
/// An attribute left `None` is left out of the header, and means what leaving it
/// out means: no `Expires` and no `Max-Age` is a session cookie, no `Domain` is
/// the origin host alone, no `Path` is the request's own directory.
pub(all) struct Cookie {
  name : String
  value : String
  /// When the cookie dies, written as the HTTP-date `Expires` carries.
  expires : @moondate.Moment?
  /// How long it lives, in seconds. A browser that understands it prefers it to
  /// `Expires`, which is why a deletion writes both.
  max_age : Int?
  domain : String?
  path : String?
  secure : Bool
  http_only : Bool
  same_site : SameSite?
} derive(Eq, Debug)

///|
pub extend Cookie with Eq::{equal, not_equal}

///|
pub extend Cookie with Debug::{to_repr}

///|
/// A cookie by name, with the defaults a server usually wants.
///
/// `path` defaults to `/`, so the cookie covers the whole site, and `same_site` to
/// `Lax`, which is what a browser assumes of a cookie that does not say — and what
/// stops a cross-site form post from carrying a session. Passing `None` for either
/// leaves the attribute out.
pub fn Cookie::new(
  name : String,
  value : String,
  expires? : @moondate.Moment,
  max_age? : Int,
  domain? : String,
  path? : String? = Some("/"),
  secure? : Bool = false,
  http_only? : Bool = false,
  same_site? : SameSite? = Some(Lax),
) -> Cookie {
  { name, value, expires, max_age, domain, path, secure, http_only, same_site, }
}

///|
/// The `Set-Cookie` field value this cookie is sent as.
///
/// Attributes come in RFC 6265 §4.1.1's order, which is the order a browser and a
/// log reader expect. The octets a name, value, domain or path may not carry are
/// dropped rather than escaped: what a reader gets back is then the text that was
/// set, and a `\r\n` smuggled into a value cannot open a header of its own.
///
/// An `expires` that is a time with no date aborts: a cookie cannot die at a
/// clock reading, and a caller that built one has made a mistake rather than met
/// a condition.
pub fn Cookie::encode(self : Cookie) -> String {
  let out = StringBuilder()
  out.write_string(safe(self.name[:]))
  out.write_char('=')
  out.write_string(safe(self.value[:]))
  match self.expires {
    Some(moment) => {
      out.write_string("; Expires=")
      out.write_string(
        moment.http_text() catch {
          _ => abort("a cookie cannot expire at a time with no date")
        },
      )
    }
    None => ()
  }
  match self.max_age {
    Some(seconds) => {
      out.write_string("; Max-Age=")
      out.write_string(seconds.to_string())
    }
    None => ()
  }
  match self.domain {
    Some(domain) => {
      out.write_string("; Domain=")
      out.write_string(safe(domain[:]))
    }
    None => ()
  }
  match self.path {
    Some(path) => {
      out.write_string("; Path=")
      out.write_string(safe(path[:]))
    }
    None => ()
  }
  if self.secure {
    out.write_string("; Secure")
  }
  if self.http_only {
    out.write_string("; HttpOnly")
  }
  match self.same_site {
    Some(same_site) => {
      out.write_string("; SameSite=")
      out.write_string(same_site.code())
    }
    None => ()
  }
  out.to_string()
}

///|
/// The cookie a `Set-Cookie` field value states, or `None` when it states none —
/// an empty field, or one whose first pair has no `=`.
///
/// Everything §5.2 says to ignore is ignored rather than refused: an attribute no
/// revision defines, an `Expires` that is not a date, a `Max-Age` that is not a
/// number. A server sends what it sends, and a client that refused the header
/// would lose the cookie over an attribute it does not even use.
pub fn Cookie::decode(raw : StringView) -> Cookie? {
  let pieces = split(raw, ';')
  if pieces.length() == 0 {
    return None
  }
  let (name, value) = match pair(pieces[0][:]) {
    Some(pair) => pair
    None => return None
  }
  let mut expires : @moondate.Moment? = None
  let mut max_age : Int? = None
  let mut domain : String? = None
  let mut path : String? = None
  let mut secure = false
  let mut http_only = false
  let mut same_site : SameSite? = None
  for i = 1; i < pieces.length(); i = i + 1 {
    let piece = pieces[i]
    let (key, text) = match pair(piece[:]) {
      Some((key, text)) => (lower(key[:]), text)
      // An attribute with no `=` is a flag.
      None => (lower(trim(piece[:])), "")
    }
    match key {
      "expires" => expires = Some(@moondate.http(text[:])) catch { _ => None }
      "max-age" =>
        max_age = Some(@string.parse_int(text[:])) catch { _ => None }
      "domain" =>
        // A leading dot is how RFC 2109 wrote a domain and §5.2.3 says to drop it.
        domain = Some(
          if text.has_prefix(".") {
            text[1:].to_owned()
          } else {
            text
          },
        )
      "path" => path = Some(text)
      "secure" => secure = true
      "httponly" => http_only = true
      "samesite" => same_site = SameSite::of(text[:])
      _ => ()
    }
  }
  Some({
    name,
    value,
    expires,
    max_age,
    domain,
    path,
    secure,
    http_only,
    same_site,
  })
}

///|
/// The `Cookie` field value that sends these pairs, which is what a client writes
/// back from what it was set.
///
/// The header carries names and values and no attributes at all: those were the
/// server's instructions to the client, not something the client repeats.
pub fn encode(items : ArrayView[(String, String)]) -> String {
  let out = StringBuilder()
  for i = 0; i < items.length(); i = i + 1 {
    if i > 0 {
      out.write_string("; ")
    }
    out.write_string(safe(items[i].0[:]))
    out.write_char('=')
    out.write_string(safe(items[i].1[:]))
  }
  out.to_string()
}

///|
/// The pairs a `Cookie` field value carries, in the order they arrived.
///
/// A piece with no `=` is dropped rather than read as a name with no value, which
/// is what §5.4 leaves a server free to do and what every server does. Duplicate
/// names are kept: which one wins is the reader's decision, and [`get`] makes the
/// one browsers make.
pub fn decode(raw : StringView) -> Array[(String, String)] {
  let out : Array[(String, String)] = []
  for piece in split(raw, ';') {
    match pair(piece[:]) {
      Some(pair) => out.push(pair)
      None => ()
    }
  }
  out
}

///|
/// The value of the cookie named `name` in a `Cookie` field value, or `None`.
///
/// The first of a repeated name wins, which is the value a browser sends first
/// and the one every server library reads.
pub fn get(raw : StringView, name : StringView) -> String? {
  let want = name.to_owned()
  for piece in split(raw, ';') {
    match pair(piece[:]) {
      Some((key, value)) => if key == want { return Some(value) }
      None => ()
    }
  }
  None
}

// ------------------------------------------------------------------- the pieces

///|
/// One `name=value`, or `None` when the piece has no `=`.
///
/// The spaces around the name and around the value belong to the separators, not
/// to either: a space is not a cookie-octet, so one that arrives around a value
/// was written by whoever laid the header out.
fn pair(piece : StringView) -> (String, String)? {
  let text = trim(piece)
  for i = 0; i < text.length(); i = i + 1 {
    if text[i] == '=' {
      return Some((trim(text[0:i]), trim(text[i + 1:])))
    }
  }
  None
}

///|
/// `s` split on `sep`, every piece kept as written.
fn split(s : StringView, sep : Char) -> Array[String] {
  let out : Array[String] = []
  let piece = StringBuilder()
  for c in s {
    if c == sep {
      out.push(piece.to_string())
      piece.reset()
    } else {
      piece.write_char(c)
    }
  }
  out.push(piece.to_string())
  out
}

///|
/// `s` without its leading and trailing spaces and tabs.
fn trim(s : StringView) -> String {
  let mut from = 0
  let mut upto = s.length()
  while from < upto && (s[from] == ' ' || s[from] == '\t') {
    from = from + 1
  }
  while upto > from && (s[upto - 1] == ' ' || s[upto - 1] == '\t') {
    upto = upto - 1
  }
  s[from:upto].to_owned()
}

///|
/// `s` in lowercase, for the attribute names and values §5.2 compares case-blind.
fn lower(s : StringView) -> String {
  let out = StringBuilder()
  for c in s {
    let code = c.to_int()
    out.write_char(
      if code >= 0x41 && code <= 0x5A {
        (code + 32).unsafe_to_char()
      } else {
        c
      },
    )
  }
  out.to_string()
}

///|
/// `s` without the octets a cookie-octet may not be: RFC 6265 §4.1.1 allows the
/// printable ASCII other than space, `"`, `,`, `;` and `\`.
///
/// Dropped, not escaped, because an escape the writer applies and the reader does
/// not know about is worse than a character that never survives.
fn safe(s : StringView) -> String {
  let out = StringBuilder()
  for c in s {
    let code = c.to_int()
    if code > 0x20 &&
      code < 0x7F &&
      code != 0x22 &&
      code != 0x2C &&
      code != 0x3B &&
      code != 0x5C {
      out.write_char(c)
    }
  }
  out.to_string()
}
