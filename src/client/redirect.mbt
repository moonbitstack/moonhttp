// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How many redirects a request may follow before it is a loop by another name.
///
/// Twenty, which is where Chrome and Firefox stop and what curl's own default is
/// well above. A chain longer than this is a server that cannot make up its mind,
/// and following it only costs the client the requests.
pub let hops : Int32 = 20

///|
/// What following a redirect comes to (RFC 9110 §15.4).
///
/// The four answers a client needs, in one place: where to go, with which method,
/// with or without the body that was sent, and which of the fields it was going to
/// send must be dropped on the way.
pub(all) struct Follow {
  /// The target, resolved against the request that was redirected.
  url : @moonurl.Url
  /// The method to send it with — rewritten where §15.4 rewrites it.
  verb : @method.Method
  /// Whether the body goes with it. A body that was dropped is not resent.
  body : Bool
  /// Field names to drop before sending, lowercased. Empty when the origin did
  /// not change.
  strip : Array[String]
} derive(Eq, Debug)

///|
pub extend Follow with Eq::{equal, not_equal}

///|
pub extend Follow with Debug::{to_repr}

///|
/// Why a redirect was not followed.
pub(all) suberror Refused {
  /// The status is not one a client follows: a 304, a 300 it would have to choose
  /// from, or something that is not a 3xx at all.
  NotARedirect(status~ : Int32)
  /// `Location` is missing, empty, or not a URI reference this client can parse.
  Location(got~ : String)
  /// The target is one this request has already been to (§15.4).
  Loop(at~ : Int32)
  /// More hops than `hops`, or the caller's own ceiling.
  TooMany(limit~ : Int32, got~ : Int32)
  /// The method and the body both have to be resent, and the body cannot be.
  Replay(String)
} derive(Eq, Debug)

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
/// A refusal prints as the fault it is.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    NotARedirect(status~) =>
      logger.write_string("NotARedirect(status=\{status})")
    Location(got~) => logger.write_string("Location(got=" + got + ")")
    Loop(at~) => logger.write_string("Loop(at=\{at})")
    TooMany(limit~, got~) =>
      logger.write_string("TooMany(limit=\{limit}, got=\{got})")
    Replay(m) => logger.write_string("Replay(" + m + ")")
  }
}

///|
pub extend Refused with Show::{to_string, output}

///|
/// Where a 3xx sends the next request, and how that request differs from the one
/// that was redirected (RFC 9110 §15.4).
///
/// `visited` is the chain so far, oldest first, and answers two questions at once:
/// whether this redirect goes somewhere the chain has already been — a loop — and
/// whether the chain is longer than `hops`. A caller with no chain to speak of
/// passes the request it just sent.
///
/// The method rewrite is the part that gets argued about. §15.4.2 and §15.4.3 make
/// changing a `POST` to a `GET` a MAY, for historical reasons, and every browser
/// takes it; §15.4.4 makes it a MUST for a 303, and §15.4.8 and §15.4.9 forbid it
/// for a 307 and a 308, which exist precisely to keep the method and the body. So
/// this does what the browsers do, and `replay` is how a caller whose body was a
/// stream rather than bytes says it cannot send it twice: a 307 that would have to
/// resend one is refused rather than turned into an empty `PUT`.
pub fn follow(
  status~ : Int32,
  location~ : String,
  from~ : @moonurl.Url,
  verb~ : @method.Method,
  visited~ : ArrayView[@moonurl.Url],
  body~ : Bool = false,
  replay~ : Bool = true,
  limit~ : Int32 = hops,
) -> Follow raise Refused {
  match status {
    301 | 302 | 303 | 307 | 308 => ()
    _ => raise NotARedirect(status~)
  }
  // §15.4.4: a 303 answers "the result is over there", so the method becomes GET
  // for everything but a HEAD, which is already a GET without the body.
  let rewrite = match status {
    303 =>
      match verb {
        @method.Method::Head => false
        _ => true
      }
    301 | 302 =>
      // §15.4.2, §15.4.3: the historical rewrite, for a POST and nothing else.
      match verb {
        @method.Method::Post => true
        _ => false
      }
    _ => false
  }
  if visited.length() >= limit {
    raise TooMany(limit~, got=visited.length() + 1)
  }
  let text = trim(location)
  if text.length() == 0 {
    raise Location(got=location)
  }
  let target = @moonurl.Url::decode(text[:]) catch {
    _ => raise Location(got=location)
  }
  let url = from.resolve(target)
  let next_verb = if rewrite { @method.Method::Get } else { verb }
  let send_body = body && !rewrite
  if send_body && !replay {
    raise Replay(
      "§15.4.8 keeps the method and the body; this one cannot be resent",
    )
  }
  // A loop is the same target twice, however it was written: the key is the five
  // parts §4.3.1 of RFC 9110 makes an origin and a target, not the string.
  let wanted = key(url)
  for i in 0..<visited.length() {
    if key(visited[i]) == wanted {
      raise Loop(at=i)
    }
  }
  // §15.4: a redirect to another origin is where credentials stop being sent,
  // because the origin they were meant for is not the one asking for them.
  let strip : Array[String] = if same_origin(from, url) {
    []
  } else {
    ["authorization", "cookie", "proxy-authorization"]
  }
  { url, verb: next_verb, body: send_body, strip, }
}

///|
/// Whether two URLs name the same origin (§4.3.1 of RFC 9110): scheme, host and
/// port, with the scheme's default port standing in for an absent one.
///
/// The comparison is the one §15.4 turns on. `https://example.com` and
/// `https://example.com:443/` are one origin; `http://example.com` and
/// `https://example.com` are not, and neither is a different host on the same
/// port.
pub fn same_origin(a : @moonurl.Url, b : @moonurl.Url) -> Bool {
  let scheme_a = lower(a.scheme.unwrap_or(""))
  let scheme_b = lower(b.scheme.unwrap_or(""))
  if scheme_a != scheme_b {
    return false
  }
  if lower(a.host.unwrap_or("")) != lower(b.host.unwrap_or("")) {
    return false
  }
  port(a) == port(b)
}

///|
/// What makes two URLs the same target for a loop check: the origin and the path,
/// with the default port written the same way whether it was named or not.
fn key(url : @moonurl.Url) -> String {
  let out = StringBuilder()
  out.write_string(lower(url.scheme.unwrap_or("")))
  out.write_string("://")
  out.write_string(lower(url.host.unwrap_or("")))
  out.write_string(":")
  out.write_string(port(url).to_string())
  out.write_string(url.path)
  match url.query {
    Some(query) => out.write_string("?" + query)
    None => ()
  }
  out.to_string()
}

///|
/// The port a URL names, with the scheme's own default where it names none.
fn port(url : @moonurl.Url) -> Int32 {
  match url.port {
    Some(port) => port
    None =>
      match lower(url.scheme.unwrap_or("")) {
        "http" => 80
        "https" => 443
        _ => 0
      }
  }
}

///|
/// The `Location` of a response, if it had a usable one.
pub fn location(headers : ArrayView[(String, String)]) -> String? {
  for (name, value) in headers {
    if lower(name) == "location" {
      return Some(trim(value))
    }
  }
  None
}
