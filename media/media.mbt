// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What a response says it is when nothing says otherwise.
///
/// `application/octet-stream` is what RFC 9110 §8.3 names for "some bytes, and I
/// am not going to guess" — a browser offers to save it rather than trying to
/// render it, which is the safe answer for content of unknown shape.
pub let fallback : String = "application/octet-stream"

///|
/// The media type a filename's extension implies.
///
/// Deliberately short. This labels the downloads that actually occur; it is not
/// a copy of the IANA registry, and a caller that knows the type names it rather
/// than hoping the extension does.
///
/// The text types carry `charset=utf-8`, because a browser handed `text/plain`
/// with no charset applies its own locale's and shows something else.
pub fn type_of(filename : StringView) -> String {
  let lower = filename.to_lower()
  let mut dot = -1
  for i = 0; i < lower.length(); i = i + 1 {
    if lower[i] == '.' {
      dot = i
    }
  }
  if dot < 0 {
    return fallback
  }
  match lower[dot + 1:].to_owned() {
    "txt" | "text" | "log" => "text/plain; charset=utf-8"
    "html" | "htm" => "text/html; charset=utf-8"
    "css" => "text/css; charset=utf-8"
    "csv" => "text/csv; charset=utf-8"
    "md" => "text/markdown; charset=utf-8"
    "js" | "mjs" => "text/javascript; charset=utf-8"
    "json" => "application/json"
    "xml" => "application/xml"
    "yaml" | "yml" => "application/yaml"
    "pdf" => "application/pdf"
    "zip" => "application/zip"
    "gz" => "application/gzip"
    "wasm" => "application/wasm"
    "png" => "image/png"
    "jpg" | "jpeg" => "image/jpeg"
    "gif" => "image/gif"
    "webp" => "image/webp"
    "svg" => "image/svg+xml"
    "ico" => "image/vnd.microsoft.icon"
    "woff" => "font/woff"
    "woff2" => "font/woff2"
    "mp3" => "audio/mpeg"
    "mp4" => "video/mp4"
    _ => fallback
  }
}

///|
/// The `Content-Disposition` value naming `filename` (RFC 6266).
///
/// A name that survives percent-encoding unchanged is quoted as it is; anything
/// else — a space, an accent, a quote, a newline — goes out as `filename*`,
/// which is the only form that can carry a character outside ASCII and the only
/// one that cannot be made to end the header early.
///
/// `inline` asks the browser to display the content rather than save it, which
/// is what a PDF or an image served for viewing wants.
pub fn disposition(filename : StringView, inline? : Bool = false) -> String {
  let kind = if inline { "inline" } else { "attachment" }
  let quoted = @mime.percent_encode(filename, safe="/")
  if quoted == filename.to_owned() {
    kind + "; filename=\"" + filename.to_owned() + "\""
  } else {
    kind + "; filename*=utf-8''" + quoted
  }
}
