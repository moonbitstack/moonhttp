// The small text helpers every field in this package needs: splitting a list
// without breaking a quoted argument, trimming the whitespace a field value may
// carry, and comparing tokens the way §5.1 says to.

///|
/// Split on `sep`, but not inside a quoted string: a directive's argument may be
/// quoted, and a quoted argument may hold the separator (§5.6.4).
fn pieces(text : String, sep : Char) -> Array[String] {
  let out : Array[String] = []
  let mut buf = StringBuilder()
  let mut quoted = false
  for c in text {
    if c == '"' {
      quoted = !quoted
      buf.write_char(c)
    } else if c == sep && !quoted {
      out.push(buf.to_string())
      buf = StringBuilder()
    } else {
      buf.write_char(c)
    }
  }
  out.push(buf.to_string())
  out
}

///|
fn trim(text : String) -> String {
  let mut start = 0
  let mut end = text.length()
  while start < end && (text[start] == ' ' || text[start] == '\t') {
    start += 1
  }
  while end > start && (text[end - 1] == ' ' || text[end - 1] == '\t') {
    end -= 1
  }
  text[start:end].to_owned()
}

///|
fn unquote(text : String) -> String {
  if text.length() >= 2 && text[0] == '"' && text[text.length() - 1] == '"' {
    let inner = StringBuilder()
    let mut i = 1
    while i < text.length() - 1 {
      if text[i] == '\\' && i + 1 < text.length() - 1 {
        inner.write_char(text[i + 1].unsafe_to_char())
        i += 2
      } else {
        inner.write_char(text[i].unsafe_to_char())
        i += 1
      }
    }
    inner.to_string()
  } else {
    text
  }
}

///|
fn lower(text : String) -> String {
  let out = StringBuilder()
  for c in text {
    let n = c.to_int()
    out.write_char(
      if n >= 0x41 && n <= 0x5a {
        (n + 32).unsafe_to_char()
      } else {
        c
      },
    )
  }
  out.to_string()
}

///|
fn join(items : Array[String], sep : String) -> String {
  let out = StringBuilder()
  for i in 0..<items.length() {
    if i > 0 {
      out.write_string(sep)
    }
    out.write_string(items[i])
  }
  out.to_string()
}
