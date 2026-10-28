// The small text helpers the two fields here share: splitting a list without
// breaking a quoted member, trimming the whitespace a field value may carry, and
// the ASCII case folding §5.1 asks for.

///|
/// Split on `sep`, but not inside a quoted string: both `Location` and `Alt-Svc`
/// carry quoted strings that may hold the separator.
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
/// A quoted-string's contents, with its quoted-pairs resolved (§5.6.4).
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
