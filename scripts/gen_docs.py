#!/usr/bin/env python3
"""Generate docs/api.html — the reference — from the `///` comments above the
public items in each package.

Reproducible: it reads the .mbt files, so the page cannot drift from the code.
`docs/index.html`, `guide.html` and `protocols.html` are written by hand and are
not touched here.
"""
import re, html, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

# (anchor, source directory, section of the specification, one line about it)
PKGS = [
    ("form", "form", "WHATWG", "A request body read as the form its Content-Type says it is: multipart/form-data through moonmime, application/x-www-form-urlencoded through moonurl."),
    ("range", "range", "RFC 9110 §14", "Range requests: the fields, the arithmetic against a length, and the multi-range body."),
    ("conditional", "conditional", "RFC 9110 §13", "Entity-tags, the five precondition fields, and the order §13.2.2 weighs them in."),
    ("cookie", "cookie", "RFC 6265", "Cookie and Set-Cookie, each read and written."),
    ("cache", "cache", "RFC 9111", "Cache decisions: Cache-Control both sides, freshness, age, storability and reuse, and the conditional request a cache sends."),
    ("client", "client", "9110 §15.4 · 7838", "Redirection and Alt-Svc: where a response sends a client next, with which method, and which credentials stop at the origin."),
    ("sse", "sse", "WHATWG", "Server-Sent Events, framed both ways and dispatched the way an EventSource does."),
    ("ws", "ws", "RFC 6455 §5", "WebSocket framing: opcodes, masking, reassembly, close statuses."),
    ("pmd", "pmd", "RFC 7692", "permessage-deflate: the four parameters, the offer and answer, and a reader and writer over ws frames."),
    ("deflate", "deflate", "RFC 1951", "Raw DEFLATE shaped for a stream that outlives one message: a window carried across messages, and a ceiling on what one may expand to."),
    ("upgrade", "upgrade", "RFC 6455 §4", "The opening handshake — both sides, and the proof that makes the difference."),
    ("method", "method", "RFC 9110 §9", "Request methods: the nine standard ones and any other token, and whether each is safe and idempotent."),
    ("header", "header", "RFC 9110 §5", "Header fields, as the octets both header compressions share."),
    ("huffman", "huffman", "RFC 7541 App. B", "The Huffman code HPACK and QPACK both use."),
    ("hpack", "hpack", "RFC 7541", "HTTP/2 header compression: both tables, both ends."),
    ("qpack", "qpack", "RFC 9204", "HTTP/3 header compression: both tables, the field lines, both instruction streams."),
    ("http1", "http1", "RFC 9112", "HTTP/1.1 messages: request and status lines, field lines, body framing, the chunked coding; and Conn, a whole connection on h11's state machine."),
    ("http2", "http2", "RFC 9113", "HTTP/2 framing: the nine-octet header, all ten frame types, the connection preface; and Conn, a whole connection after python-hyper h2."),
    ("http3", "http3", "RFC 9114", "HTTP/3 frames, their placement rules, settings, stream types and connection."),
]


def sources(pkg):
    """Every source of a package, tests excluded, the root file first."""
    files = sorted(p for p in (ROOT / "src" / pkg).glob("*.mbt")
                   if not p.name.endswith(("_test.mbt", "_wbtest.mbt")))
    return sorted(files, key=lambda p: (p.stem != pkg, p.name))


PUBLIC = re.compile(r"^pub(?:\((?:all|open|readonly)\))?\s+(.*)$")


def kind_of(sig):
    for word in ("struct", "enum", "suberror", "trait", "fn", "let", "type", "impl"):
        if sig.startswith(word):
            return word
    return "item"


def parse(path):
    """Public items with the doc comment above them.

    Signatures `moon fmt` broke over several lines are joined back up; a type
    keeps its body, since the fields and the variants are the type. `extend`
    lines are derive plumbing and not API.
    """
    items, doc, held = [], [], None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        s = line.strip()
        if held is not None:
            held.append(line if held[0].lstrip().startswith(("struct", "enum", "suberror", "trait")) else s)
            body = "\n".join(held)
            if body.count("(") <= body.count(")") and body.count("{") <= body.count("}"):
                items.append(shape(held, doc))
                doc, held = [], None
            continue
        if s == "///|":
            doc = []
        elif s.startswith("///"):
            doc.append(s[3:].strip())
        elif PUBLIC.match(s):
            sig = PUBLIC.match(s).group(1)
            if sig.startswith("extend") or sig.startswith("impl "):
                doc = []
                continue
            if sig.count("(") > sig.count(")") or sig.count("{") > sig.count("}"):
                held = [sig]
                continue
            items.append(shape([sig], doc))
            doc = []
        elif s == "":
            pass
        else:
            doc = []
    return items


def shape(held, doc):
    """One item: its kind, its signature, and what was said above it."""
    kind = kind_of(held[0].lstrip())
    if kind in ("struct", "enum", "suberror", "trait"):
        # A type keeps its body — the fields and variants are the type — but the
        # `///` marks go: the page is documentation, not the source.
        sig = "\n".join(re.sub(r"^\s*///\s?", "", line) for line in held)
    else:
        sig = re.sub(r"\s+", " ", " ".join(x.strip() for x in held))
        sig = re.sub(r"\s*\{.*$", "", sig).rstrip()
        sig = re.sub(r",\s*\)", ")", sig)
    return (kind, sig, " ".join(doc).strip())


def tint(sig):
    s = html.escape(sig)
    s = re.sub(r"\b(fn|struct|let)\b", r'<span class="k">\1</span>', s)
    s = re.sub(r"\b([A-Z][A-Za-z0-9_]*)\b", r'<span class="ty">\1</span>', s)
    s = s.replace("-&gt;", '<span class="op">-&gt;</span>').replace("?", '<span class="op">?</span>')
    return s


def prose(t):
    t = html.escape(t)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", t)


def esc(t):
    return html.escape(t)


HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API reference — moonhttp</title>
<meta name="description" content="Every public type, function and value in moonhttp, generated from the doc comments in the sources.">
<meta name="theme-color" content="#e8f4f8" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0d232d" media="(prefers-color-scheme: dark)">
<link rel="icon" href="./favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Noto+Sans+SC:wght@300;400;500;700&display=swap">
<link rel="stylesheet" href="./assets/site.css">
<script type="module" src="assets/scrollbar.js"></script>
</head>
<body>

<header class="top">
  <div class="page top-in">
    <a class="brand" href="./"><span class="tile"><i></i><i></i><i></i></span>moonhttp</a>
    <nav class="nav">
      <a href="./guide.html">Guide</a>
      <a href="./api.html" class="on">API</a>
      <a href="./protocols.html">Protocols</a>
      <a class="gh" href="https://github.com/moonbitstack/moonhttp" aria-label="GitHub repository" title="GitHub">
        <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>
      </a>
    </nav>
  </div>
</header>
"""

FOOT = """<footer class="foot">
  <div class="page">
    <div class="foot-grid">
      <div class="about">
        <a class="brand" href="./"><span class="tile"><i></i><i></i><i></i></span>moonhttp</a>
        <p>HTTP logic for MoonBit, with no I/O in it. Bytes in, values out, on every target the compiler builds for.</p>
      </div>
      <div>
        <h4>Pages</h4>
        <ul>
          <li><a href="./guide.html">Guide</a></li>
          <li><a href="./api.html">API reference</a></li>
          <li><a href="./protocols.html">Protocols</a></li>
        </ul>
      </div>
      <div>
        <h4>Families</h4>
        <ul>
          <li><a href="./api.html#http1">HTTP/1.1</a></li>
          <li><a href="./api.html#http2">HTTP/2</a></li>
          <li><a href="./api.html#http3">HTTP/3</a></li>
          <li><a href="./api.html#ws">WebSocket</a></li>
        </ul>
      </div>
      <div>
        <h4>Elsewhere</h4>
        <ul>
          <li><a href="https://github.com/moonbitstack/moonhttp">GitHub</a></li>
          <li><a href="https://mooncakes.io/docs/moonbitstack/moonhttp">mooncakes</a></li>
          <li><a href="https://github.com/moonbitstack/moonhttp/blob/master/LICENSE">Apache-2.0</a></li>
        </ul>
      </div>
    </div>
    <div class="meta">
      <svg class="tick-meta" width="56" height="6" viewBox="0 0 56 6" aria-hidden="true"><path class="a" d="M0 3h22"/><path class="b" d="M28 3h14"/><path class="c" d="M48 3h8"/></svg>
      <span>Apache-2.0</span>
      <span>© 2026 Leo Cheng</span>
      <span>RFC 9110 · 9111 · 9112 · 9113 · 9114 · 6455 · 7692 · 7838</span>
    </div>
  </div>
</footer>

<script src="./assets/site.js"></script>
</body>
</html>
"""


def main():
    body = [HEAD, '<main>', '<section class="page masthead">',
            '<svg class="tick tick-tr" width="148" height="56" viewBox="0 0 148 56" aria-hidden="true">'
            '<path class="a" d="M36 4h112"/><path class="b" d="M72 20h76"/><path class="c" d="M110 36h38"/></svg>',
            '<p class="label">Reference · <b>generated</b></p>',
            '<h1 class="display">Every name,<br>with its section.</h1>',
            '<p class="lede">This page is built from the doc comments above the public items in the sources, '
            'so a function that is documented is a function that is here. Nineteen packages, in the order the '
            'site lists them.</p>',
            '</section>', '<div class="page api">']

    body.append('<aside class="apirail">'
                '<div class="search"><input id="q" type="search" placeholder="filter names" '
                'aria-label="Filter the reference by name" autocomplete="off" spellcheck="false">'
                '<span class="slash">/</span></div>'
                '<nav>')
    for i, (anchor, _, _, _) in enumerate(PKGS, 1):
        body.append('<a href="#%s"><span>%02d</span>%s</a>' % (anchor, i, anchor))
    body.append('</nav><p class="count" id="hits"></p></aside>')

    body.append('<div class="ref">')
    total = 0
    for i, (anchor, pkg, spec, desc) in enumerate(PKGS, 1):
        items = [item for path in sources(pkg) for item in parse(path)]
        total += len(items)
        body.append('<section class="pkg" id="%s">' % anchor)
        body.append('<div class="pkg-head"><span class="no">%02d</span>'
                    '<h2><span class="at">@</span>%s</h2><span class="spec">%s</span></div>'
                    % (i, anchor, esc(spec)))
        body.append('<p class="pkg-desc">%s</p>' % esc(desc))
        for kind, sig, doc in items:
            body.append('<div class="item" data-k="%s"><span class="kind">%s</span>'
                        '<div><pre class="sig">%s</pre>%s</div></div>'
                        % (kind, kind, tint(sig), ('<p class="item-doc">%s</p>' % prose(doc)) if doc else ''))
        body.append('</section>')
    body.append('<p class="empty hidden" id="empty">Nothing here matches that.</p>')
    body.append('</div></div></main>')

    body.append(FOOT)
    body = "\n".join(body)
    body = body.replace('<p class="count" id="hits"></p>',
                        '<p class="count" id="hits">%d entries</p>' % total)

    out = ROOT / "docs" / "api.html"
    out.write_text(body, encoding="utf-8")
    print("wrote %s (%d public items across %d packages)" % (out, total, len(PKGS)))


if __name__ == "__main__":
    main()
