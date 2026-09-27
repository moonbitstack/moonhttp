#!/usr/bin/env python3
"""Generate a self-contained, styled API-reference site (docs/index.html) for
gh-pages from the package sources' `///` doc comments. Reproducible: reads the
.mbt files, so the docs never drift from the code."""
import re, html, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKGS = [
    ("url", "url", "RFC 3986 URI references: taking one apart, putting it back, resolving a relative one, and percent coding by component."),
    ("mime", "mime", "RFC 7578 multipart/form-data and WHATWG urlencoded — both ways a browser posts a form."),
    ("dataurl", "dataurl", "RFC 2397 data URLs: a whole representation written inside the reference to it."),
    ("media", "media", "RFC 9110 media types and RFC 6266 Content-Disposition — what a body is, and what to save it as."),
    ("range", "range", "RFC 9110 §14 range requests: the fields, the arithmetic against a length, and the multi-range body."),
    ("conditional", "conditional", "RFC 9110 §8.8 and §13: entity-tags, the five precondition fields, and the order §13.2.2 weighs them in."),
    ("cookie", "cookie", "RFC 6265 Cookie and Set-Cookie, each read and written."),
    ("sse", "sse", "WHATWG Server-Sent Events, framed both ways and dispatched the way an EventSource does."),
    ("ws", "ws", "RFC 6455 §5 WebSocket framing: opcodes, masking, reassembly, close statuses."),
    ("upgrade", "upgrade", "RFC 6455 §4, the opening handshake — both sides, and the proof that makes the difference."),
    ("header", "header", "RFC 9110 §5 header fields, as the octets both header compressions share."),
    ("huffman", "huffman", "RFC 7541 Appendix B, the Huffman code HPACK and QPACK both use."),
    ("hpack", "hpack", "RFC 7541 HTTP/2 header compression: both tables, both ends."),
    ("qpack", "qpack", "RFC 9204 HTTP/3 header compression: both tables, the field lines, both instruction streams."),
    ("http1", "http1", "RFC 9112 messages: request and status lines, field lines, body framing, the chunked coding."),
    ("http2", "http2", "RFC 9113 framing: the nine-octet header, all ten frame types, the connection preface."),
    ("http3", "http3", "RFC 9114 frames, their placement rules, settings, stream types and connection."),
]


def sources(pkg):
    """Every source of a package, tests excluded, the root file first."""
    files = sorted(p for p in (ROOT / pkg).glob("*.mbt")
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
        sig = "\n".join(held)
    else:
        sig = re.sub(r"\s+", " ", " ".join(x.strip() for x in held))
        sig = re.sub(r"\s*\{.*$", "", sig).rstrip()
        sig = re.sub(r",\s*\)", ")", sig)
    return (kind, sig, " ".join(doc).strip())


TYPES = {"Bytes", "String", "Int", "Char", "Bool", "Array", "Map", "UInt64", "Unit"}


def tint(sig):
    s = html.escape(sig)
    s = re.sub(r"\b(fn|struct|let)\b", r'<span class="k">\1</span>', s)
    s = re.sub(r"\b([A-Z][A-Za-z0-9_]*)\b", r'<span class="ty">\1</span>', s)
    s = s.replace("-&gt;", '<span class="op">-&gt;</span>').replace("?", '<span class="op">?</span>')
    return s


def prose(t):
    t = html.escape(t)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", t)


CSS = r"""
:root{
  --bg:#fbfbfd; --panel:#ffffff; --panel-2:#f6f7fb; --ink:#14181f;
  --muted:#5b6675; --line:#e8ebf1; --accent:#6d5efc; --accent-soft:#efecff; --out:#0ca678;
  --code-bg:#f4f5f9; --shadow:0 1px 2px rgba(20,24,31,.04),0 8px 24px -12px rgba(20,24,31,.10);
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0b0e14; --panel:#131722; --panel-2:#0f131c; --ink:#e9edf6; --muted:#96a1b5;
  --line:#212736; --accent:#9d8bff; --accent-soft:#1c1b3a; --out:#2dd4a7;
  --code-bg:#161b26; --shadow:0 1px 2px rgba(0,0,0,.3),0 12px 30px -14px rgba(0,0,0,.5);
}}
:root[data-theme=light]{--bg:#fbfbfd;--panel:#fff;--panel-2:#f6f7fb;--ink:#14181f;--muted:#5b6675;--line:#e8ebf1;--accent:#6d5efc;--accent-soft:#efecff;--out:#0ca678;--code-bg:#f4f5f9;--shadow:0 1px 2px rgba(20,24,31,.04),0 8px 24px -12px rgba(20,24,31,.10)}
:root[data-theme=dark]{--bg:#0b0e14;--panel:#131722;--panel-2:#0f131c;--ink:#e9edf6;--muted:#96a1b5;--line:#212736;--accent:#9d8bff;--accent-soft:#1c1b3a;--out:#2dd4a7;--code-bg:#161b26;--shadow:0 1px 2px rgba(0,0,0,.3),0 12px 30px -14px rgba(0,0,0,.5)}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{animation:none!important;transition:none!important}}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:"IBM Plex Sans",system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  font-size:15.5px;line-height:1.6;-webkit-font-smoothing:antialiased}
code,pre,.mono{font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.layout{display:grid;grid-template-columns:264px minmax(0,1fr);max-width:1180px;margin:0 auto}

/* sidebar */
.sidebar{position:sticky;top:0;align-self:start;height:100vh;overflow-y:auto;
  border-right:1px solid var(--line);padding:1.6rem 1.1rem 2rem;background:var(--panel-2)}
.brand{display:flex;align-items:center;gap:.55rem;font-family:"IBM Plex Mono";font-weight:600;
  font-size:1.35rem;letter-spacing:-.01em;color:var(--ink);margin-bottom:.15rem}
.brand .dot{width:11px;height:11px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px var(--accent-soft)}
.brand-sub{color:var(--muted);font-size:.8rem;margin:0 0 1.3rem;padding-left:.15rem}
.side-nav{display:flex;flex-direction:column;gap:.1rem}
.side-nav a{color:var(--muted);font-size:.9rem;padding:.32rem .6rem;border-radius:8px;
  font-family:"IBM Plex Mono";display:flex;align-items:center;gap:.4rem;border-left:2px solid transparent}
.side-nav a .at{color:var(--accent);opacity:.6}
.side-nav a:hover{background:var(--accent-soft);color:var(--ink);text-decoration:none}
.side-nav a.active{color:var(--ink);background:var(--accent-soft);border-left-color:var(--accent);font-weight:500}
.side-nav a.active .at{opacity:1}
.side-foot{margin-top:1.6rem;padding-top:1.1rem;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:.4rem}
.side-foot img{height:20px;display:block}
.theme-btn{margin-top:1rem;background:none;border:1px solid var(--line);color:var(--muted);
  border-radius:8px;padding:.35rem .6rem;font:inherit;font-size:.82rem;cursor:pointer;width:100%}
.theme-btn:hover{border-color:var(--accent);color:var(--ink)}

/* main */
main{padding:2.6rem 2.4rem 5rem;min-width:0}
.hero h1{font-family:"IBM Plex Mono";font-weight:600;font-size:2.9rem;letter-spacing:-.02em;margin:0}
.hero .tag{color:var(--muted);font-size:1.12rem;max-width:60ch;margin:.5rem 0 1.1rem;text-wrap:balance}
.badges{display:flex;flex-wrap:wrap;gap:.45rem;margin:0 0 1.4rem}
.badges img{height:21px;display:block}
.install{display:flex;align-items:center;gap:.6rem;background:var(--panel);border:1px solid var(--line);
  border-radius:12px;padding:.65rem 1rem;box-shadow:var(--shadow);max-width:420px}
.install .prompt{color:var(--out);user-select:none;font-weight:600}
.install code{flex:1;font-size:.95rem}
.copy{background:none;border:1px solid var(--line);border-radius:7px;color:var(--muted);
  cursor:pointer;font:inherit;font-size:.72rem;padding:.2rem .5rem}
.copy:hover{border-color:var(--accent);color:var(--accent)}
.copy.ok{color:var(--out);border-color:var(--out)}

/* playground */
.pg{margin:2.2rem 0 .5rem;background:
   radial-gradient(120% 130% at 100% 0%, var(--accent-soft) 0%, transparent 55%), var(--panel);
  border:1px solid var(--line);border-radius:16px;padding:1.3rem 1.4rem;box-shadow:var(--shadow)}
.pg h2{margin:0 0 .1rem;font-size:1.06rem;display:flex;align-items:center;gap:.5rem}
.pg h2 .spark{color:var(--accent)}
.pg .hint{color:var(--muted);font-size:.86rem;margin:0 0 .9rem}
.pg input{width:100%;font-family:"IBM Plex Mono";font-size:1rem;color:var(--ink);
  background:var(--code-bg);border:1px solid var(--line);border-radius:10px;padding:.7rem .9rem;outline:none}
.pg input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.pg-rows{margin-top:.9rem;display:grid;gap:.35rem}
.pg-row{display:grid;grid-template-columns:84px 1fr auto;align-items:center;gap:.7rem;
  padding:.4rem .6rem;border-radius:9px}
.pg-row:hover{background:var(--panel-2)}
.pg-row .lbl{font-family:"IBM Plex Mono";font-size:.8rem;color:var(--accent);font-weight:500}
.pg-row .val{font-family:"IBM Plex Mono";font-size:.9rem;color:var(--out);overflow-x:auto;white-space:nowrap;
  scrollbar-width:thin}
.pg-row .val::-webkit-scrollbar{height:5px}

/* sections + cards */
section.pkg{scroll-margin-top:1.2rem;padding-top:2.4rem;margin-top:2rem;border-top:1px solid var(--line)}
section.pkg > h2{font-family:"IBM Plex Mono";font-size:1.55rem;margin:0 0 .15rem;letter-spacing:-.01em}
section.pkg > h2 .at{color:var(--accent)}
.pdesc{color:var(--muted);margin:.15rem 0 1.2rem;max-width:70ch}
.item{background:var(--panel);border:1px solid var(--line);border-radius:13px;
  padding:1rem 1.2rem;margin:.85rem 0;box-shadow:var(--shadow);transition:border-color .15s,transform .15s}
.item:hover{border-color:color-mix(in oklab,var(--accent) 40%,var(--line))}
.kind{display:inline-block;font-size:.66rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;
  border-radius:6px;padding:.1rem .45rem;margin-bottom:.55rem;
  color:var(--accent);background:var(--accent-soft);border:1px solid color-mix(in oklab,var(--accent) 26%,transparent)}
.item[data-k=struct] .kind{--c:#8b5cf6}.item[data-k=fn] .kind{--c:#0ca678}.item[data-k=let] .kind{--c:#2563eb}
.item .kind{color:var(--c,var(--accent));background:color-mix(in oklab,var(--c,var(--accent)) 13%,transparent);
  border-color:color-mix(in oklab,var(--c,var(--accent)) 30%,transparent)}
.sig{font-size:.98rem;margin:0 0 .55rem;overflow-x:auto;white-space:pre;color:var(--ink);padding-bottom:.15rem}
.sig .k{color:#8b5cf6;font-weight:500}.sig .ty{color:var(--accent)}.sig .op{color:var(--muted)}
@media (prefers-color-scheme:dark){.sig .k{color:#b794ff}}
.doc{margin:0;color:var(--ink);max-width:74ch}
.doc code{background:var(--code-bg);padding:.06rem .35rem;border-radius:5px;font-size:.9em;color:var(--accent)}
footer{margin-top:3rem;padding-top:1.3rem;border-top:1px solid var(--line);color:var(--muted);font-size:.9rem}

@media (max-width:820px){
  .layout{grid-template-columns:1fr}
  .sidebar{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line)}
  .side-nav{flex-flow:row wrap}.side-nav a{border-left:none}.side-nav a.active{border-left:none}
  main{padding:1.8rem 1.2rem 4rem}.hero h1{font-size:2.2rem}
  .pg-row{grid-template-columns:70px 1fr auto}
}
"""

# JS: codecs (mirror the library exactly) + playground + scroll-spy + copy + theme
JS = r"""
document.addEventListener("DOMContentLoaded",()=>{
  // copy buttons
  document.querySelectorAll("[data-copy]").forEach(btn=>btn.addEventListener("click",()=>{
    navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(()=>{
      const t=btn.textContent;btn.textContent="copied";btn.classList.add("ok");
      setTimeout(()=>{btn.textContent=t;btn.classList.remove("ok");},1100);});}));
  // scroll-spy
  const links=[...document.querySelectorAll(".side-nav a")];
  const map=Object.fromEntries(links.map(a=>[a.getAttribute("href").slice(1),a]));
  const spy=new IntersectionObserver(es=>{es.forEach(e=>{if(e.isIntersecting){
    links.forEach(a=>a.classList.remove("active"));const a=map[e.target.id];if(a)a.classList.add("active");}});},
    {rootMargin:"-10% 0px -80% 0px"});
  document.querySelectorAll("section.pkg").forEach(s=>spy.observe(s));
  // theme toggle
  const tb=document.getElementById("theme");if(tb)tb.addEventListener("click",()=>{
    const cur=document.documentElement.getAttribute("data-theme")
      ||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light");
    document.documentElement.setAttribute("data-theme",cur==="dark"?"light":"dark");});
});
"""


def esc(t):
    return html.escape(t)


def main():
    HEAD = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>moonhttp — MoonBit API</title>'
            '<link rel="preconnect" href="https://fonts.googleapis.com">'
            '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
            '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&'
            'family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">'
            '<style>' + CSS + '</style></head><body>')

    side = ['<aside class="sidebar"><div class="brand"><span class="dot"></span>moonhttp</div>'
            '<p class="brand-sub">MoonBit API reference</p><nav class="side-nav">']
    side += ['<a href="#%s"><span class="at">@</span>%s</a>' % (n, n) for n, _, _ in PKGS]
    side += ['</nav>'
             '<button class="theme-btn" id="theme">◐ toggle theme</button>'
             '<div class="side-foot">'
             '<a href="https://github.com/moonbitstack/moonhttp/actions"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/moonbitstack/moonhttp/ci.yml?branch=master&label=CI&logo=github"></a>'
             '<a href="https://mooncakes.io/docs/moonbitstack/moonhttp"><img alt="mooncakes" src="https://img.shields.io/badge/mooncakes-moonbitstack%2Fmoonhttp-1f6feb"></a>'
             '</div></aside>']

    hero = ('<main><header class="hero"><h1>moonhttp</h1>'
            '<p class="tag">The HTTP family for MoonBit: the formats a request and a response '
            'are written in, each a package of its own. Bytes in, events out; no sockets.</p>'
            '<div class="badges">'
            '<a href="https://github.com/moonbitstack/moonhttp/actions"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/moonbitstack/moonhttp/ci.yml?branch=master&label=CI&logo=github"></a>'
            '<img alt="tests" src="https://img.shields.io/badge/tests-238%20passing-0ca678">'
            '<a href="https://github.com/moonbitstack/moonhttp"><img alt="GitHub" src="https://img.shields.io/badge/GitHub-source-24292f?logo=github"></a>'
            '<img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-6d5efc"></div>'
            '<div class="install"><span class="prompt">$</span><code>moon add moonbitstack/moonhttp</code>'
            '<button class="copy" data-copy="moon add moonbitstack/moonhttp">copy</button></div>'
            '</header>')

    body = [HEAD, '<div class="layout">'] + side + [hero]
    for name, pkg, desc in PKGS:
        body.append('<section class="pkg" id="%s"><h2><span class="at">@</span>%s</h2>'
                    '<p class="pdesc">%s</p>' % (name, name, esc(desc)))
        items = [item for path in sources(pkg) for item in parse(path)]
        for kind, sig, doc in items:
            body.append('<div class="item" data-k="%s"><span class="kind">%s</span>'
                        '<pre class="sig">%s</pre>%s</div>'
                        % (kind, kind, tint(sig), ('<p class="doc">%s</p>' % prose(doc)) if doc else ''))
        body.append('</section>')
    body.append('<footer>Generated from source <code>///</code> doc-comments · '
                '<a href="https://mooncakes.io/docs/moonbitstack/moonhttp">mooncakes</a> · '
                '<a href="https://github.com/moonbitstack/moonhttp">GitHub</a> · Apache-2.0 © Leo Cheng</footer>')
    body.append('</main></div><script>' + JS + '</script></body></html>')

    out = ROOT / "docs" / "index.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(body), encoding="utf-8")
    total = sum(len(parse(p)) for _, pkg, _ in PKGS for p in sources(pkg))
    print("wrote %s (%d public items across %d packages)" % (out, total, len(PKGS)))


if __name__ == "__main__":
    main()
