(() => {
// The site's whole script: copying a line, filtering a list, marking where the
// reader is, and one calculator. Nothing here is required to read a page.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

// ---------------------------------------------------------------- copy

for (const btn of $$("[data-copy]")) {
  btn.addEventListener("click", () => {
    const code = btn.closest(".code");
    const text =
      btn.getAttribute("data-copy") ??
      (code ? code.querySelector("pre").innerText.replace(/\n$/, "") : "");
    const done = () => {
      const was = btn.textContent;
      btn.textContent = "copied";
      btn.classList.add("ok");
      setTimeout(() => {
        btn.textContent = was;
        btn.classList.remove("ok");
      }, 1200);
    };
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, done);
  });
}

// ---------------------------------------------------------------- API filter

const q = $("#q");
if (q) {
  const items = $$(".item");
  const pkgs = $$(".pkg");
  const rail = $$(".apirail a");
  const hits = $("#hits");
  const empty = $("#empty");
  const total = items.length;

  const filter = () => {
    const needle = q.value.trim().toLowerCase();
    let shown = 0;
    for (const item of items) {
      const hit = needle === "" || item.textContent.toLowerCase().includes(needle);
      item.classList.toggle("hidden", !hit);
      if (hit) shown += 1;
    }
    for (const pkg of pkgs) {
      const any = pkg.querySelector(".item:not(.hidden)") !== null;
      pkg.classList.toggle("hidden", needle !== "" && !any);
      const a = rail.find((x) => x.getAttribute("href") === "#" + pkg.id);
      if (a) a.classList.toggle("hidden", needle !== "" && !any);
    }
    if (hits) hits.textContent = needle === "" ? total + " entries" : shown + " / " + total;
    if (empty) empty.classList.toggle("hidden", shown !== 0);
  };

  q.addEventListener("input", filter);
  q.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      q.value = "";
      filter();
      q.blur();
    }
  });
  addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== q) {
      e.preventDefault();
      q.focus();
      q.select();
    }
  });
  filter();
}

// ---------------------------------------------------------------- scroll spy

const spyLinks = $$(".rail a, .apirail a");
if (spyLinks.length && "IntersectionObserver" in window) {
  const seen = new Map();
  const setOn = (id) => {
    for (const a of spyLinks) a.classList.toggle("on", a.getAttribute("href") === "#" + id);
  };
  const watcher = new IntersectionObserver(
    (entries) => {
      for (const e of entries) seen.set(e.target.id, e.intersectionRatio);
      let best = null;
      let most = 0;
      for (const [id, ratio] of seen) {
        if (ratio > most) {
          most = ratio;
          best = id;
        }
      }
      if (best) setOn(best);
    },
    { rootMargin: "-15% 0px -60% 0px", threshold: [0, 0.2, 0.6, 1] },
  );
  for (const section of $$("section[id]")) watcher.observe(section);
}

// ---------------------------------------------------------------- cache age

// The numbers come from moonhttp's cache.Entry built to JavaScript
// (engine/moonhttp.js, written by the docs workflow).
const calc = $("#calc");
const engine = calc ? import("../engine/moonhttp.js") : null;
if (calc) {
  const input = (name) => $("#a-" + name, calc);
  const out = (name) => $("#v-" + name, calc);
  const verdict = $("#verdict", calc);

  const paint = async () => {
    const dated = Number(input("dated").value);
    const ageField = Number(input("age").value);
    const delay = Number(input("delay").value);
    const resident = Number(input("resident").value);
    const life = Number(input("life").value);

    const m = await engine;
    const { initial, current, left, fresh } = JSON.parse(
      m.age(dated, ageField, delay, resident, life),
    );

    out("dated").textContent = dated + "s";
    out("age").textContent = ageField + "s";
    out("delay").textContent = delay + "s";
    out("resident").textContent = resident + "s";
    out("life").textContent = life + "s";

    $("#r-age", calc).textContent = current + "s";
    $("#r-left", calc).textContent = left >= 0 ? left + "s" : "—";
    $("#r-initial", calc).textContent = initial + "s";

    verdict.classList.toggle("stale", !fresh);
    verdict.textContent = "";
    const dot = document.createElement("span");
    dot.className = "dot";
    verdict.append(dot, fresh ? "fresh — may be served" : "stale — validate or fetch");
  };

  for (const el of $$("input", calc)) el.addEventListener("input", paint);
  paint();
}
})();
