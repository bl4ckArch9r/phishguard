// Runs the real index.html + app.js in jsdom against a LIVE PhishGuard server.
//   npm i jsdom && PHISHGUARD_URL=http://127.0.0.1:8000 node tests/ui_dom_test.js
// (Checks DOM behaviour and XSS-safety. It does not check visual appearance.)
const { JSDOM } = require("jsdom");
const fs = require("fs");
const path = require("path");
const BASE = process.env.PHISHGUARD_URL || "http://127.0.0.1:8765";
const FRONT = path.resolve(__dirname, "../../frontend");
const html = fs.readFileSync(path.join(FRONT, "index.html"), "utf8");
const js = fs.readFileSync(path.join(FRONT, "app.js"), "utf8");
let fails = 0;
const ok = (c, m) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) fails++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function boot(fetchImpl) {
  const dom = new JSDOM(html, { url: BASE + "/#scan", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.Element.prototype.scrollIntoView = () => {};
  w.matchMedia = () => ({ matches: false });
  w.fetch = fetchImpl || ((p, o) => fetch(BASE + p, o));
  w.eval(js);
  return w;
}
async function scan(w, url, deep = false) {
  w.document.querySelector("#urlInput").value = url;
  w.document.querySelector("#deepToggle").checked = deep;
  w.document.querySelector("#scanForm").dispatchEvent(new w.Event("submit", { cancelable: true, bubbles: true }));
  for (let i = 0; i < 80; i++) {
    await sleep(100);
    if (!w.document.querySelector("#result").hidden || !w.document.querySelector("#error").hidden) break;
  }
}

(async () => {
  let w = boot();
  await scan(w, "br-icloud.com.br");
  let r = w.document.querySelector("#result");
  ok(!r.hidden && /Suspicious|Likely phishing/.test(r.textContent), "br-icloud.com.br renders a non-safe verdict");
  const strong = r.querySelector(".url-line strong");
  ok(strong && strong.textContent === "br-icloud.com.br", "registered domain is highlighted inside the URL line");
  ok(r.querySelectorAll(".ev").length >= 2 && /Apple/.test(r.textContent), "evidence rows render with the brand explanation");
  ok(/How the score was built/.test(r.textContent) && /What was checked/.test(r.textContent), "score breakdown and coverage boxes present");

  w = boot(); await scan(w, "https://www.wikipedia.org");
  r = w.document.querySelector("#result");
  ok(/Looks safe/.test(r.textContent), "wikipedia.org renders 'Looks safe'");
  ok(!/Why the AI rated/.test(r.textContent), "no alarming AI-reasons box on a safe result");

  w = boot(); await scan(w, "javascript:alert(1)");
  ok(!w.document.querySelector("#error").hidden && w.document.querySelector("#error").textContent.length > 5 && w.document.querySelector("#result").hidden,
    "invalid scheme shows a readable error and no result");

  // XSS: strings that originate from a scanned (hostile) page must be inserted as text
  const evil = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>';
  const fake = { id: 1, url: "http://x.test/" + evil, host: "x.test", registered_domain: "x.test", verdict: "phishing", score: 90, confidence: 0.9,
    breakdown: { page: 40 }, coverage: { available: ["url"], total: 5 }, notes: [evil],
    evidence: [{ layer: "page", id: "t", title: evil, detail: evil, severity: "high", points: 10 }],
    actions: [evil], model: { name: "m", probability: 0.9, trained_on: "f", explanation: { method: "exact", numeric: [{ text: evil }], patterns: [{ pattern: evil }] } },
    intel_status: { local_feed: "clean" }, page_fetch: { ok: true }, facts: {}, deep: true };
  w = boot(() => Promise.resolve({ ok: true, status: 200, json: async () => fake }));
  await scan(w, "http://x.test/a", true);
  await sleep(150);
  r = w.document.querySelector("#result");
  ok(r.querySelectorAll("img, script").length === 0 && !w.__pwned, "hostile title/URL/reasons are NOT parsed as HTML");
  ok(r.textContent.includes("<img src=x"), "hostile text is displayed literally");

  for (const [tab, expect] of [["dashboard", /links checked|Nothing to show/], ["history", /Result|No scans yet/], ["model", /selected model|No trained model/]]) {
    w = boot(); w.location.hash = "#" + tab; w.dispatchEvent(new w.Event("hashchange")); await sleep(1200);
    const box = w.document.querySelector("#tab-" + tab);
    ok(!box.hidden && expect.test(box.textContent), `${tab} tab renders`);
  }
  console.log(fails ? `\n${fails} FAILED` : "\nALL UI CHECKS PASSED");
  process.exit(fails ? 1 : 0);
})();
