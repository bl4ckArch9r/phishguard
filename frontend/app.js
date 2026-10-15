"use strict";
/* All server-supplied strings (page titles, URLs, reasons) are inserted with
   textContent only - never innerHTML - so a hostile page cannot inject markup. */

const $ = (s, r = document) => r.querySelector(s);
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
const pct = (x, d = 1) => (x == null ? "n/a" : (x * 100).toFixed(d) + "%");

const VERDICT = {
  safe: { word: "Looks safe", icon: "✓", sub: "No strong phishing signals were found." },
  suspicious: { word: "Suspicious", icon: "!", sub: "Some warning signs. Don't log in from this link." },
  phishing: { word: "Likely phishing", icon: "✕", sub: "Strong signs this link is trying to steal information." },
};
const LAYER_TITLE = {
  intel: "Threat intelligence", page: "Page behaviour", brand: "Brand impersonation",
  domain: "Domain & certificate", url: "Address structure", model: "AI model (address)",
  pageai: "AI model (page content)",
};
const LAYER_ORDER = ["intel", "page", "pageai", "brand", "domain", "url", "model"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Note" };
const PROVIDER_LABEL = { local_feed: "Local phishing feed", virustotal: "VirusTotal", safe_browsing: "Google Safe Browsing", urlhaus: "URLhaus" };
const STATE_LABEL = { clean: ["Not listed", "s-ok"], listed: ["Listed", "s-bad"], not_configured: ["Not configured", "s-off"], error: ["Unavailable", "s-off"] };
const BREAKDOWN_LABEL = { model: "AI model (address)", pageai: "AI model (page content)", url: "Address structure", brand: "Brand impersonation", page: "Page behaviour", domain: "Domain & certificate", intel: "Threat intelligence" };

async function api(path, opts) {
  const res = await fetch(path, opts);
  let body = null;
  try { body = await res.json(); } catch (_) { /* ignore */ }
  if (!res.ok) {
    const msg = body && body.detail ? (typeof body.detail === "string" ? body.detail : "That request wasn't valid.") : `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return body;
}

/* ---------- routing ---------- */
const tabs = ["scan", "dashboard", "history", "model"];
function route() {
  const t = tabs.includes(location.hash.slice(1)) ? location.hash.slice(1) : "scan";
  for (const name of tabs) $("#tab-" + name).hidden = name !== t;
  document.querySelectorAll("nav a").forEach((a) => {
    if (a.dataset.tab === t) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  if (t === "dashboard") loadDashboard();
  if (t === "history") loadHistory();
  if (t === "model") loadModel();
}
window.addEventListener("hashchange", route);

/* ---------- scan ---------- */
const form = $("#scanForm"), input = $("#urlInput"), btn = $("#scanBtn");
let lastResult = null;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;
  const deep = $("#deepToggle").checked;
  $("#error").hidden = true; $("#result").hidden = true;
  btn.disabled = true; btn.textContent = "Checking…";
  showProgress(deep);
  try {
    const r = await api("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, deep }) });
    renderResult(r);
  } catch (err) {
    const box = $("#error"); box.textContent = err.message; box.hidden = false;
  } finally {
    $("#progress").hidden = true; $("#progress").classList.remove("on");
    btn.disabled = false; btn.textContent = "Check link";
  }
});

function showProgress(deep) {
  const p = clear($("#progress")); p.hidden = false; p.classList.add("on");
  const steps = ["Reading the address", "Asking the AI model", "Checking brand look-alikes"];
  if (deep) steps.push("Inspecting the live page", "Checking domain, certificate and threat feeds");
  p.append(h("strong", {}, "Analysing…"), h("ul", {}, steps.map((s) => h("li", {}, h("span", { class: "dot" }), s))));
}

function urlLine(r) {
  const line = h("div", { class: "url-line", "aria-label": "Analysed address" });
  const url = r.url, reg = r.registered_domain || "";
  const hostStart = url.indexOf("//") + 2;
  const idx = reg ? url.toLowerCase().indexOf(reg.toLowerCase(), hostStart) : -1;
  if (idx < 0) { line.append(url); return line; }
  line.append(url.slice(0, idx), h("strong", { title: "The part that actually identifies the website" }, url.slice(idx, idx + reg.length)), url.slice(idx + reg.length));
  return line;
}

function renderResult(r) {
  lastResult = r;
  const v = VERDICT[r.verdict];
  const root = clear($("#result")); root.hidden = false;

  const fill = h("div", { class: "meter-fill f-" + r.verdict, style: "width:0%" });
  const meter = h("div", { class: "meter" },
    h("div", { class: "meter-bar", role: "img", "aria-label": `Risk score ${r.score} out of 100` }, fill),
    h("div", { class: "meter-scale" }, h("span", {}, "Safe 0–34"), h("span", {}, "Suspicious 35–64"), h("span", {}, "Phishing 65+")));

  const head = h("div", { class: "card" },
    h("div", { class: "verdict" },
      h("div", {},
        h("div", { class: "verdict-word v-" + r.verdict }, h("span", { "aria-hidden": "true" }, v.icon), v.word),
        h("div", { class: "verdict-sub" }, v.sub)),
      h("div", { class: "score" }, h("b", {}, r.score), h("span", {}, `risk score · ${pct(r.confidence, 0)} confidence`))),
    urlLine(r), meter,
    r.notes && r.notes.length ? h("div", { class: "notes" }, r.notes.map((n) => h("p", {}, n))) : null);

  // evidence grouped by layer
  const left = h("div", { class: "card", style: "margin-top:0" }, h("h3", {}, "What we found"));
  for (const layer of LAYER_ORDER) {
    const items = r.evidence.filter((e) => e.layer === layer);
    if (!items.length) continue;
    left.append(h("div", { class: "ev-group" }, h("h3", {}, LAYER_TITLE[layer]),
      items.map((e) => h("div", { class: "ev" },
        h("span", { class: "chip sev-" + e.severity }, SEV_LABEL[e.severity]),
        h("div", {}, h("div", { class: "ev-title" }, e.title), e.detail ? h("div", { class: "ev-detail" }, e.detail) : null),
        h("span", { class: "ev-pts" }, e.points ? "+" + e.points : "")))));
  }

  // sidebar
  const side = h("div", { class: "side" });
  side.append(h("div", { class: "box" }, h("h3", {}, "What to do"), h("ul", {}, r.actions.map((a) => h("li", {}, a)))));

  const bk = Object.entries(r.breakdown);
  side.append(h("div", { class: "box" }, h("h3", {}, "How the score was built"),
    bk.length ? bk.map(([k, val]) => h("div", { class: "bk" }, h("span", {}, BREAKDOWN_LABEL[k] || k), h("b", {}, "+" + val)))
      : h("div", { class: "muted" }, "No risk points were added."),
    h("div", { class: "bk", style: "border-top:1px solid var(--line);margin-top:6px;padding-top:8px" }, h("span", {}, "Total"), h("b", {}, r.score + " / 100"))));

  if (r.model) {
    const ex = r.model.explanation || {};
    const concerned = r.model.probability >= 0.5;
    side.append(h("div", { class: "box" },
      h("h3", {}, concerned ? `Why the AI rated this ${pct(r.model.probability, 0)} phishing-like` : "What the AI thought"),
      !concerned ? h("div", { class: "muted" }, `The AI model rated this link ${pct(r.model.probability, 0)} likely to be phishing, so it raised no strong objection on the address alone.`)
        : (ex.numeric || []).length ? h("ul", {}, ex.numeric.slice(0, 4).map((n) => h("li", {}, n.text)))
        : h("div", { class: "muted" }, "No single feature stood out; the overall pattern of the address looked like known phishing links."),
      concerned && (ex.patterns || []).length ? h("p", { class: "muted", style: "font-size:13.5px;margin:10px 0 0" }, "Text patterns it weighs: ",
        ex.patterns.slice(0, 4).map((p, i) => [i ? ", " : "", h("span", { class: "mono" }, `"${p.pattern}"`)])) : null,
      concerned && ex.method === "approximate" ? h("p", { class: "muted", style: "font-size:13px;margin:8px 0 0" }, "Feature ranking is approximate for this model type.") : null));
  }

  if (typeof r.preview === "string" && /^[A-Za-z0-9+\/=]{20,}$/.test(r.preview)) {
    const img = h("img", { class: "preview", alt: "Rendered view of the page, captured in an isolated browser" });
    img.src = "data:image/jpeg;base64," + r.preview;
    side.append(h("div", { class: "box" }, h("h3", {}, "Safe preview"), img,
      h("p", { class: "muted", style: "font-size:13px;margin:8px 0 0" },
        "Picture of the page taken in an isolated browser. Nothing was typed or submitted.")));
  }

  const checks = h("div", { class: "box" }, h("h3", {}, "What was checked"));
  const pf = r.page_fetch || {};
  const br = (r.facts || {}).browser;
  if (r.deep && br) checks.append(h("div", { class: "status-row" }, h("span", {}, "Page behaviour (browser)"),
    h("span", { class: br.rendered ? "s-ok" : "s-off" }, br.rendered ? "Rendered & watched" : "Not available")));
  checks.append(h("div", { class: "status-row" }, h("span", {}, "Live page"),
    h("span", { class: pf.ok ? "s-ok" : "s-off" }, !r.deep ? "Skipped" : pf.ok ? "Inspected" : "Could not reach")));
  if (r.deep) for (const [k, st] of Object.entries(r.intel_status || {})) {
    const [label, cls] = STATE_LABEL[st] || [st, "s-off"];
    checks.append(h("div", { class: "status-row" }, h("span", {}, PROVIDER_LABEL[k] || k), h("span", { class: cls }, label)));
  }
  checks.append(h("p", { class: "muted", style: "font-size:13px;margin:8px 0 0" }, "A source that isn't configured or reachable adds nothing to the score — it doesn't count as 'clean'."));
  side.append(checks);

  const toast = h("div", { class: "toast", "aria-live": "polite" });
  const send = async (status, msg) => {
    try { await api(`/api/scans/${r.id}/report`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) }); toast.textContent = msg; }
    catch (e) { toast.textContent = e.message; toast.style.color = "var(--bad)"; }
  };
  side.append(h("div", { class: "box" }, h("h3", {}, "Help improve results"),
    h("div", { class: "btns" },
      r.verdict === "safe"
        ? h("button", { on: { click: () => send("false_negative", "Thanks — flagged as a missed phishing link.") } }, "This is actually phishing")
        : h("button", { on: { click: () => send("false_positive", "Thanks — flagged as a false alarm.") } }, "This is a false alarm"),
      h("button", { on: { click: () => send("confirmed", "Thanks — verdict confirmed.") } }, "Verdict is correct"),
      h("button", { on: { click: async () => { await navigator.clipboard.writeText(JSON.stringify(r, null, 2)); toast.textContent = "Report copied as JSON."; } } }, "Copy report")),
    toast));

  root.append(head, h("div", { class: "cols" }, left, side));
  requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = r.score + "%"; }));
  root.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

/* ---------- history ---------- */
const chip = (v) => h("span", { class: "chip " + (v === "safe" ? "sev-info" : v === "suspicious" ? "sev-medium" : "sev-high") }, v === "safe" ? "Safe" : v === "suspicious" ? "Suspicious" : "Phishing");

async function loadHistory() {
  const box = clear($("#historyContent"));
  try {
    const rows = await api("/api/history?limit=100");
    if (!rows.length) { box.append(h("div", { class: "panel empty" }, "No scans yet. Check a link to start your history.")); return; }
    box.append(h("div", { class: "panel tw" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Result", "Score", "Address", "When", "Feedback"].map((c, i) => h("th", { class: i === 1 ? "num" : "" }, c)))),
      h("tbody", {}, rows.map((r) => h("tr", { class: "click", tabindex: "0", on: { click: () => openScan(r.id), keydown: (e) => { if (e.key === "Enter") openScan(r.id); } } },
        h("td", {}, chip(r.verdict)), h("td", { class: "num mono" }, r.score), h("td", { class: "mono" }, r.url),
        h("td", {}, new Date(r.ts).toLocaleString()), h("td", { class: "muted" }, r.report_status ? r.report_status.replace("_", " ") : "—")))))));
  } catch (e) { box.append(h("div", { class: "error" }, e.message)); }
}
async function openScan(id) {
  try { const r = await api("/api/scans/" + id); location.hash = "#scan"; input.value = r.url; renderResult(r); }
  catch (e) { alert(e.message); }
}

/* ---------- dashboard ---------- */
const COL = { safe: "var(--safe)", suspicious: "var(--chart-warn)", phishing: "var(--bad)" };
async function loadDashboard() {
  const box = clear($("#dashContent"));
  try {
    const s = await api("/api/stats");
    if (!s.total) { box.append(h("div", { class: "panel empty" }, "Nothing to show yet. Scan a few links and your statistics will appear here.")); return; }
    const bv = s.by_verdict, flagged = bv.phishing + bv.suspicious;
    box.append(h("div", { class: "tiles" },
      tile(s.total, "links checked"), tile(bv.phishing, "flagged as phishing"), tile(bv.suspicious, "flagged as suspicious"),
      tile(s.avg_duration_ms != null ? (s.avg_duration_ms / 1000).toFixed(1) + " s" : "n/a", "average scan time"), tile(s.reports, "user feedback reports")));

    const seg = (k) => h("i", { style: `width:${(bv[k] / s.total) * 100}%;background:${COL[k]}`, title: `${k}: ${bv[k]}` });
    box.append(h("div", { class: "panel" }, h("h3", {}, "Share of results"),
      h("div", { class: "stack", role: "img", "aria-label": `${bv.safe} safe, ${bv.suspicious} suspicious, ${bv.phishing} phishing` }, seg("safe"), seg("suspicious"), seg("phishing")),
      h("div", { class: "legend" }, ["safe", "suspicious", "phishing"].map((k) => h("span", {}, h("em", { style: "background:" + COL[k] }), `${k[0].toUpperCase() + k.slice(1)} ${bv[k]} (${Math.round((bv[k] / s.total) * 100)}%)`)))));

    box.append(h("div", { class: "panel" }, h("h3", {}, "Last 14 days"), trendChart(s.trend)));

    box.append(h("div", { class: "panel tw" }, h("h3", {}, "Most flagged domains"),
      s.top_flagged_domains.length ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Domain"), h("th", { class: "num" }, "Times flagged"), h("th", { class: "num" }, "Highest score"))),
        h("tbody", {}, s.top_flagged_domains.map((d) => h("tr", {}, h("td", { class: "mono" }, d.domain), h("td", { class: "num" }, d.count), h("td", { class: "num mono" }, d.max_score)))))
        : h("div", { class: "muted" }, "No suspicious or phishing domains recorded yet.")));
  } catch (e) { box.append(h("div", { class: "error" }, e.message)); }
}
const tile = (n, label) => h("div", { class: "tile" }, h("b", {}, n), h("span", {}, label));

function trendChart(trend) {
  const NS = "http://www.w3.org/2000/svg";
  if (!trend.length) return h("div", { class: "muted" }, "No scans in this period.");
  const W = 700, H = 190, pad = { l: 30, r: 8, t: 8, b: 26 };
  const max = Math.max(...trend.map((d) => d.safe + d.suspicious + d.phishing), 1);
  const bw = Math.min(40, (W - pad.l - pad.r) / trend.length - 6);
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Scans per day by result"); svg.style.width = "100%";
  const el = (n, a, t) => { const e = document.createElementNS(NS, n); for (const k in a) e.setAttribute(k, a[k]); if (t != null) e.textContent = t; svg.append(e); return e; };
  el("line", { x1: pad.l, x2: W - pad.r, y1: H - pad.b, y2: H - pad.b, stroke: "var(--line)" });
  el("text", { x: pad.l - 6, y: pad.t + 8, "text-anchor": "end", "font-size": 11, fill: "var(--muted)" }, max);
  el("text", { x: pad.l - 6, y: H - pad.b, "text-anchor": "end", "font-size": 11, fill: "var(--muted)" }, 0);
  trend.forEach((d, i) => {
    const x = pad.l + (i + 0.5) * ((W - pad.l - pad.r) / trend.length) - bw / 2;
    let y = H - pad.b;
    for (const k of ["safe", "suspicious", "phishing"]) {
      const hh = (d[k] / max) * (H - pad.t - pad.b);
      if (hh > 0) { el("rect", { x, y: y - hh, width: bw, height: hh, fill: COL[k], rx: 2 }); y -= hh; }
    }
    el("text", { x: x + bw / 2, y: H - 8, "text-anchor": "middle", "font-size": 11, fill: "var(--muted)" }, d.date.slice(5));
  });
  return svg;
}

/* ---------- model ---------- */
async function loadModel() {
  const box = clear($("#modelContent"));
  try {
    const m = await api("/api/model");
    if (!m.loaded) { box.append(h("div", { class: "banner" }, "No trained model is loaded. Run train.py with a labelled URL dataset, then restart the server.")); return; }
    const mt = m.metrics;
    if (/synthetic/i.test(m.trained_on || "")) box.append(h("div", { class: "banner" }, "This model was trained on SYNTHETIC smoke-test data. The metrics below are not meaningful. Train on a real dataset before reporting results."));
    box.append(h("div", { class: "tiles" }, tile(m.name.replace(/_/g, " "), "selected model"), tile(m.trained_on, "trained on"),
      tile(mt ? mt.n_urls.toLocaleString() : "n/a", "URLs in dataset"), tile(mt ? mt.inference_ms_per_url + " ms" : "n/a", "per URL, features + prediction")));
    if (mt) {
      const rows = Object.entries(mt.candidates);
      box.append(h("div", { class: "panel tw" }, h("h3", {}, "Model comparison"), h("p", { class: "muted", style: "margin:0 0 10px;font-size:14.5px" }, mt.evaluation + ". Higher is better except the two error rates."),
        h("table", {}, h("thead", {}, h("tr", {}, ["Model", "Accuracy", "Precision", "Recall", "F1", "False positive rate", "False negative rate", "ROC AUC"].map((c, i) => h("th", { class: i ? "num" : "" }, c)))),
          h("tbody", {}, rows.map(([name, x]) => h("tr", {}, h("td", {}, name.replace(/_/g, " "), name === mt.selected ? h("span", { class: "chip sev-info", style: "margin-left:8px" }, "selected") : null),
            h("td", { class: "num mono" }, pct(x.accuracy, 2)), h("td", { class: "num mono" }, pct(x.precision, 2)), h("td", { class: "num mono" }, pct(x.recall, 2)), h("td", { class: "num mono" }, pct(x.f1, 2)),
            h("td", { class: "num mono" }, pct(x.false_positive_rate, 2)), h("td", { class: "num mono" }, pct(x.false_negative_rate, 2)), h("td", { class: "num mono" }, x.roc_auc == null ? "n/a" : x.roc_auc.toFixed(4))))))));
      const rs = mt.random_split_metrics_for_selected, hs = mt.selected_metrics;
      box.append(h("div", { class: "panel" }, h("h3", {}, "Does it generalise to new domains?"),
        h("p", { style: "margin:0;max-width:70ch" }, `Scored on domains it never saw in training, the selected model reaches F1 ${pct(hs.f1, 2)}. On an ordinary random split it would reach ${pct(rs.f1, 2)}. The gap (${(mt.generalization_gap_f1 * 100).toFixed(2)} points) shows how much a random split overstates real-world performance.`),
        h("p", { class: "muted", style: "margin:10px 0 0;font-size:14px" }, mt.note)));
    }
    box.append(h("div", { class: "panel" }, h("h3", {}, "Threat-intelligence sources"),
      Object.entries(m.providers).map(([k, v]) => h("div", { class: "status-row" }, h("span", {}, PROVIDER_LABEL[k] || k),
        h("span", { class: v.configured ? "s-ok" : "s-off" }, v.configured ? (v.entries ? v.entries.toLocaleString() + " entries" : "Configured") : "Not configured")))));
  } catch (e) { box.append(h("div", { class: "error" }, e.message)); }
}

route();
