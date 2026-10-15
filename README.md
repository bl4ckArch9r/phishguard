# PhishGuard — AI-powered phishing detection and response

Paste a link and PhishGuard decides **Safe / Suspicious / Phishing**, gives a 0–100 risk score, and shows the evidence behind it. Detection is not rule-matching alone: a trained machine-learning model reads the URL, and the result is cross-checked against what the page actually does, the domain's history and threat feeds.

## How one scan works

| Layer | What it does | Needs network |
|---|---|---|
| **URL AI model** | Character n-grams + lexical features of the address, logistic regression, Platt-calibrated | no |
| **Page-content AI model** | TF-IDF over the page's title, wording and form labels + 20 structure numbers, calibrated; limited to 30 points because it is a weak classifier alone | yes |
| **Address rules** | IP hosts, `@` tricks, shorteners, punycode, keyword stuffing | no |
| **Brand impersonation** | Brand names (incl. Sri Lankan banks and telcos) used by a domain that is not the brand's; typosquatting | no |
| **Page behaviour** | Password forms posting to another domain, hidden iframes, obfuscated JS, redirect chains, scam wording, ClickFix clipboard tricks | yes |
| **Domain & certificate** | DNS, TLS trust/age, domain registration age (RDAP) | yes |
| **Threat intelligence** | Local OpenPhish feed, VirusTotal, Google Safe Browsing, URLhaus | yes (+ keys) |

`risk.py` merges the layers under per-layer caps into a 0-100 score: below 35 Safe, 35-64 Suspicious, 65 and above Phishing. A feed hit sets a floor of 92. A layer that is unavailable adds nothing and is shown as "not configured / could not reach", never as "clean".

## Measured results (honest numbers)

- **URL model:** trained on 297,021 labelled URLs with a domain-held-out split: recall 71.1%, false-positive rate 1.6%, ROC-AUC 0.939.
- **Page model:** 3,641 collected pages: combined variant recall 29.6%, FPR 2.0%, ROC-AUC 0.876.
- **Full system:** on 200 fresh OpenPhish URLs and 200 legitimate Tranco sites never used for tuning (feed shortcut disabled): 70.0% recall with 0 false positives at the phishing threshold, 89.5% recall with 2.5% false positives at the suspicious threshold, ROC-AUC 0.979. About a third of detections depend on a hosting provider's malware warning.
- Small sample, one time period, and Tranco sites are not a perfect stand-in for what users check. Treat these as indicative, not guarantees. See the report for the full method and limits.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd backend
uvicorn phishguard.main:app --port 8000
# open http://127.0.0.1:8000
```

Trained models are not stored in the repository (they are large and reproducible). The app runs without them (the AI layers are reported as missing); to enable them, train as below.

## Train the model on real data

```bash
cd backend
python train.py --data path/to/urls.csv
```

The CSV needs a URL column and a label column (auto-detected; override with `--url-col` / `--label-col`). Labels like `1/0`, `phishing/legitimate`, `bad/good`, `malicious/benign` are understood.

**You need a dataset of raw URLs**: a public Kaggle phishing-URL dataset, OpenPhish for fresh phishing URLs and the Tranco list for legitimate ones. `python tools/build_dataset.py` merges them into `data/urls_plus.csv`. Check each licence.

The page-content model is trained separately: `python tools/collect_pages.py` downloads pages (use a network without a web filter, which returns its own block pages), then `python tools/train_page_model.py`. `python tools/evaluate_system.py` runs the end-to-end evaluation.

What `train.py` does and reports:
- **Domain-held-out split** — no registered domain appears in both train and test. This is the honest number; many papers use a random split, which lets a model memorise domains (the generalisation problem in your proposal, ref. [3]).
- Also trains the same model on a **random split** and prints the gap, so you can show how much that overstates performance.
- Accuracy, precision, recall, F1, false-positive rate, false-negative rate, ROC-AUC, confusion matrix, and **detection time per URL** — exactly the metrics in your Table 3.1.
- Compares two candidate models and deploys the best by F1. Saves `models/phishing_model.joblib` and `models/metrics.json`, which the **Model** tab displays.

> `tools/make_synthetic_data.py` generates a fake dataset **for smoke-testing the pipeline only**. Its patterns are invented, so the metrics are meaningless (it scores ~100%). The Model tab shows a warning whenever the model was trained on a file named `synthetic`. Never put those numbers in a report.

## Rendered-page (dynamic) behaviour analysis

Beyond reading the page's HTML, PhishGuard can load it in an isolated headless Chromium and watch what it does once its JavaScript runs: login forms built by script, pages that show a different document to scanners than to browsers (cloaking), automatic form submits, pop-ups, dialogs, download attempts. It also returns a small screenshot ("Safe preview").

```bash
pip install -r requirements.txt
playwright install chromium          # one-time, ~150 MB
```
The browser has no network of its own (DNS disabled, dead proxy): every request it makes is answered by the same SSRF-safe, IP-pinned fetcher as the static scan, POSTs are blocked, downloads refused, and each scan uses a fresh context. If Playwright or Chromium is missing, PhishGuard falls back to static analysis. Turn it off with `PHISHGUARD_BROWSER=0`. On Windows, run uvicorn **without** `--reload`. In Docker add `playwright install --with-deps chromium` to the image.

## Threat feeds

```bash
cd backend
python -m phishguard.threat_intel refresh      # downloads the OpenPhish community feed to data/blocklist.txt
export VIRUSTOTAL_API_KEY=...  GOOGLE_SAFE_BROWSING_KEY=...  URLHAUS_AUTH_KEY=...   # optional
```
See `.env.example`. The feed download and the three provider calls could not be run against the real services during development (no internet in the build sandbox); their response parsing is unit-tested with mocked responses. Test them once with your own keys.

## API

```bash
curl -X POST http://127.0.0.1:8000/api/analyze -H 'Content-Type: application/json' \
     -d '{"url":"br-icloud.com.br","deep":true}'
```
`POST /api/analyze` · `GET /api/history` · `GET /api/scans/{id}` · `POST /api/scans/{id}/report` (`false_positive` / `false_negative` / `confirmed`) · `GET /api/stats` · `GET /api/model` · `GET /api/health` · interactive docs at `/api/docs`.

The URL is sent in the POST body, not the query string, so it doesn't end up in access logs.

## Tests

```bash
cd backend && pytest -q                      # 54 passed, 1 skipped (needs a trained model)
# UI + XSS check in a simulated DOM, against a running server:
npm i jsdom && PHISHGUARD_URL=http://127.0.0.1:8000 node tests/ui_dom_test.js
```
Covered: regression cases (`facebook.unitedcolleges.net`, `signin.eby.de.zukruygxctzmmqi.civpro.co.za`, `br-icloud.com.br` — all scored "Safe" by the earlier rule-based PhishBane), known-good sites, credential-harvesting page analysis, live fetch against a local test server, SSRF blocking, threat-feed hits, API validation / rate limit / API key, and that hostile page content cannot inject HTML into the dashboard.

## Deploy safely

PhishGuard fetches URLs that strangers give it, which is the textbook SSRF situation. Built in: http/https only, DNS resolved once and every address must be public, the request is pinned to that IP (closes DNS-rebinding), redirects re-validated per hop, size/time caps, no form submission. **Also** run it where it cannot reach your internal network:

```bash
docker build -t phishguard .
docker run -p 8000:8000 -v phishguard-data:/data --env-file .env phishguard
```
Put it behind HTTPS (Caddy / nginx / your host's TLS), set `PHISHGUARD_API_KEY` if it is public, and never set `PHISHGUARD_ALLOW_PRIVATE` outside tests.

## Mapping to the project proposal

| Proposal component | Where |
|---|---|
| 1 · AI Phishing Detection Engine | `train.py`, `features.py`, `model_service.py` |
| 2 · URL & Website Intelligence Analyzer | `page_analyzer.py`, `domain_intel.py`, `netguard.py` |
| 3 · Threat Intelligence & Risk Correlation | `threat_intel.py`, `risk.py` |
| 4 · Awareness, Response & Reporting | `frontend/`, `storage.py`, `/api/*` (explanations, recommended actions, history, statistics, user reports) |

## What has and hasn't been verified

Verified: training pipelines; unit/API tests; front-end DOM and XSS safety; page analysis, redirects and SSRF blocking against local servers; end-to-end evaluation on fresh phishing and legitimate sites (see Measured results).

Not verified: performance on targeted phishing that clones a bank's full site, long-term drift as campaigns change, and use under real user load.

## Limitations

- URL + page analysis can't see everything: phishing pages that only show their form after JavaScript runs, cloaking that serves scanners a harmless page, and brand-new campaigns can be missed. Treat scores as likelihood, not proof.
- Brand matching uses a small hand-made list (`brands.py`) and can false-alarm on brand words that are also ordinary names. Extend and review it.
- Rule weights are reasoned defaults, not fitted values. Tune them on your held-out set and record the change in your report.
- Scan history is stored without query strings; no credentials are collected or processed. Only scan links you are entitled to analyse.

## Licence and responsible use

Academic project (SLIIT IE3092 Information Security Project). Only scan links you are entitled to analyse. Do not point the page fetcher at internal networks.
