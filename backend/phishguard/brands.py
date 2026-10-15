"""Brand registry used for impersonation and typosquatting checks.

Each brand has:
  keywords  - lowercase strings that attackers put in hostnames/paths to look legitimate
  official  - registered domains that really belong to the brand

Sri Lankan brands are included because the project targets local users, but the
list is plain data: extend it for your own market.
"""

BRANDS = {
    # --- Global ---
    "paypal":    {"keywords": ["paypal"], "official": ["paypal.com", "paypal.me"]},
    "google":    {"keywords": ["google", "gmail"], "official": ["google.com", "gmail.com", "youtube.com", "google.lk", "goo.gl"]},
    "microsoft": {"keywords": ["microsoft", "office365", "outlook", "onedrive"], "official": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com"]},
    "apple":     {"keywords": ["apple", "icloud", "appleid"], "official": ["apple.com", "icloud.com"]},
    "amazon":    {"keywords": ["amazon"], "official": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazonaws.com"]},
    "facebook":  {"keywords": ["facebook"], "official": ["facebook.com", "fb.com", "meta.com", "fb.me"]},
    "instagram": {"keywords": ["instagram"], "official": ["instagram.com"]},
    "whatsapp":  {"keywords": ["whatsapp"], "official": ["whatsapp.com", "wa.me"]},
    "netflix":   {"keywords": ["netflix"], "official": ["netflix.com"]},
    "linkedin":  {"keywords": ["linkedin"], "official": ["linkedin.com", "lnkd.in"]},
    "dhl":       {"keywords": ["dhl"], "official": ["dhl.com", "dhl.de"]},
    "fedex":     {"keywords": ["fedex"], "official": ["fedex.com"]},
    "ebay":      {"keywords": ["ebay"], "official": ["ebay.com", "ebay.de", "ebay.co.uk"]},
    "binance":   {"keywords": ["binance"], "official": ["binance.com"]},
    # --- Sri Lanka ---
    "commercialbank": {"keywords": ["commercialbank", "combank"], "official": ["combank.lk", "combank.net"]},
    "sampath":        {"keywords": ["sampath"], "official": ["sampath.lk"]},
    "bankofceylon":   {"keywords": ["bankofceylon"], "official": ["boc.lk"]},
    "peoplesbank":    {"keywords": ["peoplesbank"], "official": ["peoplesbank.lk"]},
    "seylan":         {"keywords": ["seylan"], "official": ["seylan.lk"]},
    "ndb":            {"keywords": ["ndbbank"], "official": ["ndbbank.com"]},
    "dfcc":           {"keywords": ["dfcc"], "official": ["dfcc.lk"]},
    "nsb":            {"keywords": ["nationalsavingsbank"], "official": ["nsb.lk"]},
    "dialog":         {"keywords": ["dialog"], "official": ["dialog.lk"]},
    "mobitel":        {"keywords": ["mobitel", "sltmobitel"], "official": ["mobitel.lk", "sltmobitel.lk", "slt.lk"]},
    "daraz":          {"keywords": ["daraz"], "official": ["daraz.lk"]},
    "slpost":         {"keywords": ["srilankapost", "slpost"], "official": ["slpost.lk", "srilankapost.gov.lk"]},
    "ird":            {"keywords": ["inlandrevenue"], "official": ["ird.gov.lk"]},
}

# Extra brands used ONLY for the page-title check (not for the URL model's features, which were trained
# on the list above). A page whose title starts with one of these names but is hosted elsewhere is
# claiming an identity it does not have.
PAGE_BRANDS = {
    "roblox":    {"keywords": ["roblox"], "official": ["roblox.com", "rbxcdn.com"]},
    "tiktok":    {"keywords": ["tiktok"], "official": ["tiktok.com", "tiktokv.com", "tiktokcdn.com"]},
    "ledger":    {"keywords": ["ledger"], "official": ["ledger.com"]},
    "coinbase":  {"keywords": ["coinbase"], "official": ["coinbase.com"]},
    "metamask":  {"keywords": ["metamask"], "official": ["metamask.io"]},
    "trustwallet": {"keywords": ["trust wallet", "trustwallet"], "official": ["trustwallet.com"]},
    "trezor":    {"keywords": ["trezor"], "official": ["trezor.io"]},
    "imtoken":   {"keywords": ["imtoken"], "official": ["token.im", "imtoken.com"]},
    "meta":      {"keywords": ["meta for business", "meta business"], "official": ["meta.com", "facebook.com"]},
    "steam":     {"keywords": ["steam"], "official": ["steampowered.com", "steamcommunity.com"]},
    "discord":   {"keywords": ["discord"], "official": ["discord.com", "discord.gg"]},
    "telegram":  {"keywords": ["telegram"], "official": ["telegram.org", "t.me"]},
    "adobe":     {"keywords": ["adobe"], "official": ["adobe.com"]},
    "dropbox":   {"keywords": ["dropbox"], "official": ["dropbox.com"]},
    "docusign":  {"keywords": ["docusign"], "official": ["docusign.com", "docusign.net"]},
    "wetransfer": {"keywords": ["wetransfer"], "official": ["wetransfer.com"]},
    "swisscom":  {"keywords": ["swisscom"], "official": ["swisscom.ch"]},
    "sunrise":   {"keywords": ["sunrise"], "official": ["sunrise.ch"]},
}

# Words that appear in phishing hostnames/paths far more than in legitimate ones.
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "log-in", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "banking", "wallet", "invoice", "support",
    "unlock", "suspend", "billing", "payment", "recover", "authenticate",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "icu", "gq", "tk", "ml", "cf",
    "ga", "work", "rest", "country", "kim", "loan", "men", "support", "cam",
}

# Platforms where anyone can publish a site on a subdomain for free. Legitimate people use them too,
# so this is only a small signal; but they are also where a large share of current phishing is hosted.
FREE_HOSTS = {
    "pages.dev", "netlify.app", "vercel.app", "github.io", "blogspot.com", "weebly.com", "wixsite.com",
    "glitch.me", "web.app", "firebaseapp.com", "workers.dev", "jimdofree.com", "typedream.app",
    "webflow.io", "craftum.io", "b12sites.com", "000webhostapp.com", "herokuapp.com", "onrender.com",
    "netlify.com", "surge.sh", "repl.co", "replit.app", "framer.app", "carrd.co", "godaddysites.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}


def official_domains() -> set:
    out = set()
    for b in BRANDS.values():
        out.update(b["official"])
    return out
