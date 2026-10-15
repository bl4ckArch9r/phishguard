"""Page behaviour analysis: what does the page DO, not just what does the URL look like?

Works on HTML fetched by netguard.safe_fetch. Nothing is executed or submitted;
the HTML is only parsed.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from . import features as F
from .brands import BRANDS, PAGE_BRANDS
from .evidence import Evidence

OBFUSCATION = re.compile(r"(eval\s*\(|atob\s*\(|unescape\s*\(|fromCharCode|document\.write\s*\(\s*unescape)", re.I)
NO_RIGHT_CLICK = re.compile(r"(contextmenu|event\.button\s*==\s*2|oncontextmenu\s*=\s*[\"']return false)", re.I)


# Social-engineering language in the VISIBLE text, grouped by what the lure is trying to achieve.
# One group is weak evidence (security blogs mention "seed phrase" too); two or more together is strong.
LURES = {
    "credential": re.compile(r"verify your (account|identity)|confirm your identity|account (has been |is )?(suspended|locked|limited|restricted)|"
                             r"unusual (sign-?in )?activity|update your (payment|billing)|password (has )?expired|session (has )?expired|"
                             r"re-?enter your password", re.I),
    "crypto":     re.compile(r"seed phrase|recovery phrase|secret recovery|12[- ]word|24[- ]word|connect (your )?wallet|validate (your )?wallet|private key", re.I),
    "prize":      re.compile(r"free robux|claim your (prize|reward|gift)|you (have )?won|congratulations!? you|limited[- ]time (reward|offer)", re.I),
    "fine":       re.compile(r"tax (penalty|fine|notice)|कर दंड|traffic fine|unpaid (toll|fine)|customs (fee|charge)|parcel .{0,40}(held|undelivered)|delivery fee", re.I),
}
CLICKFIX_PROMPT = re.compile(r"(win(dows)?\s*\+\s*r|ctrl\s*\+\s*v|press\s+ctrl|paste (it|the|this) (in|into))", re.I)
CLICKFIX_SCRIPT = re.compile(r"(navigator\.clipboard\.writeText|execCommand\(['\"]copy)", re.I)
CLICKFIX_PAYLOAD = re.compile(r"(powershell|mshta|cmd(\.exe)?\s*/c|curl\s+http|wget\s+http|\-enc\b)", re.I)

_ANALYTICS = {"googletagmanager.com", "google-analytics.com", "doubleclick.net",
              "googleadservices.com", "hotjar.com", "clarity.ms"}


def _reg(url: str) -> str:
    host = urlsplit(url).hostname or ""
    return F.registered_domain(host) if host else ""


def analyze_page(final_url: str, html: str, chain: list) -> tuple[list[Evidence], dict]:
    ev: list[Evidence] = []
    facts: dict = {}
    page_reg = _reg(final_url)
    original_reg = _reg(chain[0][0]) if chain else page_reg

    # ---- redirects --------------------------------------------------
    hops = len(chain) - 1
    facts["redirect_hops"] = max(hops, 0)
    if original_reg and page_reg and original_reg != page_reg:
        ev.append(Evidence("page", "redirect_cross_domain", "Redirects to a different domain",
                           f"The link starts on {original_reg} but the page you land on is {page_reg}.",
                           "medium", 10))
    if hops >= 3:
        ev.append(Evidence("page", "redirect_chain", "Long redirect chain",
                           f"{hops} redirects before reaching the page.", "low", 5))

    if not html:
        return ev, facts

    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    facts["title"] = title[:120]
    text_len = len(soup.get_text(" ", strip=True))
    facts["text_length"] = text_len

    # ---- credential forms -----------------------------------------
    forms = soup.find_all("form")
    pw_inputs = soup.find_all("input", attrs={"type": re.compile("^password$", re.I)})
    facts["forms"] = len(forms)
    facts["password_fields"] = len(pw_inputs)

    if pw_inputs:
        is_https = final_url.lower().startswith("https://")
        if not is_https:
            ev.append(Evidence("page", "password_over_http", "Asks for a password over an unencrypted connection",
                               "Anything typed here travels in clear text.", "high", 20))
        else:
            ev.append(Evidence("page", "password_form", "Page contains a password field",
                               "Login pages are normal, but they are the target of phishing, so the other evidence matters.",
                               "info", 0))

    for form in forms:
        action = (form.get("action") or "").strip()
        has_pw = bool(form.find("input", attrs={"type": re.compile("^password$", re.I)}))
        if action.lower().startswith("mailto:"):
            ev.append(Evidence("page", "form_mailto", "Form sends data to an email address",
                               "Legitimate sites do not collect logins by emailing them.", "high", 20))
            continue
        if not has_pw:
            continue
        if action in ("", "#") or action.lower().startswith("javascript:"):
            ev.append(Evidence("page", "form_blank_action", "Login form has no real destination",
                               "The submit target is blank or script-driven, which hides where your data goes.",
                               "low", 5))
            continue
        target = urljoin(final_url, action)
        treg = _reg(target)
        if treg and page_reg and treg != page_reg:
            ev.append(Evidence("page", "form_cross_domain", "Login form sends your password to another domain",
                               f"The form on {page_reg} submits to {treg}.", "critical", 30))

    # ---- hidden / framed content -------------------------------------
    hidden_iframes = 0
    for fr in soup.find_all("iframe"):
        # Standard analytics fallbacks (e.g. the Google Tag Manager <noscript> frame) are
        # invisible by design on millions of legitimate sites, so they are not evidence.
        if fr.find_parent("noscript") is not None or _reg(urljoin(final_url, fr.get("src") or "")) in _ANALYTICS:
            continue
        style = (fr.get("style") or "").replace(" ", "").lower()
        w, h = str(fr.get("width", "")), str(fr.get("height", ""))
        if "display:none" in style or "visibility:hidden" in style or w in ("0", "1") or h in ("0", "1"):
            hidden_iframes += 1
    facts["hidden_iframes"] = hidden_iframes
    if hidden_iframes:
        ev.append(Evidence("page", "hidden_iframe", "Contains hidden frames",
                           f"{hidden_iframes} invisible frame(s) can load content without you seeing it.", "medium", 10))

    # ---- external resource ratio -------------------------------------
    srcs = [t.get("src") or t.get("href") for t in soup.find_all(["img", "script", "link"])]
    srcs = [s for s in srcs if s and not s.startswith(("data:", "#", "javascript:"))]
    external = 0
    for s in srcs:
        r = _reg(urljoin(final_url, s))
        if r and page_reg and r != page_reg:
            external += 1
    facts["resources"] = len(srcs)
    facts["external_resources"] = external
    if len(srcs) >= 6 and external / len(srcs) > 0.8:
        ev.append(Evidence("page", "mostly_external", "Most page resources come from other websites",
                           "Cloned phishing pages often hot-link the real brand's images and scripts.",
                           "low", 5))

    # ---- brand impersonation in content ------------------------------
    hay = (title + " " + " ".join(
        (m.get("content") or "") for m in soup.find_all("meta", attrs={"property": "og:site_name"}))).lower()
    for brand, cfg in BRANDS.items():
        if page_reg in cfg["official"]:
            continue
        if any(k in hay for k in cfg["keywords"]) and (pw_inputs or forms):
            ev.append(Evidence("page", "brand_in_title", f"Page presents itself as {brand.title()} but is not hosted by them",
                               f"The page title mentions {brand} and has a form, yet the domain is {page_reg}.",
                               "high", 25))
            break

    # A page without a form can still claim to BE a brand ("Instagram", "Roblox - Free Robux", "Ledger Live").
    # Only a title that STARTS with the brand name counts, so ordinary pages that merely mention it do not.
    if not any(e.id == "brand_in_title" for e in ev):
        head = title.lower().lstrip(" \t\n-|:·•")
        for brand, cfg in {**BRANDS, **PAGE_BRANDS}.items():
            if page_reg in cfg["official"]:
                continue
            if any(re.match(re.escape(k) + r"\b", head) for k in cfg["keywords"]):
                ev.append(Evidence("page", "brand_title_claim", f"Page title claims to be {brand.title()}, but is not hosted by them",
                                   f"The title starts with '{brand}' while the domain is {page_reg}.", "medium", 14))
                break

    # ---- favicon from elsewhere ---------------------------------------
    icon = soup.find("link", rel=lambda v: v and "icon" in " ".join(v).lower())
    if icon and icon.get("href"):
        ireg = _reg(urljoin(final_url, icon["href"]))
        if ireg and page_reg and ireg != page_reg:
            facts["favicon_domain"] = ireg
            if ireg in {d for b in BRANDS.values() for d in b["official"]}:
                ev.append(Evidence("page", "favicon_brand", "Borrows a well-known brand's icon",
                                   f"The page icon is loaded from {ireg}.", "medium", 10))

    # ---- scripts / evasion ----------------------------------------------
    scripts = " ".join(s.get_text() for s in soup.find_all("script"))[:200_000]
    obf = len(OBFUSCATION.findall(scripts))
    facts["obfuscation_hits"] = obf
    if obf >= 3:
        ev.append(Evidence("page", "obfuscated_js", "Obfuscated JavaScript",
                           "The page uses encoding tricks (eval/atob/unescape) often used to hide phishing code.",
                           "medium", 10))
    if NO_RIGHT_CLICK.search(scripts + html[:50_000]):
        ev.append(Evidence("page", "no_right_click", "Blocks right-click / inspection",
                           "Sites that stop you inspecting them are often hiding something.", "low", 5))
    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    if meta_refresh:
        ev.append(Evidence("page", "meta_refresh", "Page auto-redirects using a meta refresh",
                           "", "low", 3))

    # ---- social-engineering language and "ClickFix" ---------------------------
    vis = soup.get_text(" ", strip=True)[:30_000]
    groups = [g for g, rx in LURES.items() if rx.search(vis)]
    facts["lure_groups"] = groups
    if len(groups) >= 2:
        ev.append(Evidence("page", "lure_text", "Page text uses several scam-style lures",
                           "It combines " + " + ".join(groups) + " wording (account threats, wallet phrases, prizes, fines).",
                           "medium", 14))
    elif len(groups) == 1:
        ev.append(Evidence("page", "lure_text", "Page text uses scam-style wording",
                           f"It contains {groups[0]}-type wording. Weak on its own.", "low", 6))
    if CLICKFIX_SCRIPT.search(scripts) and (CLICKFIX_PAYLOAD.search(scripts) or CLICKFIX_PROMPT.search(vis)):
        ev.append(Evidence("page", "clickfix", "Page copies a command to your clipboard and tells you to run it",
                           "The 'ClickFix' trick: a fake human-check makes you paste a command into Windows Run or a terminal.",
                           "high", 30))

    # ---- thin credential page -------------------------------------------
    if pw_inputs and text_len < 400:
        ev.append(Evidence("page", "thin_login", "Almost nothing on the page except a login form",
                           "Real services usually surround logins with navigation and content.", "low", 5))

    return ev, facts
