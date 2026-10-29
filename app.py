from flask import Flask, request, jsonify, render_template
import re
import urllib.parse
import socket
import ssl
import datetime
import math
from collections import Counter
app = Flask(__name__)
# ─────────────────────────────────────────────
# Phishing Detection Engine
# ─────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "account", "update", "secure", "verify", "banking",
    "paypal", "amazon", "apple", "google", "microsoft", "netflix", "ebay",
    "confirm", "password", "credential", "wallet", "free", "prize", "winner",
    "urgent", "alert", "suspended", "verify", "validate", "limited", "offer",
    "click", "here", "now", "access", "support", "helpdesk", "recover",
    "reset", "unusual", "activity", "security", "checkout", "invoice",
    "payment", "billing", "update", "expire", "disabled", "blocked"
]
TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "netflix.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "wikipedia.org", "reddit.com",
    "stackoverflow.com", "paypal.com", "ebay.com", "yahoo.com",
    "bing.com", "zoom.us", "dropbox.com", "adobe.com", "spotify.com"
]
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".space", ".icu", ".vip", ".cam",
    ".bid", ".stream", ".download", ".review", ".trade", ".loan",
    ".work", ".party", ".date", ".win", ".racing", ".cricket"
]
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rebrand.ly",
    "is.gd", "buff.ly", "short.link", "tiny.cc", "shorte.st",
    "adf.ly", "bc.vc", "snip.li", "cutt.ly"
]
def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())
def check_ssl(hostname: str) -> dict:
    """Check SSL certificate validity."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(4)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_dt - datetime.datetime.utcnow()).days
                return {"valid": True, "days_remaining": days_left, "expired": days_left < 0}
            return {"valid": True, "days_remaining": None, "expired": False}
    except Exception as e:
        return {"valid": False, "days_remaining": None, "expired": None, "error": str(e)}
def analyze_url(raw_url: str) -> dict:
    # Normalize
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {"error": "Invalid URL format"}
    hostname  = parsed.hostname or ""
    path      = parsed.path or ""
    query     = parsed.query or ""
    full_path = path + "?" + query if query else path
    findings  = []
    score     = 0   # 0 = safe  … higher = more suspicious
    # ── 1. HTTPS check ──
    has_https = parsed.scheme == "https"
    if not has_https:
        findings.append({"type": "warning", "message": "No HTTPS – connection is unencrypted"})
        score += 25
    else:
        findings.append({"type": "safe", "message": "Uses HTTPS encryption"})
    # ── 2. URL shortener ──
    is_shortener = any(s in hostname for s in URL_SHORTENERS)
    if is_shortener:
        findings.append({"type": "danger", "message": "URL shortener detected – real destination is hidden"})
        score += 30
    # ── 3. IP address instead of domain ──
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(hostname):
        findings.append({"type": "danger", "message": "IP address used instead of domain name"})
        score += 35
    # ── 4. Suspicious TLD ──
    matched_tld = next((t for t in SUSPICIOUS_TLDS if hostname.endswith(t)), None)
    if matched_tld:
        findings.append({"type": "danger", "message": f"High-risk TLD detected: {matched_tld}"})
        score += 20
    # ── 5. Trusted-brand impersonation ──
    impersonated = []
    for brand in TRUSTED_DOMAINS:
        brand_name = brand.split(".")[0]
        if brand_name in hostname and not hostname.endswith(brand):
            impersonated.append(brand_name)
    if impersonated:
        findings.append({
            "type": "danger",
            "message": f"Possible brand impersonation: {', '.join(impersonated)}"
        })
        score += 40
    # ── 6. Trusted domain (whitelist) ──
    is_trusted = any(hostname == td or hostname.endswith("." + td) for td in TRUSTED_DOMAINS)
    if is_trusted and not impersonated:
        findings.append({"type": "safe", "message": "Domain is on the trusted-brands list"})
        score -= 20
    # ── 7. Suspicious keywords in URL ──
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if len(found_keywords) >= 3:
        findings.append({"type": "danger", "message": f"Multiple phishing keywords: {', '.join(found_keywords[:5])}"})
        score += 20
    elif found_keywords:
        findings.append({"type": "warning", "message": f"Phishing-related keywords: {', '.join(found_keywords)}"})
        score += 10
    # ── 8. Subdomain count ──
    parts = hostname.split(".")
    sub_count = len(parts) - 2
    if sub_count >= 3:
        findings.append({"type": "danger", "message": f"Excessive subdomains ({sub_count}) – common obfuscation tactic"})
        score += 15
    elif sub_count == 2:
        findings.append({"type": "warning", "message": "Multiple subdomains detected"})
        score += 5
    # ── 9. URL length ──
    url_len = len(url)
    if url_len > 150:
        findings.append({"type": "danger", "message": f"Very long URL ({url_len} chars) – often used to confuse users"})
        score += 15
    elif url_len > 75:
        findings.append({"type": "warning", "message": f"Unusually long URL ({url_len} chars)"})
        score += 5
    # ── 10. Special characters & obfuscation ──
    special_chars = re.findall(r"[@%]", url)
    if special_chars:
        findings.append({"type": "danger", "message": f"Obfuscation characters detected: {', '.join(set(special_chars))}"})
        score += 20
    # ── 11. Numeric domains ──
    if re.search(r"\d{5,}", hostname):
        findings.append({"type": "warning", "message": "Long numeric sequence in domain – uncommon for legitimate sites"})
        score += 10
    # ── 12. Entropy (randomness) ──
    entropy = calculate_entropy(hostname)
    if entropy > 3.8:
        findings.append({"type": "warning", "message": f"High domain entropy ({entropy:.2f}) – may be algorithmically generated"})
        score += 10
    # ── 13. Hyphen overuse ──
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        findings.append({"type": "danger", "message": f"Many hyphens in domain ({hyphen_count}) – phishing pattern"})
        score += 15
    elif hyphen_count >= 1:
        findings.append({"type": "warning", "message": "Hyphens in domain name"})
        score += 5
    # ── 14. SSL check (live) ──
    if has_https and hostname:
        ssl_result = check_ssl(hostname)
        if ssl_result["valid"]:
            days = ssl_result.get("days_remaining")
            if days is not None and days < 30:
                findings.append({"type": "warning", "message": f"SSL certificate expiring soon ({days} days)"})
                score += 10
            elif days is not None:
                findings.append({"type": "safe", "message": f"Valid SSL certificate ({days} days remaining)"})
        else:
            findings.append({"type": "danger", "message": "SSL certificate invalid or could not be verified"})
            score += 20
    # ── Final verdict ──
    score = max(0, min(score, 100))
    if score <= 15:
        risk_level = "safe"
        verdict    = "This URL appears to be SAFE"
        color      = "green"
    elif score <= 40:
        risk_level = "low"
        verdict    = "LOW risk – proceed with caution"
        color      = "yellow"
    elif score <= 65:
        risk_level = "medium"
        verdict    = "MEDIUM risk – likely suspicious"
        color      = "orange"
    else:
        risk_level = "high"
        verdict    = "HIGH risk – likely a PHISHING URL"
        color      = "red"
    return {
        "url":        url,
        "hostname":   hostname,
        "score":      score,
        "risk_level": risk_level,
        "verdict":    verdict,
        "color":      color,
        "has_https":  has_https,
        "findings":   findings,
        "stats": {
            "url_length":    url_len,
            "subdomain_count": sub_count,
            "entropy":       round(entropy, 2),
            "keyword_hits":  len(found_keywords),
            "hyphen_count":  hyphen_count,
        }
    }
# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")
@app.route("/api/check", methods=["POST"])
def check_url():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = analyze_url(url)
    return jsonify(result)
if __name__ == "__main__":
    app.run(debug=True, port=5050)