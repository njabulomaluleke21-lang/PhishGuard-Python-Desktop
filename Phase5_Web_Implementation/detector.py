"""Rule-based phishing email analysis. No machine learning or network requests."""
import re
from urllib.parse import urlparse

RULES = {
    "urgency": {"weight": 25, "terms": ["act now", "urgent", "immediately", "within 24 hours", "account will be suspended", "final warning", "limited time"], "label": "Urgent or threatening language"},
    "credentials": {"weight": 30, "terms": ["verify your password", "confirm your password", "login details", "sign in to verify", "update your password", "account credentials", "one-time pin", "otp"], "label": "Request for passwords or login details"},
    "payment_reward": {"weight": 20, "terms": ["claim your prize", "you have won", "processing fee", "send payment", "bank details", "refund is waiting", "gift card", "payment required"], "label": "Payment, prize or reward bait"},
    "suspicious_links": {"weight": 25, "terms": ["click here", "open the link", "follow this link", "http://"], "label": "Potentially suspicious link wording"},
    "impersonation": {"weight": 15, "terms": ["dear customer", "dear user", "security department", "it support team", "your bank", "microsoft support", "official support"], "label": "Generic or authority-based impersonation wording"},
}
URL_RE = re.compile(r"https?://[^\s<>\]\[()]+|www\.[^\s<>\]\[()]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}

def _normalise_url(raw):
    raw = raw.rstrip(".,;:!?)\"'")
    return raw if "://" in raw else "http://" + raw

def analyse_email(email_text):
    text = (email_text or "").strip()
    if not text:
        return {"score": 0, "risk": "Not analysed", "findings": [], "urls": [], "summary": "Enter email text before starting an analysis."}
    lowered, findings, score = text.lower(), [], 0
    for rule in RULES.values():
        matched = [term for term in rule["terms"] if term in lowered]
        if matched:
            score += rule["weight"]
            findings.append({"category": rule["label"], "matched": matched, "points": rule["weight"]})
    urls = []
    for match in URL_RE.findall(text):
        parsed = urlparse(_normalise_url(match))
        host = (parsed.hostname or "").lower()
        flags = []
        if host in SHORTENERS: flags.append("URL shortener")
        if parsed.scheme == "http": flags.append("Unencrypted HTTP link")
        if re.search(r"\d+\.\d+\.\d+\.\d+", host): flags.append("IP-address host")
        urls.append({"url": match.rstrip(".,;:!?)\"'"), "host": host, "flags": flags})
        if flags:
            score += 15
            findings.append({"category": "URL structure warning", "matched": flags, "points": 15})
    score = min(score, 100)
    risk = "Low" if score < 20 else "Medium" if score < 50 else "High"
    if score == 0:
        summary = "No configured warning rules were triggered. This does not guarantee that the email is safe."
    elif risk == "High":
        summary = "Several warning indicators were detected. Do not open links or share sensitive information until independently verified."
    elif risk == "Medium":
        summary = "Some warning indicators were detected. Verify the sender through a trusted channel before responding."
    else:
        summary = "A small number of warning indicators were detected. Remain cautious and verify unexpected requests."
    return {"score": score, "risk": risk, "findings": findings, "urls": urls, "summary": summary}
