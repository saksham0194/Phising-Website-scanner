import os, re, base64, ipaddress
from urllib.parse import urlparse
from typing import Optional
import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from dotenv import load_dotenv

APP_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(APP_DIR, "API.env"))
app = FastAPI(title="PhishGuard", version="1.0.0")
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
GSB_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
TIMEOUT = 12

class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not accepted.")
    host = parsed.hostname.rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Private, local and reserved IP addresses cannot be scanned.")
    except ValueError as e:
        if "cannot be scanned" in str(e):
            raise
        # Not an IP: validate hostname format.
        if len(host) > 253 or not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", host):
            raise ValueError("The domain name appears invalid.")
    return raw

def heuristic_checks(url: str) -> list[dict]:
    p = urlparse(url)
    host = p.hostname or ""
    findings = []
    if p.scheme != "https":
        findings.append({"name": "HTTPS", "status": "warning", "detail": "The URL uses HTTP, so traffic is not protected by HTTPS."})
    else:
        findings.append({"name": "HTTPS", "status": "info", "detail": "The URL uses HTTPS. This encrypts traffic but does not prove the site is trustworthy."})
    if "@" in p.netloc:
        findings.append({"name": "URL user-info", "status": "warning", "detail": "The URL contains an @ symbol in its authority section, which can be used to disguise the destination."})
    if len(url) > 120:
        findings.append({"name": "Unusually long URL", "status": "warning", "detail": "Long URLs can obscure the real destination. This is a weak signal, not proof of phishing."})
    if host.startswith("xn--") or ".xn--" in host:
        findings.append({"name": "Punycode domain", "status": "warning", "detail": "The domain contains an internationalized label. Check carefully for lookalike characters."})
    if host.count("-") >= 3:
        findings.append({"name": "Hyphen-heavy domain", "status": "warning", "detail": "The domain contains several hyphens. This alone does not establish maliciousness."})
    if re.search(r"(login|verify|secure|account|update|wallet|password)", host):
        findings.append({"name": "Sensitive keywords", "status": "warning", "detail": "The hostname contains words commonly used in account or credential lures."})
    if not findings:
        findings.append({"name": "Basic URL checks", "status": "info", "detail": "No obvious URL-format warning was detected. This is not a safety verdict."})
    return findings

def scan_virustotal(url: str) -> dict:
    if not VT_KEY:
        return {"available": False, "provider": "VirusTotal", "detail": "API key not configured."}
    headers = {"x-apikey": VT_KEY}
    try:
        # URL identifier is URL-safe base64 without padding, as required by VT.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=TIMEOUT)
        if r.status_code == 404:
            submitted = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=TIMEOUT)
            if submitted.status_code not in (200, 201):
                return {"available": False, "provider": "VirusTotal", "detail": f"Submission unavailable (HTTP {submitted.status_code})."}
            return {"available": True, "provider": "VirusTotal", "pending": True, "detail": "URL submitted. Scan results may take a short time to become available."}
        r.raise_for_status()
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"available": True, "provider": "VirusTotal", "stats": stats, "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)), "detail": "Latest available engine results."}
    except requests.RequestException:
        return {"available": False, "provider": "VirusTotal", "detail": "Could not reach VirusTotal. Try again later."}

def scan_google(url: str) -> dict:
    if not GSB_KEY:
        return {"available": False, "provider": "Google Safe Browsing", "detail": "API key not configured."}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"
    body = {
        "client": {"clientId": "phishguard-local", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(endpoint, json=body, timeout=TIMEOUT)
        r.raise_for_status()
        matches = r.json().get("matches", [])
        return {"available": True, "provider": "Google Safe Browsing", "matches": len(matches), "threats": [m.get("threatType", "UNKNOWN") for m in matches], "detail": "Known threat-list lookup."}
    except requests.RequestException:
        return {"available": False, "provider": "Google Safe Browsing", "detail": "Could not reach Google Safe Browsing. Try again later."}

@app.get("/")
def home():
    return FileResponse(os.path.join(APP_DIR, "static", "index.html"))

@app.get("/api/health")
def health():
    return {"ok": True, "virustotal_configured": bool(VT_KEY), "google_safe_browsing_configured": bool(GSB_KEY)}

@app.post("/api/scan")
def scan(req: ScanRequest):
    try:
        url = normalize_url(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    vt = scan_virustotal(url)
    gsb = scan_google(url)
    heuristics = heuristic_checks(url)

    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    google_hits = gsb.get("matches", 0)
    score = min(100, google_hits * 75 + malicious * 12 + suspicious * 5)
    score = max(score, min(45, sum(1 for x in heuristics if x["status"] == "warning") * 8))
    if google_hits or malicious >= 3:
        verdict = "Malicious"
    elif malicious or suspicious or score >= 25:
        verdict = "Suspicious"
    elif not vt["available"] and not gsb["available"]:
        verdict = "Unverified"
    else:
        verdict = "No known threat detected"

    return {
        "url": url, "domain": urlparse(url).hostname, "verdict": verdict,
        "risk_score": score, "scanned_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "providers": [vt, gsb], "checks": heuristics,
        "disclaimer": "A clean result does not guarantee a website is safe. Threat databases can be incomplete or delayed. Do not enter passwords or payment details on unfamiliar sites."
    }
