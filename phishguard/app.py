import base64
import hashlib
import ipaddress
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

APP_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(APP_DIR, "API.env"))

app = FastAPI(title="PhishGuard", version="2.0.0")
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
GSB_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
TIMEOUT = 15
MAX_FILE_SIZE = 32 * 1024 * 1024
VT_BASE = "https://www.virustotal.com/api/v3"


class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        host = parsed.hostname
        if parsed.scheme.lower() not in ("http", "https") or not host:
            raise ValueError
        if parsed.username or parsed.password:
            raise ValueError("URLs containing usernames or passwords are not accepted.")
        if parsed.port and not 1 <= parsed.port <= 65535:
            raise ValueError
        host = host.rstrip(".").lower()
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                raise ValueError("Private, local and reserved IP addresses cannot be scanned.")
        except ValueError as exc:
            if "cannot be scanned" in str(exc):
                raise
            if len(host) > 253 or "." not in host or not re.fullmatch(
                r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
                host,
            ):
                raise ValueError("The domain name appears invalid.")
        return raw
    except ValueError as exc:
        if str(exc):
            raise
        raise ValueError("Enter a valid public http:// or https:// URL.")


def heuristic_checks(url: str) -> list[dict]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    findings = []
    if parsed.scheme != "https":
        findings.append({"name": "HTTPS", "status": "warning", "detail": "The URL uses HTTP, so traffic is not protected by HTTPS."})
    else:
        findings.append({"name": "HTTPS", "status": "info", "detail": "HTTPS encrypts traffic but does not prove the site is trustworthy."})
    if "@" in parsed.netloc:
        findings.append({"name": "URL user-info", "status": "warning", "detail": "The authority section contains an @ symbol that can disguise the destination."})
    if len(url) > 120:
        findings.append({"name": "Unusually long URL", "status": "warning", "detail": "Long URLs can obscure the destination. This is only a weak signal."})
    if host.startswith("xn--") or ".xn--" in host:
        findings.append({"name": "Punycode domain", "status": "warning", "detail": "The domain contains an internationalized label. Check for lookalike characters."})
    if host.count("-") >= 3:
        findings.append({"name": "Hyphen-heavy domain", "status": "warning", "detail": "The domain contains several hyphens. This alone does not establish maliciousness."})
    if re.search(r"(login|verify|secure|account|update|wallet|password)", host):
        findings.append({"name": "Sensitive keywords", "status": "warning", "detail": "The hostname contains words often used in credential lures."})
    if not findings:
        findings.append({"name": "Basic URL checks", "status": "info", "detail": "No obvious URL-format warning was detected. This is not a safety verdict."})
    return findings


def scan_virustotal_url(url: str) -> dict:
    if not VT_KEY:
        return {"available": False, "provider": "VirusTotal", "detail": "API key not configured."}
    headers = {"x-apikey": VT_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        response = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=TIMEOUT)
        if response.status_code == 404:
            submitted = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=TIMEOUT)
            if submitted.status_code not in (200, 201):
                return {"available": False, "provider": "VirusTotal", "detail": f"Submission unavailable (HTTP {submitted.status_code})."}
            return {"available": True, "provider": "VirusTotal", "pending": True, "detail": "URL submitted. Results may take a short time to become available."}
        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"available": True, "provider": "VirusTotal", "stats": stats, "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)), "detail": "Latest available engine results."}
    except requests.RequestException:
        return {"available": False, "provider": "VirusTotal", "detail": "Could not reach VirusTotal. Try again later."}


def scan_google(url: str) -> dict:
    if not GSB_KEY:
        return {"available": False, "provider": "Google Safe Browsing", "detail": "API key not configured."}
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
            json=body,
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        matches = response.json().get("matches", [])
        return {"available": True, "provider": "Google Safe Browsing", "matches": len(matches), "threats": [item.get("threatType", "UNKNOWN") for item in matches], "detail": "Known threat-list lookup."}
    except requests.RequestException:
        return {"available": False, "provider": "Google Safe Browsing", "detail": "Could not reach Google Safe Browsing. Try again later."}


def scan_virustotal_file(content: bytes, filename: str, sha256: str) -> dict:
    if not VT_KEY:
        return {"available": False, "provider": "VirusTotal", "detail": "API key not configured. SHA-256 was calculated locally; no reputation lookup was performed."}
    headers = {"x-apikey": VT_KEY}
    try:
        lookup = requests.get(f"{VT_BASE}/files/{sha256}", headers=headers, timeout=TIMEOUT)
        if lookup.status_code == 200:
            attributes = lookup.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            return {
                "available": True,
                "provider": "VirusTotal",
                "stats": stats,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "detail": "Existing file reputation found by SHA-256.",
            }
        if lookup.status_code != 404:
            lookup.raise_for_status()
        safe_name = os.path.basename(filename).replace("\r", "_").replace("\n", "_")[:180] or "upload.bin"
        upload = requests.post(
            f"{VT_BASE}/files",
            headers=headers,
            files={"file": (safe_name, content, "application/octet-stream")},
            timeout=60,
        )
        upload.raise_for_status()
        analysis_id = upload.json().get("data", {}).get("id")
        return {"available": True, "provider": "VirusTotal", "pending": True, "analysis_id": analysis_id, "detail": "File submitted to VirusTotal. Analysis is pending; check back for the completed report."}
    except requests.RequestException as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status == 413:
            detail = "VirusTotal rejected the upload because it exceeds its upload limit."
        elif status == 429:
            detail = "VirusTotal rate limit reached. Try again later."
        else:
            detail = "Could not complete the VirusTotal file lookup or upload. Try again later."
        return {"available": False, "provider": "VirusTotal", "detail": detail}


@app.get("/")
def home():
    return FileResponse(os.path.join(APP_DIR, "static", "index.html"))


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "virustotal_configured": bool(VT_KEY),
        "google_safe_browsing_configured": bool(GSB_KEY),
        "file_scan_max_bytes": MAX_FILE_SIZE,
    }


@app.post("/api/scan")
def scan(req: ScanRequest):
    try:
        url = normalize_url(req.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    vt = scan_virustotal_url(url)
    gsb = scan_google(url)
    checks = heuristic_checks(url)
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    google_hits = gsb.get("matches", 0)
    score = min(100, google_hits * 75 + malicious * 12 + suspicious * 5)
    score = max(score, min(45, sum(item["status"] == "warning" for item in checks) * 8))
    if google_hits or malicious >= 3:
        verdict = "Malicious"
    elif malicious or suspicious or score >= 25:
        verdict = "Suspicious"
    elif not vt["available"] and not gsb["available"]:
        verdict = "Unverified"
    else:
        verdict = "No known threat detected"
    return {
        "url": url,
        "domain": urlparse(url).hostname,
        "verdict": verdict,
        "risk_score": score,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "providers": [vt, gsb],
        "checks": checks,
        "disclaimer": "A clean result does not guarantee a website is safe. Threat databases can be incomplete or delayed. Do not enter passwords or payment details on unfamiliar sites.",
    }


@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...), consent: bool = Form(...)):
    if not consent:
        raise HTTPException(status_code=400, detail="Explicit consent is required before a file is sent to VirusTotal.")
    content = await file.read(MAX_FILE_SIZE + 1)
    await file.close()
    if not content:
        raise HTTPException(status_code=400, detail="The selected file is empty.")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File is too large. Maximum supported size is 32 MB.")
    sha256 = hashlib.sha256(content).hexdigest()
    provider = scan_virustotal_file(content, file.filename or "upload.bin", sha256)
    malicious = provider.get("malicious", 0)
    suspicious = provider.get("suspicious", 0)
    if malicious >= 3:
        verdict = "Malicious"
        score = min(100, malicious * 12 + suspicious * 5)
    elif malicious or suspicious:
        verdict = "Suspicious"
        score = min(100, malicious * 12 + suspicious * 5)
    elif provider.get("pending"):
        verdict = "Analysis pending"
        score = 0
    elif provider.get("available"):
        verdict = "No known threat detected"
        score = 0
    else:
        verdict = "Unverified"
        score = 0
    return {
        "filename": os.path.basename(file.filename or "upload.bin")[:180],
        "size": len(content),
        "sha256": sha256,
        "verdict": verdict,
        "risk_score": score,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "providers": [provider],
        "disclaimer": "The file was not executed. With your consent, its contents were sent to VirusTotal for analysis. A clean result does not guarantee a file is safe. Do not open files you do not trust.",
    }
