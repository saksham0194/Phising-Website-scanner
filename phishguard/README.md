# PhishGuard

A local-first phishing URL scanner with a React-free lightweight dashboard and a Python FastAPI backend.

## Run locally

1. Install Python 3.10 or newer.
2. Open a terminal in this folder.
3. Create and activate a virtual environment:
   - Windows: `py -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install packages: `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and set API keys if you have them.
6. Set the environment variables in your terminal (or use a dotenv runner):
   - PowerShell: `$env:VIRUSTOTAL_API_KEY="your-key"` and `$env:GOOGLE_SAFE_BROWSING_API_KEY="your-key"`
   - macOS/Linux: `export VIRUSTOTAL_API_KEY="your-key"` and `export GOOGLE_SAFE_BROWSING_API_KEY="your-key"`
7. Start: `uvicorn app:app --reload`
8. Open http://127.0.0.1:8000

## API keys

- VirusTotal: https://www.virustotal.com/gui/my-apikey
- Google Safe Browsing: https://developers.google.com/safe-browsing/v4/get-started

The app works without keys, but reputation providers will show as not configured. Add keys only on your own server. Never expose API keys in frontend JavaScript or commit them to Git.

## Important limitations

- A clean scan does not guarantee a URL is safe.
- The risk score is a simple triage indicator, not a calibrated probability.
- The app queries reputation APIs and checks URL patterns. It does not execute or browse the submitted website.
- VirusTotal may return a pending result after a new URL is submitted; scan it again after a short wait.
- This starter is intended for local development. Before public deployment, add authentication, rate limiting, logging controls, secure secret management, abuse prevention, and provider quota handling.
