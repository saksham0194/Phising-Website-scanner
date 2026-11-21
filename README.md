# 🛡️ PhishGuard 2.0
### Intelligent Phishing & Malicious File Detection Platform

PhishGuard is a web-based cybersecurity tool designed to identify potentially malicious URLs and files using threat intelligence and security analysis.

It combines a modern, animated interface with VirusTotal integration to help users investigate suspicious links and files.

---

## ✨ Features

### 🔗 URL Scanner
- Scan suspicious URLs for potential threats.
- VirusTotal reputation analysis.
- Google Safe Browsing integration (optional).
- URL inspection and phishing-related heuristic checks.
- Risk score and security verdict.

### 📁 File Scanner
- Upload files for security analysis.
- Maximum upload size: 32 MB.
- SHA-256 fingerprint calculation for file reputation lookup.
- VirusTotal file reputation analysis.
- Explicit consent before submitting file contents to VirusTotal.
- File risk score and detection report.

### 🎨 Modern User Interface
- Premium dark cybersecurity-themed design.
- Animated background effects and glowing elements.
- Interactive scanning animations.
- Drag-and-drop file upload.
- Responsive scanning dashboard.
- Colour-coded threat indicators.

---

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| FastAPI | Backend framework |
| HTML5 | Website structure |
| CSS3 | Styling and animations |
| JavaScript | Frontend interactions |
| VirusTotal API | Threat intelligence |
| Google Safe Browsing API | URL safety checks |
| Uvicorn | ASGI server |
| Render | Cloud deployment |
| GitHub | Version control |

---

## 📂 Project Structure

```text
PhishGuard/
│
├── phishguard/
│   ├── static/
│   │   └── index.html
│   │
│   ├── app.py
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
│
└── .gitignore
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/saksham0194/Phising-Website-scanner.git
```

### 2. Navigate to the backend directory

```bash
cd Phising-Website-scanner/phishguard
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the environment

**Windows:**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
source .venv/bin/activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure API keys

Create a file named `API.env` inside the `phishguard` directory.

Add your API keys:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
```

Google Safe Browsing is optional.

Never upload `API.env` or expose your API keys publicly.

### 7. Start the application

```bash
python -m uvicorn app:app --reload
```

Open your browser:

**http://127.0.0.1:8000**

API documentation:

**http://127.0.0.1:8000/docs**

---

## 🔍 How It Works

### URL Scanning
1. Enter a website URL.
2. PhishGuard validates and analyses the submitted URL.
3. Available threat intelligence providers are queried.
4. Security signals are evaluated.
5. A risk score and scanning report are displayed.

### File Scanning
1. Select or drag and drop a file.
2. Provide consent for VirusTotal submission.
3. PhishGuard calculates the file's SHA-256 fingerprint.
4. It checks available file reputation information.
5. When necessary, the file may be submitted to VirusTotal.
6. A security verdict and risk report are returned.

---

## 🌐 Live Demo

**Website:** https://phising-website-scanner.onrender.com

**API Documentation:** https://phising-website-scanner.onrender.com/docs

---

## 🔐 Security & Privacy

- API keys must be stored in environment variables.
- Never commit API credentials to GitHub.
- Uploaded files are not executed by the scanner.
- File uploads are limited to 32 MB.
- File submission to VirusTotal requires user consent.
- Submitting files to VirusTotal means their contents may be shared with VirusTotal and its security partners.

**Disclaimer:** PhishGuard is an educational security analysis tool. A clean scan does not guarantee that a URL or file is safe. Threat intelligence databases may be incomplete or outdated. Do not use this tool as a replacement for professional antivirus or endpoint protection software.

---

## 🎓 Project Information

**Project Name:** PhishGuard 2.0

**Category:** Cybersecurity / Web Application Development

**Purpose:** Educational project focused on phishing detection, malicious file analysis, and threat intelligence integration.

**Developer:** Saksham

---

## 📜 License

This project is intended for educational and demonstration purposes.

If you wish to distribute or reuse this project, add an appropriate open-source license and review the licensing terms of its dependencies and external services.
