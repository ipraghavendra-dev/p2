# 🦅 Hawk Threat Scanner

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/Security-IPQS%20%26%20VirusTotal%20v3-red.svg)](https://virustotal.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

- 🔗 **Malicious Link & Phishing Scanner**: Inspect suspicious URLs, detect deceptive domains, phishing schemes, and calculate real-time **malicious risk percentage %**.
- 🔍 **Instant Hash Scanning**: Direct cryptographic lookup for **MD5**, **SHA-1**, and **SHA-256** indicators of compromise.
- 📁 **In-Memory File Analysis**: Drag & drop APKs, executables, documents (PDF/Word/Excel) up to 100MB with zero disk storage exposure.
- ⚡ **Local SQLite Cache**: SQLModel persistent database prevents duplicate external API hits and reduces latency to `< 5ms`.
- 🌐 **VirusTotal v3 Gateway**: Live threat telemetry across 70+ security vendors with built-in 4 req/min auto-throttling rate limiter.
- 🛡️ **Intelligent Heuristic Engine**: Built-in fallback database with known signatures (e.g. WannaCry, EICAR, Trojan, Phishing test links) allowing instant offline/local testing.
- 🎨 **Modern Cyber Aesthetic**: Glowing risk gauge, responsive glassmorphism dark mode, and sample test vectors.
- 🚀 **One-Click Deployment**: Ready for GitHub, Docker, Render, Railway, and Heroku.

---

## 📁 Repository Structure

```
.
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py         # Configuration & environment variables
│   │   ├── database.py       # SQLite SQLModel connection
│   │   ├── models.py         # Database schemas & Pydantic request models
│   │   ├── scanner.py        # VirusTotal v3 client & rate limiter
│   │   └── main.py           # FastAPI endpoints & static file serving
│   └── requirements.txt      # Python dependencies
├── frontend/
│   ├── index.html            # Dashboard UI
│   ├── css/
│   │   └── style.css         # Glassmorphism & cyber styling
│   └── js/
│       └── app.js            # Frontend logic & API integration
├── .github/
│   └── workflows/
│       └── ci.yml            # Automated GitHub Actions test pipeline
├── .env.example              # Environment variables template
├── .gitignore                # Git ignore rules
├── Dockerfile                # Production multi-stage Docker build
├── docker-compose.yml        # Docker compose orchestrator
├── Procfile                  # Railway / Heroku deployment process
├── render.yaml               # Render.com blueprint configuration
└── README.md                 # Documentation & deployment guide
```

---

## ⚡ Quick Start (Local Run)

### 1. Clone or Open the Repository
```bash
git clone https://github.com/YOUR_USERNAME/aegis-threat-scanner.git
cd aegis-threat-scanner
```

### 2. Set Up Virtual Environment & Dependencies
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install requirements
pip install -r backend/requirements.txt
```

### 3. (Optional) Configure VirusTotal API Key
Create a `.env` file from the template:
```bash
cp .env.example .env
```
Add your free VirusTotal API key in `.env` (optional — app includes built-in offline heuristics if left blank):
```env
VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key_here
```

### 4. Run the Server
```bash
uvicorn backend.app.main:app --reload --port 8000
```

Open your browser and visit: **`http://localhost:8000`**
Interactive Swagger API Docs are available at: **`http://localhost:8000/docs`**

---

## 🐳 Run with Docker

Run the entire application in a lightweight container with a single command:

```bash
docker-compose up --build
```
Access the application at `http://localhost:8000`.

---

## 📤 How to Upload to GitHub

Follow these steps in your terminal inside the project root:

```bash
# 1. Initialize git repository
git init

# 2. Add all project files
git add .

# 3. Commit the code
git commit -m "feat: initial commit for Aegis Threat Scanner fullstack app"

# 4. Set default branch to main
git branch -M main

# 5. Link to your GitHub repository (replace with your repo URL)
git remote add origin https://github.com/YOUR_USERNAME/aegis-threat-scanner.git

# 6. Push code to GitHub
git push -u origin main
```

---

## 🚀 Free Deployment Guide

### Option 1: Deploy to Render (Recommended - 100% Free)

1. Create a free account at [Render.com](https://render.com).
2. Click **New +** &rarr; **Web Service**.
3. Connect your GitHub repository (`aegis-threat-scanner`).
4. Configure the settings:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r backend/requirements.txt`
   - **Start Command**: `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
5. (Optional) In **Environment Variables**, add:
   - `VIRUSTOTAL_API_KEY`: *(Your key)*
6. Click **Deploy Web Service** — Render will give you a live HTTPS URL (e.g. `https://aegis-scanner.onrender.com`).

*(Alternatively, click **New +** &rarr; **Blueprint** and Render will automatically read the included `render.yaml` file!)*

---

### Option 2: Deploy to Railway

1. Sign in to [Railway.app](https://railway.app) using GitHub.
2. Click **New Project** &rarr; **Deploy from GitHub repo**.
3. Select your `aegis-threat-scanner` repository.
4. Railway automatically detects the `Procfile` and `Dockerfile` and builds the project.
5. In **Variables**, add `VIRUSTOTAL_API_KEY` (optional).
6. Under **Settings**, click **Generate Domain** to get your public URL.

---

### Option 3: Deploy with Docker on Any Cloud (DigitalOcean, AWS, GCP, Fly.io)

```bash
# Fly.io deployment
fly launch
fly deploy
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status & VT configuration check |
| `POST` | `/scan/url` or `/api/scan/url` | Inspect suspicious URLs/links & get malicious risk percentage |
| `POST` | `/scan/hash` or `/api/scan/hash` | Inspect MD5 / SHA-1 / SHA-256 signature |
| `POST` | `/scan/file` or `/api/scan/file` | Multipart file upload and automatic hash analysis |
| `GET` | `/api/recent` | Retrieve recent scan telemetry from SQLite store |
| `GET` | `/docs` | Interactive OpenAPI / Swagger UI documentation |

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for details.
