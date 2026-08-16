# 🦅 Hawk Threat Scanner

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/Security-Threat%20Intelligence%20%26%20VirusTotal%20v3-red.svg)](https://virustotal.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Link & Phishing Scanner: Analyzes submitted URLs to detect malicious domains and phishing attempts, assigning a risk score based on detected threats.

Instant Hash Lookups: Checks file hashes (MD5, SHA-1, SHA-256) directly against known threat databases.

In-Memory File Analysis: Accepts file uploads (APKs, executables, documents) up to 100MB, processing them entirely in memory to avoid saving files to disk.

Local SQLite Cache: Stores recent scan results using SQLModel to prevent redundant API calls and speed up repeated lookups.

VirusTotal Integration: Queries the VirusTotal v3 API across 70+ security vendors with built-in rate limiting (4 requests/minute).

Fallback Signature Engine: Includes an offline database of common test signatures (e.g., EICAR, WannaCry, sample phishing URLs) for local testing without network access.

Web Interface: Styled with a dark mode interface, interactive risk gauge, and pre-loaded sample inputs for quick testing.

Deployment Ready: Configurations included for Docker, GitHub, Render, Railway, and Heroku.

License
Distributed under the MIT License. See LICENSE for details.
