import os
import time
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from sqlmodel import SQLModel, create_engine, Session, select, desc

from .config import DATABASE_URL, FRONTEND_DIR, is_vt_configured, VT_API_KEY
from .models import ThreatCache, HashScanRequest, ScanResponse, ThreatReport
from .scanner import (
    calculate_sha256,
    calculate_md5,
    calculate_sha1,
    fetch_from_virustotal,
    fetch_url_from_virustotal,
    fallback_threat_analysis,
    fallback_url_analysis,
    evaluate_file_payload,
    calculate_verdict
)

# Initialize Database Engine
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SQLModel.metadata.create_all(engine)

# Initialize FastAPI Application
app = FastAPI(
    title="Hawk Threat Scanner API",
    description="Multi-engine threat detection gateway with IPQS URL scanner, VirusTotal v3 and SQLite caching.",
    version="1.0.0"
)

# Enable CORS for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    """Ensure database tables exist on server startup."""
    SQLModel.metadata.create_all(engine)


# ==========================================
# Core Analysis Service Logic
# ==========================================

def process_hash_query(clean_hash: str, file_name: Optional[str] = None) -> Dict[str, Any]:
    """Core logic to lookup, query VirusTotal, or fallback to heuristics for file hashes."""
    with Session(engine) as session:
        # 1. Check local database cache
        cached = session.get(ThreatCache, clean_hash)
        if cached:
            if file_name and not cached.file_name:
                cached.file_name = file_name
                session.add(cached)
                session.commit()
                session.refresh(cached)

            return {
                "source": "local_database_cache",
                "status": "cached",
                "message": "Retrieved from high-speed local database cache.",
                "data": cached
            }

        # 2. Query VirusTotal Live API if key is present
        vt_data = fetch_from_virustotal(clean_hash)
        if vt_data and "data" in vt_data and "attributes" in vt_data["data"]:
            attrs = vt_data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total_engines = malicious + suspicious + harmless + undetected
            risk_pct = round(((malicious + suspicious) / total_engines) * 100, 2) if total_engines > 0 else 0.0
            verdict, _ = calculate_verdict(risk_pct, malicious + suspicious)

            popular_threat = attrs.get("popular_threat_classification", {})
            threat_cat = popular_threat.get("suggested_threat_label", "Generic / Threat Feed")

            new_cache = ThreatCache(
                file_hash=clean_hash,
                file_name=file_name or attrs.get("meaningful_name", "Analyzed_Artifact"),
                risk_percentage=risk_pct,
                malicious_count=malicious,
                suspicious_count=suspicious,
                harmless_count=harmless,
                undetected_count=undetected,
                total_engines=total_engines,
                verdict=verdict,
                threat_category=threat_cat,
                scanned_at=time.time()
            )
            session.add(new_cache)
            session.commit()
            session.refresh(new_cache)

            return {
                "source": "virustotal_live_api",
                "status": "success",
                "message": "Analyzed via live VirusTotal intelligence feed.",
                "data": new_cache
            }

        # 3. Fallback to Hawk Heuristic Signature Engine
        fallback_res = fallback_threat_analysis(clean_hash, file_name=file_name)
        new_cache = ThreatCache(
            file_hash=clean_hash,
            file_name=fallback_res["file_name"],
            risk_percentage=fallback_res["risk_percentage"],
            malicious_count=fallback_res["malicious_count"],
            suspicious_count=fallback_res["suspicious_count"],
            harmless_count=fallback_res["harmless_count"],
            undetected_count=fallback_res["undetected_count"],
            total_engines=fallback_res["total_engines"],
            verdict=fallback_res["verdict"],
            threat_category=fallback_res["threat_category"],
            scanned_at=fallback_res["scanned_at"]
        )
        session.add(new_cache)
        session.commit()
        session.refresh(new_cache)

        return {
            "source": "hawk_signature_engine",
            "data": new_cache,
            "message": "Processed via Hawk heuristics & signature database.",
            "is_cached": False
        }


def process_url_query(target_url: str) -> Dict[str, Any]:
    """Core logic to inspect URLs, query VirusTotal URL endpoint, or evaluate heuristic indicators."""
    clean_url = target_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    with Session(engine) as session:
        # 1. Check database cache
        cached = session.get(ThreatCache, clean_url)
        if cached:
            return {
                "source": "local_database_cache",
                "status": "cached",
                "message": "Retrieved URL intelligence from database cache.",
                "data": cached
            }

        # 2. Check VirusTotal URL Live API
        vt_data = fetch_url_from_virustotal(clean_url)
        if vt_data and "data" in vt_data and "attributes" in vt_data["data"]:
            attrs = vt_data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total_engines = malicious + suspicious + harmless + undetected
            risk_pct = round(((malicious + suspicious) / total_engines) * 100, 2) if total_engines > 0 else 0.0
            verdict, _ = calculate_verdict(risk_pct, malicious + suspicious)

            threat_cat = attrs.get("categories", {})
            cat_label = list(threat_cat.values())[0] if threat_cat else ("Phishing / Malicious Link" if malicious > 0 else "Clean Link")

            new_cache = ThreatCache(
                file_hash=clean_url,
                file_name=clean_url,
                risk_percentage=risk_pct,
                malicious_count=malicious,
                suspicious_count=suspicious,
                harmless_count=harmless,
                undetected_count=undetected,
                total_engines=total_engines,
                verdict=verdict,
                threat_category=cat_label,
                scanned_at=time.time()
            )
            session.add(new_cache)
            session.commit()
            session.refresh(new_cache)

            return {
                "source": "virustotal_live_api",
                "status": "success",
                "message": "Analyzed URL via live VirusTotal intelligence feed.",
                "data": new_cache
            }

        # 3. Fallback to Hawk Heuristic URL Engine
        url_res = fallback_url_analysis(clean_url)
        new_cache = ThreatCache(
            file_hash=clean_url,
            file_name=clean_url,
            risk_percentage=url_res["risk_percentage"],
            malicious_count=url_res["malicious_count"],
            suspicious_count=url_res["suspicious_count"],
            harmless_count=url_res["harmless_count"],
            undetected_count=url_res["undetected_count"],
            total_engines=url_res["total_engines"],
            verdict=url_res["verdict"],
            threat_category=url_res["threat_category"],
            scanned_at=url_res["scanned_at"]
        )
        session.add(new_cache)
        session.commit()
        session.refresh(new_cache)

        return {
            "source": url_res["source"],
            "status": "success",
            "message": "URL analyzed via Hawk heuristics & threat registry.",
            "data": new_cache
        }


# ==========================================
# API Endpoints
# ==========================================

@app.get("/api/health")
def health_check():
    """Health check endpoint to verify backend status."""
    return {
        "status": "online",
        "service": "Hawk Threat Scanner Gateway",
        "virustotal_configured": is_vt_configured(),
        "database": "connected",
        "capabilities": ["hash_scan", "file_scan", "url_scan"],
        "timestamp": time.time()
    }


@app.post("/scan/hash")
@app.post("/api/scan/hash")
async def scan_hash(payload: Optional[Dict[str, Any]] = Body(None), hash_value: Optional[str] = Query(None)):
    """Direct lookup endpoint for cryptographic signature hashes (MD5, SHA-1, SHA-256)."""
    target_hash = ""
    if payload:
        target_hash = payload.get("hash_value") or payload.get("hash") or ""
    if not target_hash and hash_value:
        target_hash = hash_value

    clean_hash = target_hash.strip().lower()
    if len(clean_hash) not in (32, 40, 64):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hash length. Must be MD5 (32), SHA-1 (40), or SHA-256 (64) characters."
        )

    if not all(c in "0123456789abcdef" for c in clean_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hexadecimal character sequence in hash string."
        )

    result = process_hash_query(clean_hash)
    return result


@app.post("/scan/url")
@app.post("/api/scan/url")
async def scan_url(payload: Optional[Dict[str, Any]] = Body(None), url: Optional[str] = Query(None)):
    """Inspects suspicious URLs/links and returns malicious percentage & security flags."""
    target_url = ""
    if payload:
        target_url = payload.get("url") or payload.get("url_value") or payload.get("link") or ""
    if not target_url and url:
        target_url = url

    clean_url = target_url.strip()
    if not clean_url or len(clean_url) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid URL (e.g., https://example.com/login)."
        )

    result = process_url_query(clean_url)
    return result


@app.post("/scan/file")
@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)):
    """Accepts file uploads, inspects binary payload, hashes in memory, and returns threat telemetry."""
    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty (0 bytes).")

        result = evaluate_file_payload(contents, file.filename or "Uploaded_Artifact")
        return {
            "source": result["source"],
            "status": "success",
            "data": result
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"File scanning error: {str(e)}")
    finally:
        await file.close()


@app.get("/api/recent")
def get_recent_scans():
    """Fetches recently scanned artifacts and links from the cache."""
    with Session(engine) as session:
        statement = select(ThreatCache).order_by(desc(ThreatCache.scanned_at)).limit(10)
        results = session.exec(statement).all()
        return {"scans": results}


# ==========================================
# Frontend Static Asset Serving
# ==========================================

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_index():
        index_path = FRONTEND_DIR / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        return JSONResponse({"message": "Frontend index.html not found. Backend API is active."})
